<?php

declare(strict_types=1);

namespace SentryIQ\\Security;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;
use Throwable;

/**
 * Strict, platform-independent validator for SentryIQ public trust bundles.
 *
 * Trust anchors are supplied by the caller from an independently pinned source.
 * This class never trusts a key merely because it appears in the candidate bundle.
 */
final class TrustBundleValidator
{
    private const MAX_BYTES = 262144;
    private const MAX_VALIDITY_SECONDS = 2592000;
    private const MAX_FUTURE_SKEW_SECONDS = 300;

    /**
     * @param list<array{kid:string,role:string,alg:string,public_key_pem:string}> $trustedSigners
     * @return array{bundle:array<string,mixed>,digest:string,sequence:string,signer_kids:list<string>}
     */
    public function validate(
        string $json,
        array $trustedSigners,
        string $expectedOwnerId,
        ?string $expectedPreviousDigest,
        ?string $minimumSequence,
        ?int $now = null
    ): array {
        if ($json === '' || strlen($json) > self::MAX_BYTES) {
            throw new RuntimeException('Trust bundle is empty or exceeds the size limit.');
        }
        $this->assertNoDuplicateKeys($json);
        try {
            $bundle = json_decode($json, false, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Trust bundle JSON is invalid.', 0, $exception);
        }
        if (!$bundle instanceof \stdClass) {
            throw new RuntimeException('Trust bundle must be a JSON object.');
        }

        $this->assertExactObjectFields($bundle, [
            'type', 'schema_version', 'policy_version', 'sequence', 'previous_digest',
            'issued_at', 'expires_at', 'owner_id', 'master_keyset',
            'release_authorisation', 'verifier', 'sigstore_tuf', 'revocations', 'signatures',
        ]);

        if ($bundle->type !== 'SENTRYIQ-TRUST-BUNDLE' || $bundle->schema_version !== 1
            || !is_string($bundle->policy_version) || $bundle->policy_version === ''
            || strlen($bundle->policy_version) > 64) {
            throw new RuntimeException('Trust bundle type, schema, or policy version is unsupported.');
        }
        $sequence = $bundle->sequence;
        if (!is_string($sequence) || !preg_match('/^[1-9][0-9]{0,18}$/D', $sequence)) {
            throw new RuntimeException('Trust bundle sequence must be a canonical positive decimal string.');
        }
        if ($minimumSequence !== null && $this->compareDecimal($sequence, $minimumSequence) <= 0) {
            throw new RuntimeException('Trust bundle sequence rollback or replay rejected.');
        }
        if (!is_string($bundle->owner_id) || !hash_equals($expectedOwnerId, $bundle->owner_id)) {
            throw new RuntimeException('Trust bundle owner identity mismatch.');
        }
        if ($expectedPreviousDigest === null) {
            if ($bundle->previous_digest !== null) {
                throw new RuntimeException('Initial trust bundle must have a null previous digest.');
            }
        } elseif (!is_string($bundle->previous_digest)
            || !preg_match('/^[a-f0-9]{64}$/D', $bundle->previous_digest)
            || !hash_equals($expectedPreviousDigest, $bundle->previous_digest)) {
            throw new RuntimeException('Trust bundle digest chain is broken.');
        }

        $currentTime = $now ?? time();
        $issuedAt = $this->parseUtc($bundle->issued_at ?? null);
        $expiresAt = $this->parseUtc($bundle->expires_at ?? null);
        if ($issuedAt > $currentTime + self::MAX_FUTURE_SKEW_SECONDS
            || $expiresAt <= $currentTime
            || $expiresAt <= $issuedAt
            || ($expiresAt - $issuedAt) > self::MAX_VALIDITY_SECONDS) {
            throw new RuntimeException('Trust bundle validity window is invalid or expired.');
        }

        $this->validateMasterKeyset($bundle->master_keyset ?? null);
        $this->validateKeyCollection($bundle->release_authorisation ?? null, 'release-authorisation', true);
        $this->validateVerifier($bundle->verifier ?? null);
        $this->validateTufReference($bundle->sigstore_tuf ?? null);
        $this->validateRevocations($bundle->revocations ?? null);
        $this->assertRoleSeparation($bundle);

        if (!is_array($bundle->signatures) || $bundle->signatures === []) {
            throw new RuntimeException('Trust bundle has no detached signatures.');
        }

        $unsigned = clone $bundle;
        unset($unsigned->signatures);
        $canonicalPayload = $this->canonicalJson($unsigned);
        $signerKids = $this->verifySignatures($bundle->signatures, $canonicalPayload, $trustedSigners);
        if ($signerKids === []) {
            throw new RuntimeException('Trust bundle has no valid signature from an independently trusted key.');
        }

        return [
            'bundle' => json_decode(json_encode($bundle, JSON_THROW_ON_ERROR), true, 64, JSON_THROW_ON_ERROR),
            'digest' => hash('sha256', $canonicalPayload),
            'sequence' => $sequence,
            'signer_kids' => $signerKids,
        ];
    }

    private function assertExactObjectFields(mixed $value, array $expected): void
    {
        if (!$value instanceof \\stdClass) {
            throw new RuntimeException('Trust bundle object has an invalid shape.');
        }
        $actual = array_keys(get_object_vars($value));
        sort($actual, SORT_STRING);
        sort($expected, SORT_STRING);
        if ($actual !== $expected) {
            throw new RuntimeException('Trust bundle contains missing or unknown fields.');
        }
    }

    private function validateMasterKeyset(mixed $keyset): void
    {
        $this->assertExactObjectFields($keyset, ['signing', 'key_agreement']);
        $this->validatePublicKey($keyset->signing ?? null, 'ES256');
        $this->validatePublicKey($keyset->key_agreement ?? null, 'ECDH-ES');
        if ($keyset->signing->kid === $keyset->key_agreement->kid) {
            throw new RuntimeException('Master signing and key-agreement keys must have distinct key IDs.');
        }
    }

    private function validateKeyCollection(mixed $collection, string $purpose, bool $required): void
    {
        $this->assertExactObjectFields($collection, ['keys']);
        if (!is_array($collection->keys) || ($required && $collection->keys === [])) {
            throw new RuntimeException('Trust bundle key collection is empty or malformed.');
        }
        $seen = [];
        foreach ($collection->keys as $key) {
            $this->assertExactObjectFields($key, ['kid', 'alg', 'public_key_pem', 'purpose']);
            $this->validatePublicKey($key, 'ES256', true);
            if ($key->purpose !== $purpose || isset($seen[$key->kid])) {
                throw new RuntimeException('Trust bundle key purpose mismatch or duplicate key ID.');
            }
            $seen[$key->kid] = true;
        }
    }

    private function validateVerifier(mixed $verifier): void
    {
        $this->assertExactObjectFields($verifier, ['qualification_state', 'policy_version', 'keys']);
        if (!in_array($verifier->qualification_state, ['pending', 'qualified'], true)
            || !is_string($verifier->policy_version) || $verifier->policy_version === ''
            || !is_array($verifier->keys)) {
            throw new RuntimeException('Verifier trust state is malformed.');
        }
        if ($verifier->qualification_state === 'pending' && $verifier->keys !== []) {
            throw new RuntimeException('An unqualified verifier must not carry trusted verifier keys.');
        }
        if ($verifier->qualification_state === 'qualified' && $verifier->keys === []) {
            throw new RuntimeException('A qualified verifier must identify at least one verifier key.');
        }
        $seen = [];
        foreach ($verifier->keys as $key) {
            $this->assertExactObjectFields($key, ['kid', 'alg', 'public_key_pem', 'purpose']);
            $this->validatePublicKey($key, 'ES256', true);
            if ($key->purpose !== 'verifier-report' || isset($seen[$key->kid])) {
                throw new RuntimeException('Verifier key purpose mismatch or duplicate key ID.');
            }
            $seen[$key->kid] = true;
        }
    }

    private function validatePublicKey(mixed $key, string $expectedAlgorithm, bool $withPurpose = false): void
    {
        $fields = ['kid', 'alg', 'public_key_pem'];
        if ($withPurpose) $fields[] = 'purpose';
        $this->assertExactObjectFields($key, $fields);
        if (!is_string($key->kid) || !preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $key->kid)
            || $key->alg !== $expectedAlgorithm || !is_string($key->public_key_pem)
            || strlen($key->public_key_pem) > 8192) {
            throw new RuntimeException('Trust bundle public key metadata is invalid.');
        }
        $publicKey = openssl_pkey_get_public($key->public_key_pem);
        if ($publicKey === false) {
            throw new RuntimeException('Trust bundle contains an invalid public key.');
        }
        try {
            $details = openssl_pkey_get_details($publicKey);
            if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
                || ($details['curve_name'] ?? null) !== 'prime256v1') {
                throw new RuntimeException('Trust bundle keys must use the P-256 curve.');
            }
        } finally {
            openssl_pkey_free($publicKey);
        }
    }

    private function assertRoleSeparation(\\stdClass $bundle): void
    {
        $ids = [];
        $fingerprints = [];
        $keys = [
            $bundle->master_keyset->signing,
            $bundle->master_keyset->key_agreement,
            ...$bundle->release_authorisation->keys,
            ...$bundle->verifier->keys,
        ];
        foreach ($keys as $key) {
            if (isset($ids[$key->kid])) {
                throw new RuntimeException('Trust bundle reuses a key ID across cryptographic roles.');
            }
            $ids[$key->kid] = true;
            $publicKey = openssl_pkey_get_public($key->public_key_pem);
            if ($publicKey === false) {
                throw new RuntimeException('Trust bundle contains an invalid public key.');
            }
            try {
                $details = openssl_pkey_get_details($publicKey);
                $fingerprint = is_array($details) && is_string($details['key'] ?? null)
                    ? hash('sha256', $details['key']) : '';
            } finally {
                openssl_pkey_free($publicKey);
            }
            if ($fingerprint === '' || isset($fingerprints[$fingerprint])) {
                throw new RuntimeException('Trust bundle reuses public key material across cryptographic roles.');
            }
            $fingerprints[$fingerprint] = true;
        }
        $active = array_fill_keys(array_keys($ids), true);
        foreach ($bundle->revocations as $revocation) {
            if (isset($active[$revocation->kid])) {
                throw new RuntimeException('A key cannot be active and revoked in the same trust bundle.');
            }
        }
    }

    private function validateTufReference(mixed $tuf): void
    {
        $this->assertExactObjectFields($tuf, ['root_version', 'root_digest']);
        if (!is_int($tuf->root_version) || $tuf->root_version < 1
            || !is_string($tuf->root_digest) || !preg_match('/^[a-f0-9]{64}$/D', $tuf->root_digest)) {
            throw new RuntimeException('Sigstore/TUF root reference is malformed.');
        }
    }

    private function validateRevocations(mixed $revocations): void
    {
        if (!is_array($revocations)) {
            throw new RuntimeException('Trust bundle revocations must be an array.');
        }
        $previous = null;
        foreach ($revocations as $revocation) {
            $this->assertExactObjectFields($revocation, ['kid', 'effective_at', 'reason']);
            if (!is_string($revocation->kid) || !preg_match('/^[A-Za-z0-9._-]{1,128}$/D', $revocation->kid)
                || !is_string($revocation->reason) || $revocation->reason === '' || strlen($revocation->reason) > 256) {
                throw new RuntimeException('Trust bundle revocation entry is malformed.');
            }
            $this->parseUtc($revocation->effective_at);
            if ($previous !== null && strcmp($previous, $revocation->kid) >= 0) {
                throw new RuntimeException('Trust bundle revocations must be sorted and unique.');
            }
            $previous = $revocation->kid;
        }
    }

    private function verifySignatures(array $signatures, string $payload, array $trustedSigners): array
    {
        $trusted = [];
        foreach ($trustedSigners as $signer) {
            if (!is_array($signer) || !isset($signer['kid'], $signer['role'], $signer['alg'], $signer['public_key_pem'])
                || !is_string($signer['kid']) || !is_string($signer['role'])
                || !is_string($signer['alg']) || !is_string($signer['public_key_pem'])) {
                throw new RuntimeException('Independently pinned signer configuration is malformed.');
            }
            $trusted[$signer['kid']] = $signer;
        }

        $accepted = [];
        foreach ($signatures as $signature) {
            $this->assertExactObjectFields($signature, ['kid', 'role', 'alg', 'signature']);
            if (!is_string($signature->kid) || !is_string($signature->role)
                || $signature->alg !== 'ES256' || !is_string($signature->signature)
                || isset($accepted[$signature->kid])) {
                throw new RuntimeException('Trust bundle signature metadata is malformed or duplicated.');
            }
            $anchor = $trusted[$signature->kid] ?? null;
            if (!is_array($anchor) || $anchor['role'] !== $signature->role
                || $anchor['alg'] !== $signature->alg
                || !in_array($signature->role, ['release-authorisation', 'master-signing'], true)) {
                continue;
            }
            $raw = $this->decodeBase64Url($signature->signature);
            if (strlen($raw) !== 64) {
                throw new RuntimeException('ES256 signature must use the 64-byte JOSE encoding.');
            }
            $der = $this->rawEcdsaToDer($raw);
            $publicKey = openssl_pkey_get_public($anchor['public_key_pem']);
            if ($publicKey === false) {
                throw new RuntimeException('Pinned signer public key is invalid.');
            }
            try {
                $result = openssl_verify($payload, $der, $publicKey, OPENSSL_ALGO_SHA256);
            } finally {
                openssl_pkey_free($publicKey);
            }
            if ($result === 1) {
                $accepted[$signature->kid] = true;
            } elseif ($result === -1) {
                throw new RuntimeException('Trust bundle signature verification failed internally.');
            }
        }
        return array_keys($accepted);
    }

    private function parseUtc(mixed $value): int
    {
        if (!is_string($value) || !preg_match('/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/D', $value)) {
            throw new RuntimeException('Trust bundle timestamps must be canonical UTC seconds.');
        }
        $date = DateTimeImmutable::createFromFormat('!Y-m-d\\TH:i:s\\Z', $value, new DateTimeZone('UTC'));
        $errors = DateTimeImmutable::getLastErrors();
        if (!$date instanceof DateTimeImmutable || (is_array($errors) && ($errors['warning_count'] > 0 || $errors['error_count'] > 0))
            || $date->format('Y-m-d\\TH:i:s\\Z') !== $value) {
            throw new RuntimeException('Trust bundle timestamp is invalid.');
        }
        return $date->getTimestamp();
    }

    private function canonicalJson(mixed $value): string
    {
        if ($value instanceof \\stdClass) {
            $properties = get_object_vars($value);
            ksort($properties, SORT_STRING);
            $parts = [];
            foreach ($properties as $key => $child) {
                $parts[] = json_encode((string)$key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)
                    . ':' . $this->canonicalJson($child);
            }
            return '{' . implode(',', $parts) . '}';
        }
        if (is_array($value)) {
            return '[' . implode(',', array_map(fn($child): string => $this->canonicalJson($child), $value)) . ']';
        }
        if (is_float($value)) {
            throw new RuntimeException('Floating-point values are prohibited in trust bundle canonical data.');
        }
        if (is_int($value) || is_string($value) || is_bool($value) || $value === null) {
            return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        }
        throw new RuntimeException('Trust bundle contains an unsupported canonical JSON value.');
    }

    private function decodeBase64Url(string $encoded): string
    {
        if (!preg_match('/^[A-Za-z0-9_-]+$/D', $encoded)) {
            throw new RuntimeException('Trust bundle signature encoding is not canonical base64url.');
        }
        $decoded = base64_decode(strtr($encoded, '-_', '+/') . str_repeat('=', (4 - strlen($encoded) % 4) % 4), true);
        if (!is_string($decoded) || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $encoded) {
            throw new RuntimeException('Trust bundle signature encoding is invalid.');
        }
        return $decoded;
    }

    private function rawEcdsaToDer(string $raw): string
    {
        $integer = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\\0");
            if ($bytes === '') $bytes = "\\0";
            if ((ord($bytes[0]) & 0x80) !== 0) $bytes = "\\0" . $bytes;
            return "\\x02" . chr(strlen($bytes)) . $bytes;
        };
        $body = $integer(substr($raw, 0, 32)) . $integer(substr($raw, 32, 32));
        return "\\x30" . chr(strlen($body)) . $body;
    }

    private function compareDecimal(string $left, string $right): int
    {
        if (!preg_match('/^[1-9][0-9]{0,18}$/D', $right)) {
            throw new RuntimeException('Persisted trust sequence is malformed.');
        }
        return strlen($left) <=> strlen($right) ?: strcmp($left, $right);
    }

    private function assertNoDuplicateKeys(string $json): void
    {
        $stack = [];
        $inString = false;
        $escaped = false;
        $start = 0;
        $length = strlen($json);
        for ($i = 0; $i < $length; $i++) {
            $char = $json[$i];
            if ($inString) {
                if ($escaped) $escaped = false;
                elseif ($char === '\\\\') $escaped = true;
                elseif ($char === '"') {
                    $inString = false;
                    $index = count($stack) - 1;
                    if ($index >= 0 && $stack[$index]['object']) {
                        $next = $i + 1;
                        while ($next < $length && ctype_space($json[$next])) $next++;
                        if ($next < $length && $json[$next] === ':') {
                            try {
                                $key = json_decode(substr($json, $start, $i - $start + 1), true, 2, JSON_THROW_ON_ERROR);
                            } catch (Throwable) {
                                throw new RuntimeException('Trust bundle contains malformed JSON object keys.');
                            }
                            if (!is_string($key) || isset($stack[$index]['keys'][$key])) {
                                throw new RuntimeException('Trust bundle contains duplicate JSON object keys.');
                            }
                            $stack[$index]['keys'][$key] = true;
                        }
                    }
                }
                continue;
            }
            if ($char === '"') {
                $inString = true;
                $start = $i;
            } elseif ($char === '{') {
                $stack[] = ['object' => true, 'keys' => []];
                if (count($stack) > 64) throw new RuntimeException('Trust bundle nesting exceeds the limit.');
            } elseif ($char === '[') {
                $stack[] = ['object' => false, 'keys' => []];
                if (count($stack) > 64) throw new RuntimeException('Trust bundle nesting exceeds the limit.');
            } elseif ($char === '}' || $char === ']') {
                if ($stack === []) throw new RuntimeException('Trust bundle JSON structure is malformed.');
                array_pop($stack);
            }
        }
        if ($inString || $stack !== []) throw new RuntimeException('Trust bundle JSON structure is incomplete.');
    }
}
