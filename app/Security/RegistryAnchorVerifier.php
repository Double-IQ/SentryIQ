<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;
use Throwable;

/**
 * Verifies the exact signed registry-anchor envelope used by native trust stores.
 *
 * Trusted signer keys are injected from an independently provisioned source.
 * This class deliberately has no default key, network lookup, or app-host trust path.
 */
final class RegistryAnchorVerifier
{
    private const MAX_PAYLOAD_BYTES = 4096;
    private const MAX_AGE_SECONDS = 86400;
    private const MAX_FUTURE_SKEW_SECONDS = 60;
    private const P256_ORDER = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
    private const P256_HALF_ORDER = '7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8';

    /**
     * @param list<array{kid:string,role:string,alg:string,public_key_pem:string}> $trustedSigners
     * @return array{owner_id:string,sequence:string,bundle_sha256:string,issued_at:int,expires_at:int,previous_bundle_sha256:?string,signer_kid:string}
     */
    public function verify(
        string $signedPayload,
        string $signature,
        array $trustedSigners,
        string $expectedOwnerId,
        ?string $currentSequence,
        ?string $currentBundleDigest,
        ?int $now = null
    ): array {
        if ($expectedOwnerId === '' || strlen($expectedOwnerId) > 256
            || $signedPayload === '' || strlen($signedPayload) > self::MAX_PAYLOAD_BYTES
            || strlen($signature) !== 64) {
            throw new RuntimeException('Registry anchor input is malformed or oversized.');
        }
        $this->assertNoDuplicateKeys($signedPayload);
        try {
            $payload = json_decode($signedPayload, false, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new RuntimeException('Registry anchor payload is invalid JSON.', 0, $error);
        }
        if (!$payload instanceof \stdClass) throw new RuntimeException('Registry anchor must be a JSON object.');
        $fields = [
            'type', 'schema_version', 'owner_id', 'sequence', 'bundle_sha256',
            'issued_at', 'expires_at', 'previous_bundle_sha256', 'signer_kid',
        ];
        $actual = array_keys(get_object_vars($payload));
        sort($actual, SORT_STRING);
        $expected = $fields;
        sort($expected, SORT_STRING);
        if ($actual !== $expected) throw new RuntimeException('Registry anchor fields do not match the protocol schema.');

        if ($payload->type !== 'SENTRYIQ-REGISTRY-ANCHOR' || $payload->schema_version !== 1
            || !is_string($payload->owner_id) || !hash_equals($expectedOwnerId, $payload->owner_id)
            || !is_string($payload->sequence) || !preg_match('/^[1-9][0-9]{0,19}$/D', $payload->sequence)
            || !$this->validDigest($payload->bundle_sha256)
            || !is_int($payload->issued_at) || !is_int($payload->expires_at)
            || !is_string($payload->signer_kid) || !preg_match('/^[A-Za-z0-9._:-]{1,128}$/D', $payload->signer_kid)
            || !($payload->previous_bundle_sha256 === null || $this->validDigest($payload->previous_bundle_sha256))) {
            throw new RuntimeException('Registry anchor contains invalid or mismatched fields.');
        }

        $currentTime = $now ?? time();
        if ($payload->issued_at <= 0 || $payload->expires_at <= $currentTime
            || $payload->expires_at <= $payload->issued_at
            || $payload->expires_at - $payload->issued_at > self::MAX_AGE_SECONDS
            || $payload->issued_at > $currentTime + self::MAX_FUTURE_SKEW_SECONDS
            || $currentTime - $payload->issued_at > self::MAX_AGE_SECONDS) {
            throw new RuntimeException('Registry anchor is stale, expired, or future-dated.');
        }

        $this->assertSequenceContinuity(
            $payload->sequence,
            $payload->bundle_sha256,
            $payload->previous_bundle_sha256,
            $currentSequence,
            $currentBundleDigest
        );

        // The wire payload itself must be canonical. No parsing/re-encoding ambiguity is signed.
        $canonical = $this->canonicalPayload($payload);
        if (!hash_equals($canonical, $signedPayload)) {
            throw new RuntimeException('Registry anchor payload is not in canonical form.');
        }

        $signer = null;
        foreach ($trustedSigners as $candidate) {
            if (($candidate['kid'] ?? null) === $payload->signer_kid
                && ($candidate['role'] ?? null) === 'registry-anchor'
                && ($candidate['alg'] ?? null) === 'ES256'
                && is_string($candidate['public_key_pem'] ?? null)) {
                if ($signer !== null) throw new RuntimeException('Registry signer key ID is ambiguous.');
                $signer = $candidate;
            }
        }
        if ($signer === null) throw new RuntimeException('Registry anchor signer is not independently trusted.');

        $rawSignature = $signature;
        $r = substr($rawSignature, 0, 32);
        $s = substr($rawSignature, 32, 32);
        if ($r === str_repeat("\0", 32) || $s === str_repeat("\0", 32)
            || strcmp($s, hex2bin(self::P256_HALF_ORDER)) > 0) {
            throw new RuntimeException('Registry anchor signature is not canonical low-S ES256.');
        }
        $der = $this->rawEcdsaToDer($rawSignature);
        $key = openssl_pkey_get_public($signer['public_key_pem']);
        if ($key === false) throw new RuntimeException('Pinned registry signer public key is invalid.');
        try {
            $details = openssl_pkey_get_details($key);
            if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
                || ($details['bits'] ?? null) !== 256
                || ($details['curve_name'] ?? '') !== 'prime256v1') {
                throw new RuntimeException('Pinned registry signer must be a P-256 public key.');
            }
            if (openssl_verify($signedPayload, $der, $key, OPENSSL_ALGO_SHA256) !== 1) {
                throw new RuntimeException('Registry anchor signature verification failed.');
            }
        } finally {
            openssl_pkey_free($key);
        }

        return [
            'owner_id' => $payload->owner_id,
            'sequence' => $payload->sequence,
            'bundle_sha256' => $payload->bundle_sha256,
            'issued_at' => $payload->issued_at,
            'expires_at' => $payload->expires_at,
            'previous_bundle_sha256' => $payload->previous_bundle_sha256,
            'signer_kid' => $payload->signer_kid,
        ];
    }

    private function assertSequenceContinuity(string $sequence, string $digest, ?string $previous, ?string $currentSequence, ?string $currentDigest): void
    {
        if (($currentSequence === null) !== ($currentDigest === null)) {
            throw new RuntimeException('Current registry state is incomplete.');
        }
        if ($currentSequence === null) {
            if ($sequence !== '1' || $previous !== null) throw new RuntimeException('Initial registry anchor must start at sequence one.');
            return;
        }
        if (!preg_match('/^[1-9][0-9]{0,19}$/D', $currentSequence) || !$this->validDigest($currentDigest)) {
            throw new RuntimeException('Current registry state is malformed.');
        }
        $comparison = $this->compareDecimal($sequence, $currentSequence);
        if ($comparison === 0) {
            if (!hash_equals($currentDigest, $digest)) throw new RuntimeException('Same-sequence registry anchor substitution rejected.');
            return;
        }
        if ($comparison < 0 || $this->incrementDecimal($currentSequence) !== $sequence
            || $previous === null || !hash_equals($currentDigest, $previous)) {
            throw new RuntimeException('Registry anchor rollback or broken sequence chain rejected.');
        }
    }

    private function canonicalPayload(\stdClass $payload): string
    {
        $values = get_object_vars($payload);
        ksort($values, SORT_STRING);
        $parts = [];
        foreach ($values as $key => $value) {
            $parts[] = json_encode($key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR)
                . ':' . json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
        }
        return '{' . implode(',', $parts) . '}';
    }

    private function rawEcdsaToDer(string $raw): string
    {
        $integer = static function (string $bytes): string {
            $bytes = ltrim($bytes, "\0");
            if ($bytes === '') $bytes = "\0";
            if ((ord($bytes[0]) & 0x80) !== 0) $bytes = "\0" . $bytes;
            return "\x02" . chr(strlen($bytes)) . $bytes;
        };
        $body = $integer(substr($raw, 0, 32)) . $integer(substr($raw, 32, 32));
        return "\x30" . chr(strlen($body)) . $body;
    }

    private function compareDecimal(string $left, string $right): int
    {
        return strlen($left) <=> strlen($right) ?: strcmp($left, $right);
    }

    private function incrementDecimal(string $value): ?string
    {
        $digits = str_split($value);
        for ($i = count($digits) - 1; $i >= 0; $i--) {
            if ($digits[$i] !== '9') {
                $digits[$i] = (string)((int)$digits[$i] + 1);
                return ltrim(implode('', $digits), '0');
            }
            $digits[$i] = '0';
        }
        return count($digits) >= 20 ? null : '1' . implode('', $digits);
    }

    private function validDigest(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[a-f0-9]{64}$/D', $value) === 1;
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
                elseif ($char === '\\') $escaped = true;
                elseif ($char === '"') {
                    $inString = false;
                    $index = count($stack) - 1;
                    if ($index >= 0 && $stack[$index]['object']) {
                        $next = $i + 1;
                        while ($next < $length && ctype_space($json[$next])) $next++;
                        if ($next < $length && $json[$next] === ':') {
                            try {
                                $key = json_decode(substr($json, $start, $i - $start + 1), true, 2, JSON_THROW_ON_ERROR);
                            } catch (Throwable $error) {
                                throw new RuntimeException('Registry anchor contains malformed object keys.', 0, $error);
                            }
                            if (!is_string($key) || isset($stack[$index]['keys'][$key])) {
                                throw new RuntimeException('Registry anchor contains duplicate JSON object keys.');
                            }
                            $stack[$index]['keys'][$key] = true;
                        }
                    }
                }
                continue;
            }
            if ($char === '"') { $inString = true; $start = $i; }
            elseif ($char === '{') $stack[] = ['object' => true, 'keys' => []];
            elseif ($char === '[') $stack[] = ['object' => false, 'keys' => []];
            elseif ($char === '}' || $char === ']') {
                if ($stack === []) throw new RuntimeException('Registry anchor JSON structure is malformed.');
                array_pop($stack);
            }
            if (count($stack) > 8) throw new RuntimeException('Registry anchor nesting exceeds the limit.');
        }
        if ($inString || $stack !== []) throw new RuntimeException('Registry anchor JSON structure is incomplete.');
    }
}
