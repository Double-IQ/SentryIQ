<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;

/**
 * Verifies the native V2 owner approval transcript against independently
 * authenticated owner-key and candidate-bundle validation callbacks.
 *
 * The callbacks are trust boundaries: neither may use caller-supplied keys or
 * unverified app-host state as an authority.
 */
final class OwnerApprovalProofVerifier
{
    private const DOMAIN = "SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n";
    private const RECEIPT_VERSION = 1;
    private const MAX_BUNDLE_BYTES = 262144;

    /**
     * @param callable(string):array{owner_id:string,key_id:string,role:string,algorithm:string,status:string,device_keyset_digest:string,public_key_pem:string} $resolveActiveOwnerKey
     * @param callable(string,string,string,string,string,string):bool $validateApprovalContext
     */
    public function __construct(
        private readonly BootstrapChallengeStore $challenges,
        private readonly string $privateDirectory,
        private readonly mixed $resolveActiveOwnerKey,
        private readonly mixed $validateApprovalContext
    ) {
        if (!is_callable($resolveActiveOwnerKey) || !is_callable($validateApprovalContext)) {
            throw new RuntimeException('Authenticated owner-key and candidate-context resolvers are required.');
        }
        $real = realpath($privateDirectory);
        if ($real === false || !is_dir($real) || is_link($privateDirectory)
            || (((fileperms($real) ?: 0) & 0077) !== 0)) {
            throw new RuntimeException('Approval receipts require an existing private directory.');
        }
    }

    /**
     * The context validator receives canonical bundle bytes, root role, root key ID,
     * root SPKI fingerprint hex, and purpose. It must validate the candidate TUF
     * chain and prove that this root/context is actually present and permitted.
     *
     * @return array{receipt_id:string,owner_id:string,master_key_id:string,root_role:string,root_key_id:string,root_fingerprint:string,device_keyset_digest:string,purpose:string,bundle_sha256:string,approved_at:int,challenge_expires_at:int}
     */
    public function verifyAndRecord(
        string $encodedChallenge,
        string $ownerIdentifier,
        string $canonicalBundle,
        string $bundleDigestHex,
        string $rootRole,
        string $rootKeyId,
        string $rootFingerprintHex,
        string $deviceKeysetDigestHex,
        string $purpose,
        string $signatureBase64Url,
        int $now
    ): array {
        if ($now <= 0) {
            throw new RuntimeException('Owner approval proof timestamp is invalid.');
        }

        // Consume first: malformed context/signature and failed verification burn the challenge.
        $challenge = $this->challenges->consume($encodedChallenge, $ownerIdentifier, $bundleDigestHex, $now);

        if (strlen($canonicalBundle) < 1 || strlen($canonicalBundle) > self::MAX_BUNDLE_BYTES
            || !hash_equals(strtolower($bundleDigestHex), hash('sha256', $canonicalBundle))
            || !self::validOwner($ownerIdentifier)
            || !self::validToken($rootRole)
            || !self::validToken($rootKeyId)
            || !self::validToken($purpose)
            || !self::validDigest($rootFingerprintHex)
            || !self::validDigest($deviceKeysetDigestHex)
            || !preg_match('/^[A-Za-z0-9_-]{94,96}$/D', $signatureBase64Url)) {
            throw new RuntimeException('Owner approval proof context is malformed or inconsistent.');
        }

        $rootFingerprintHex = strtolower($rootFingerprintHex);
        $deviceKeysetDigestHex = strtolower($deviceKeysetDigestHex);
        if (!(($this->validateApprovalContext)(
            $canonicalBundle,
            $rootRole,
            $rootKeyId,
            $rootFingerprintHex,
            $deviceKeysetDigestHex,
            $purpose
        ))) {
            throw new RuntimeException('Candidate trust bundle or selected approval context failed validation.');
        }

        $key = ($this->resolveActiveOwnerKey)($ownerIdentifier);
        if (!is_array($key)
            || ($key['owner_id'] ?? null) !== $ownerIdentifier
            || !is_string($key['key_id'] ?? null) || $key['key_id'] === ''
            || ($key['role'] ?? null) !== 'master-signing'
            || ($key['algorithm'] ?? null) !== 'ES256'
            || ($key['status'] ?? null) !== 'active'
            || !is_string($key['device_keyset_digest'] ?? null)
            || !self::validDigest($key['device_keyset_digest'])
            || !hash_equals(strtolower($key['device_keyset_digest']), $deviceKeysetDigestHex)
            || !is_string($key['public_key_pem'] ?? null)) {
            throw new RuntimeException('No active owner master key matching the approved device keyset is registered.');
        }

        $signature = self::decodeBase64Url($signatureBase64Url);
        // Native CryptoKit and Java SHA256withECDSA adapters emit ASN.1 DER ECDSA.
        if (strlen($signature) < 8 || strlen($signature) > 80) {
            throw new RuntimeException('Owner approval signature has an invalid DER length.');
        }

        $transcript = self::transcript(
            $ownerIdentifier,
            hex2bin($bundleDigestHex),
            $rootRole,
            $rootKeyId,
            hex2bin($rootFingerprintHex),
            hex2bin($deviceKeysetDigestHex),
            $purpose,
            self::decodeBase64Url($encodedChallenge),
            $challenge['expires_at']
        );
        $publicKey = openssl_pkey_get_public($key['public_key_pem']);
        if ($publicKey === false) {
            throw new RuntimeException('Registered owner public key is invalid.');
        }
        $details = openssl_pkey_get_details($publicKey);
        if (!is_array($details)
            || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            openssl_pkey_free($publicKey);
            throw new RuntimeException('Registered owner key is not a P-256 ES256 key.');
        }
        try {
            $verified = openssl_verify($transcript, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        } finally {
            openssl_pkey_free($publicKey);
        }
        if ($verified !== 1) {
            throw new RuntimeException('Owner approval signature verification failed.');
        }

        $receipt = [
            'receipt_id' => bin2hex(random_bytes(16)),
            'challenge_purpose' => 'owner-bootstrap-approval',
            'protocol' => 'SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2',
            'owner_id' => $ownerIdentifier,
            'master_key_id' => $key['key_id'],
            'bundle_sha256' => strtolower($bundleDigestHex),
            'root_role' => $rootRole,
            'root_key_id' => $rootKeyId,
            'root_fingerprint' => $rootFingerprintHex,
            'device_keyset_digest' => $deviceKeysetDigestHex,
            'purpose' => $purpose,
            'challenge_sha256' => hash('sha256', self::decodeBase64Url($encodedChallenge)),
            'challenge_expires_at' => $challenge['expires_at'],
            'approved_at' => $now,
            'signature_sha256' => hash('sha256', $signature),
        ];
        $this->appendReceipt($receipt);

        return [
            'receipt_id' => $receipt['receipt_id'],
            'owner_id' => $ownerIdentifier,
            'master_key_id' => $key['key_id'],
            'root_role' => $rootRole,
            'root_key_id' => $rootKeyId,
            'root_fingerprint' => $rootFingerprintHex,
            'device_keyset_digest' => $deviceKeysetDigestHex,
            'purpose' => $purpose,
            'bundle_sha256' => $receipt['bundle_sha256'],
            'approved_at' => $now,
            'challenge_expires_at' => $challenge['expires_at'],
        ];
    }

    private static function validOwner(string $owner): bool
    {
        return $owner !== '' && strlen($owner) <= 256
            && !str_contains($owner, "\n") && !str_contains($owner, "\r");
    }

    private static function validToken(string $value): bool
    {
        return $value !== '' && strlen($value) <= 128
            && preg_match('/^[A-Za-z0-9._-]+$/D', $value) === 1;
    }

    private static function validDigest(string $value): bool
    {
        return preg_match('/^[a-fA-F0-9]{64}$/D', $value) === 1;
    }

    /** @param array<string,mixed> $receipt */
    private function appendReceipt(array $receipt): void
    {
        $path = $this->privateDirectory . '/.owner-approval-receipts.json';
        $lockPath = $this->privateDirectory . '/.owner-approval-receipts.lock';
        if (is_link($path) || is_link($lockPath)) {
            throw new RuntimeException('Approval receipt paths must not be symbolic links.');
        }
        $lock = @fopen($lockPath, 'c+b');
        if (!is_resource($lock)) throw new RuntimeException('Unable to open approval receipt lock.');
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock approval receipts.');
            @chmod($lockPath, 0600);
            clearstatcache(true, $lockPath);
            if (((fileperms($lockPath) ?: 0) & 0777) !== 0600) throw new RuntimeException('Approval receipt lock permissions are not private.');

            $records = [];
            if (is_file($path)) {
                if ((filesize($path) ?: 0) > 4_194_304) throw new RuntimeException('Approval receipt store exceeds its size limit.');
                $raw = @file_get_contents($path);
                $decoded = is_string($raw) ? json_decode($raw, true, 16, JSON_THROW_ON_ERROR) : null;
                if (!is_array($decoded) || ($decoded['version'] ?? null) !== self::RECEIPT_VERSION || !is_array($decoded['receipts'] ?? null)) {
                    throw new RuntimeException('Approval receipt store is corrupt; refusing to reset it.');
                }
                $records = $decoded['receipts'];
            } elseif (file_exists($path)) {
                throw new RuntimeException('Approval receipt path is not a regular file.');
            }
            if (count($records) >= 10000) throw new RuntimeException('Approval receipt capacity reached.');
            foreach ($records as $record) {
                if (is_array($record) && isset($record['challenge_sha256'])
                    && is_string($record['challenge_sha256'])
                    && hash_equals($record['challenge_sha256'], $receipt['challenge_sha256'])) {
                    throw new RuntimeException('An approval receipt already exists for this challenge.');
                }
            }
            $records[] = $receipt;
            $json = json_encode(['version' => self::RECEIPT_VERSION, 'receipts' => $records], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $temp = $this->privateDirectory . '/.owner-approval-receipts-' . bin2hex(random_bytes(8)) . '.tmp';
            $handle = @fopen($temp, 'x+b');
            if (!is_resource($handle)) throw new RuntimeException('Unable to create approval receipt update.');
            try {
                if (!@chmod($temp, 0600)) throw new RuntimeException('Unable to protect approval receipt update.');
                $written = fwrite($handle, $json);
                if ($written !== strlen($json) || !fflush($handle)) throw new RuntimeException('Unable to persist approval receipt.');
                if (function_exists('fsync') && !fsync($handle)) throw new RuntimeException('Unable to sync approval receipt.');
            } catch (\Throwable $error) {
                fclose($handle); @unlink($temp); throw $error;
            }
            fclose($handle);
            if (!@rename($temp, $path)) { @unlink($temp); throw new RuntimeException('Unable to atomically commit approval receipt.'); }
            @chmod($path, 0600);
            clearstatcache(true, $path);
            if (((fileperms($path) ?: 0) & 0777) !== 0600) throw new RuntimeException('Approval receipt permissions are not private.');
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private static function transcript(
        string $owner,
        string $bundleDigest,
        string $rootRole,
        string $rootKeyId,
        string $rootFingerprint,
        string $deviceKeysetDigest,
        string $purpose,
        string $challenge,
        int $expiry
    ): string {
        if (strlen($bundleDigest) !== 32 || strlen($rootFingerprint) !== 32
            || strlen($deviceKeysetDigest) !== 32 || strlen($challenge) !== 32 || $expiry <= 0) {
            throw new RuntimeException('Approval transcript fields are invalid.');
        }
        return self::DOMAIN
            . self::field($owner)
            . $bundleDigest
            . self::field($rootRole)
            . self::field($rootKeyId)
            . $rootFingerprint
            . $deviceKeysetDigest
            . self::field($purpose)
            . pack('N', strlen($challenge))
            . $challenge
            . pack('J', $expiry);
    }

    private static function field(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    private static function decodeBase64Url(string $encoded): string
    {
        $raw = base64_decode(strtr($encoded . str_repeat('=', (4 - strlen($encoded) % 4) % 4), '-_', '+/'), true);
        if (!is_string($raw) || rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $encoded) {
            throw new RuntimeException('Non-canonical base64url value.');
        }
        return $raw;
    }
}
