<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;

/**
 * Verifies the native V1 owner approval transcript against an independently
 * authenticated owner-key registry resolver and records an immutable receipt.
 *
 * The resolver MUST obtain its result from independently authenticated registry
 * state. This class deliberately accepts no caller-supplied public key.
 */
final class OwnerApprovalProofVerifier
{
    private const DOMAIN = "SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n";
    private const RECEIPT_VERSION = 1;

    /** @param callable(string):array{owner_id:string,key_id:string,role:string,algorithm:string,status:string,public_key_pem:string} $resolveActiveOwnerKey */
    public function __construct(
        private readonly BootstrapChallengeStore $challenges,
        private readonly string $privateDirectory,
        private readonly mixed $resolveActiveOwnerKey
    ) {
        if (!is_callable($resolveActiveOwnerKey)) {
            throw new RuntimeException('An authenticated owner-key registry resolver is required.');
        }
        $real = realpath($privateDirectory);
        if ($real === false || !is_dir($real) || is_link($privateDirectory)
            || (((fileperms($real) ?: 0) & 0077) !== 0)) {
            throw new RuntimeException('Approval receipts require an existing private directory.');
        }
    }

    /**
     * Consume the challenge before cryptographic verification. Invalid signatures
     * therefore burn the challenge. A receipt is committed only after verification.
     *
     * @return array{receipt_id:string,owner_id:string,key_id:string,bundle_sha256:string,approved_at:int,challenge_expires_at:int}
     */
    public function verifyAndRecord(
        string $encodedChallenge,
        string $ownerIdentifier,
        string $bundleDigestHex,
        string $signatureBase64Url,
        int $now
    ): array {
        if ($now <= 0 || !preg_match('/^[A-Za-z0-9_-]{94,96}$/D', $signatureBase64Url)) {
            throw new RuntimeException('Owner approval proof is malformed.');
        }

        // Consumption is atomic and occurs before signature verification.
        $challenge = $this->challenges->consume($encodedChallenge, $ownerIdentifier, $bundleDigestHex, $now);

        $key = ($this->resolveActiveOwnerKey)($ownerIdentifier);
        if (!is_array($key)
            || ($key['owner_id'] ?? null) !== $ownerIdentifier
            || !is_string($key['key_id'] ?? null) || $key['key_id'] === ''
            || ($key['role'] ?? null) !== 'master-signing'
            || ($key['algorithm'] ?? null) !== 'ES256'
            || ($key['status'] ?? null) !== 'active'
            || !is_string($key['public_key_pem'] ?? null)) {
            throw new RuntimeException('No active, role-bound owner master key is registered.');
        }

        $signature = self::decodeBase64Url($signatureBase64Url);
        // Native CryptoKit and Java SHA256withECDSA adapters emit ASN.1 DER ECDSA.
        if (strlen($signature) < 8 || strlen($signature) > 80) {
            throw new RuntimeException('Owner approval signature has an invalid DER length.');
        }

        $transcript = self::transcript(
            $ownerIdentifier,
            hex2bin($challenge['bundle_sha256']),
            self::decodeBase64Url($encodedChallenge),
            $challenge['expires_at']
        );
        $publicKey = openssl_pkey_get_public($key['public_key_pem']);
        if ($publicKey === false) {
            throw new RuntimeException('Registered owner public key is invalid.');
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
            'purpose' => 'owner-bootstrap-approval',
            'protocol' => 'SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1',
            'owner_id' => $ownerIdentifier,
            'key_id' => $key['key_id'],
            'bundle_sha256' => strtolower($bundleDigestHex),
            'challenge_sha256' => hash('sha256', self::decodeBase64Url($encodedChallenge)),
            'challenge_expires_at' => $challenge['expires_at'],
            'approved_at' => $now,
            'signature_sha256' => hash('sha256', $signature),
        ];
        $this->appendReceipt($receipt);
        return [
            'receipt_id' => $receipt['receipt_id'],
            'owner_id' => $ownerIdentifier,
            'key_id' => $key['key_id'],
            'bundle_sha256' => $receipt['bundle_sha256'],
            'approved_at' => $now,
            'challenge_expires_at' => $challenge['expires_at'],
        ];
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

    private static function transcript(string $owner, string $digest, string $challenge, int $expiry): string
    {
        if (strlen($digest) !== 32 || strlen($challenge) !== 32 || $expiry <= 0) {
            throw new RuntimeException('Approval transcript fields are invalid.');
        }
        return self::DOMAIN . pack('N', strlen($owner)) . $owner . $digest . pack('N', strlen($challenge)) . $challenge . pack('J', $expiry);
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
