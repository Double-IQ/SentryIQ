<?php

declare(strict_types=1);

namespace SentryIQ\\Security;

use RuntimeException;

/**
 * Durable, single-use owner-bootstrap challenges.
 *
 * The caller must place the store in the private application data directory.
 * A challenge is removed and durably committed before its bindings are checked,
 * so even a failed submission burns the token and cannot be replayed.
 */
final class BootstrapChallengeStore
{
    private const STORE_VERSION = 1;
    private const PURPOSE = 'owner-bootstrap-approval';
    private const MAX_RECORDS = 10000;
    private const MAX_TTL_SECONDS = 300;
    private const MAX_FUTURE_SKEW_SECONDS = 5;

    public function __construct(private readonly string $directory)
    {
        $real = realpath($directory);
        if ($real === false || !is_dir($real) || is_link($directory) || !$this->isOutsideDocumentRoot($real)) {
            throw new RuntimeException('Bootstrap challenge storage must be an existing private directory outside the document root.');
        }
    }

    public function issue(string $ownerIdentifier, string $bundleDigestHex, int $now, int $ttlSeconds = 300): string
    {
        self::assertOwnerIdentifier($ownerIdentifier);
        self::assertDigest($bundleDigestHex);
        if ($ttlSeconds < 1 || $ttlSeconds > self::MAX_TTL_SECONDS || $now <= 0) {
            throw new RuntimeException('Invalid bootstrap challenge lifetime.');
        }

        $challenge = random_bytes(32);
        $encoded = rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
        $key = hash('sha256', $challenge);

        $this->mutate(function (array &$records) use ($key, $ownerIdentifier, $bundleDigestHex, $now, $ttlSeconds): void {
            foreach ($records as $recordKey => $record) {
                if (!is_array($record) || !isset($record['expires_at']) || !is_int($record['expires_at']) || $record['expires_at'] < $now) {
                    unset($records[$recordKey]);
                }
            }
            if (count($records) >= self::MAX_RECORDS) {
                throw new RuntimeException('Bootstrap challenge capacity reached.');
            }
            $records[$key] = [
                'purpose' => self::PURPOSE,
                'owner_id' => $ownerIdentifier,
                'bundle_sha256' => strtolower($bundleDigestHex),
                'issued_at' => $now,
                'expires_at' => $now + $ttlSeconds,
            ];
        });

        return $encoded;
    }

    /**
     * Consume exactly once. The record is removed before expiry/owner/digest
     * validation and the removal is committed while holding the exclusive lock.
     *
     * @return array{purpose:string, owner_id:string, bundle_sha256:string, issued_at:int, expires_at:int}
     */
    public function consume(string $encodedChallenge, string $ownerIdentifier, string $bundleDigestHex, int $now): array
    {
        self::assertOwnerIdentifier($ownerIdentifier);
        self::assertDigest($bundleDigestHex);
        if ($now <= 0 || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $encodedChallenge)) {
            throw new RuntimeException('Bootstrap challenge is malformed or missing.');
        }

        $raw = base64_decode(strtr($encodedChallenge . '=', '-_', '+/'), true);
        if (!is_string($raw) || strlen($raw) !== 32) {
            throw new RuntimeException('Bootstrap challenge is malformed or missing.');
        }
        $key = hash('sha256', $raw);
        $consumed = null;

        $this->mutate(function (array &$records) use ($key, &$consumed): void {
            if (array_key_exists($key, $records)) {
                $consumed = $records[$key];
                unset($records[$key]);
            }
        });

        if (!is_array($consumed)
            || ($consumed['purpose'] ?? null) !== self::PURPOSE
            || !is_string($consumed['owner_id'] ?? null)
            || !is_string($consumed['bundle_sha256'] ?? null)
            || !is_int($consumed['issued_at'] ?? null)
            || !is_int($consumed['expires_at'] ?? null)) {
            throw new RuntimeException('Bootstrap challenge is unknown or already consumed.');
        }

        if ($consumed['issued_at'] > $now + self::MAX_FUTURE_SKEW_SECONDS
            || $now > $consumed['expires_at']
            || $consumed['expires_at'] - $consumed['issued_at'] > self::MAX_TTL_SECONDS) {
            throw new RuntimeException('Bootstrap challenge expired or has an invalid lifetime.');
        }

        if (!hash_equals($consumed['owner_id'], $ownerIdentifier)
            || !hash_equals($consumed['bundle_sha256'], strtolower($bundleDigestHex))) {
            throw new RuntimeException('Bootstrap challenge binding mismatch.');
        }

        return $consumed;
    }

    private function mutate(callable $operation): void
    {
        $lockPath = $this->directory . '/.bootstrap-challenges.lock';
        $storePath = $this->directory . '/.bootstrap-challenges.json';
        if (is_link($lockPath) || is_link($storePath)) {
            throw new RuntimeException('Bootstrap challenge store must not use symbolic links.');
        }

        $lock = @fopen($lockPath, 'c+b');
        if (!is_resource($lock)) {
            throw new RuntimeException('Unable to open bootstrap challenge lock.');
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Unable to lock bootstrap challenge store.');
            }
            @chmod($lockPath, 0600);
            if (is_link($storePath)) {
                throw new RuntimeException('Bootstrap challenge store must not use symbolic links.');
            }

            $records = [];
            if (is_file($storePath)) {
                $raw = @file_get_contents($storePath);
                $decoded = is_string($raw) ? json_decode($raw, true, 16, JSON_THROW_ON_ERROR) : null;
                if (!is_array($decoded)
                    || ($decoded['version'] ?? null) !== self::STORE_VERSION
                    || !is_array($decoded['records'] ?? null)) {
                    throw new RuntimeException('Bootstrap challenge store is corrupt; refusing to reset it.');
                }
                $records = $decoded['records'];
            }

            $operation($records);
            $json = json_encode(['version' => self::STORE_VERSION, 'records' => $records], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $tempPath = $this->directory . '/.bootstrap-challenges-' . bin2hex(random_bytes(8)) . '.tmp';
            $handle = @fopen($tempPath, 'x+b');
            if (!is_resource($handle)) {
                throw new RuntimeException('Unable to create atomic bootstrap challenge update.');
            }
            try {
                @chmod($tempPath, 0600);
                $written = fwrite($handle, $json);
                if ($written !== strlen($json) || !fflush($handle)) {
                    throw new RuntimeException('Unable to persist bootstrap challenge update.');
                }
                if (function_exists('fsync') && !fsync($handle)) {
                    throw new RuntimeException('Unable to sync bootstrap challenge update.');
                }
            } finally {
                fclose($handle);
            }
            if (!@rename($tempPath, $storePath)) {
                @unlink($tempPath);
                throw new RuntimeException('Unable to atomically commit bootstrap challenge update.');
            }
            @chmod($storePath, 0600);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function isOutsideDocumentRoot(string $directory): bool
    {
        $documentRoot = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
        if ($documentRoot === '') {
            return PHP_SAPI === 'cli';
        }
        $realRoot = realpath($documentRoot);
        if ($realRoot === false || !is_dir($realRoot)) {
            return false;
        }
        $root = rtrim($realRoot, DIRECTORY_SEPARATOR);
        $target = rtrim($directory, DIRECTORY_SEPARATOR);
        if ($root === '') {
            $root = DIRECTORY_SEPARATOR;
        }
        if (DIRECTORY_SEPARATOR === '\\\\') {
            $root = strtolower($root);
            $target = strtolower($target);
        }
        return $target !== $root && !str_starts_with($target, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR);
    }

    private static function assertOwnerIdentifier(string $ownerIdentifier): void
    {
        if ($ownerIdentifier === '' || strlen($ownerIdentifier) > 256 || str_contains($ownerIdentifier, "\\n") || str_contains($ownerIdentifier, "\\r")) {
            throw new RuntimeException('Invalid owner identifier.');
        }
    }

    private static function assertDigest(string $digest): void
    {
        if (!preg_match('/^[a-fA-F0-9]{64}$/D', $digest)) {
            throw new RuntimeException('Bundle digest must be a SHA-256 hexadecimal value.');
        }
    }
}
