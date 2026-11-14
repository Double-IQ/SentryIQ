<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Durable storage for the latest TUF root metadata.
 *
 * Call storeVerifiedRoot() only after the TUF updater has validated the
 * candidate root against both the previously trusted root and its own
 * threshold. This class provides atomic persistence and a local monotonic
 * version guard; it is not a signature verifier or a substitute for TUF.
 */
final class TufRootStore
{
    private string $rootPath;
    private string $lockPath;

    public function __construct(string $privateDirectory)
    {
        if ($privateDirectory === '' || !str_starts_with($privateDirectory, '/')
            || !is_dir($privateDirectory) || is_link($privateDirectory)) {
            throw new RuntimeException('TUF root storage must use an existing private directory.');
        }

        $realDirectory = realpath($privateDirectory);
        if (!is_string($realDirectory) || !is_writable($realDirectory)) {
            throw new RuntimeException('TUF root storage directory is not writable.');
        }

        $this->rootPath = $realDirectory . '/tuf-root.json';
        $this->lockPath = $realDirectory . '/tuf-root.lock';
    }

    /** Return the exact persisted root bytes, or null before first rotation. */
    public function load(): ?string
    {
        if (!file_exists($this->rootPath)) {
            return null;
        }
        if (is_link($this->rootPath) || !is_file($this->rootPath)) {
            throw new RuntimeException('Persisted TUF root is not a regular file.');
        }

        $bytes = file_get_contents($this->rootPath);
        if (!is_string($bytes) || $bytes === '' || strlen($bytes) > 5_000_000) {
            throw new RuntimeException('Persisted TUF root is unreadable or invalid in size.');
        }

        $this->rootVersion($bytes);
        return $bytes;
    }

    /**
     * Persist a root already accepted by the TUF updater.
     * Older or same-version-but-different root bytes are rejected.
     */
    public function storeVerifiedRoot(string $verifiedRootBytes): void
    {
        $newVersion = $this->rootVersion($verifiedRootBytes);
        $lock = @fopen($this->lockPath, 'c');
        if ($lock === false) {
            throw new RuntimeException('Unable to open TUF root storage lock.');
        }

        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Unable to lock TUF root storage.');
            }

            $currentBytes = $this->load();
            if ($currentBytes !== null) {
                $currentVersion = $this->rootVersion($currentBytes);
                if ($newVersion < $currentVersion
                    || ($newVersion === $currentVersion && !hash_equals(hash('sha256', $currentBytes), hash('sha256', $verifiedRootBytes)))) {
                    throw new RuntimeException('TUF root rollback or same-version replacement rejected.');
                }
                if ($newVersion === $currentVersion) {
                    return;
                }
            }

            $temporary = $this->rootPath . '.tmp-' . bin2hex(random_bytes(8));
            $written = @file_put_contents($temporary, $verifiedRootBytes, LOCK_EX);
            if ($written !== strlen($verifiedRootBytes) || !@chmod($temporary, 0600)
                || !@rename($temporary, $this->rootPath)) {
                @unlink($temporary);
                throw new RuntimeException('Atomic TUF root persistence failed.');
            }
            @chmod($this->rootPath, 0600);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function rootVersion(string $bytes): int
    {
        try {
            $metadata = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('TUF root metadata is not valid JSON.', 0, $exception);
        }

        $version = $metadata['signed']['version'] ?? null;
        if (($metadata['signed']['_type'] ?? null) !== 'root' || !is_int($version) || $version < 1) {
            throw new RuntimeException('TUF root metadata has an invalid type or version.');
        }
        return $version;
    }
}
