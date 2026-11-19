<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Durable storage for the latest TUF root metadata.
 *
 * storeVerifiedRoot() must only receive bytes returned by a successfully
 * completed TUF refresh. This class enforces local atomicity and monotonic
 * versions; it does not verify TUF signatures or metadata thresholds.
 */
final class TufRootStore
{
    private const MAX_ROOT_BYTES = 5_000_000;

    private string $directory;
    private string $rootPath;
    private string $lockPath;

    public function __construct(string $privateDirectory)
    {
        if ($privateDirectory === '' || !str_starts_with($privateDirectory, '/')
            || !is_dir($privateDirectory) || is_link($privateDirectory)) {
            throw new RuntimeException('TUF root storage must use an existing private directory.');
        }

        $realDirectory = realpath($privateDirectory);
        $requestedDirectory = rtrim($privateDirectory, DIRECTORY_SEPARATOR);
        if (!is_string($realDirectory) || $realDirectory === ''
            || rtrim($realDirectory, DIRECTORY_SEPARATOR) !== $requestedDirectory
            || !is_writable($realDirectory)) {
            throw new RuntimeException('TUF root storage directory is not canonical or writable.');
        }

        $directoryMode = @fileperms($realDirectory);
        if (!is_int($directoryMode) || (($directoryMode & 0022) !== 0)) {
            throw new RuntimeException('TUF root storage directory must not be group- or world-writable.');
        }

        $documentRoot = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
        if ($documentRoot === '' && PHP_SAPI !== 'cli') {
            throw new RuntimeException('Unable to establish the public web root for TUF storage.');
        }
        if ($documentRoot !== '') {
            $realDocumentRoot = realpath($documentRoot);
            if (!is_string($realDocumentRoot) || !is_dir($realDocumentRoot)) {
                throw new RuntimeException('The public web root cannot be verified for TUF storage.');
            }
            $publicRoot = rtrim($realDocumentRoot, DIRECTORY_SEPARATOR);
            $prefix = rtrim($publicRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if ($realDirectory === $publicRoot || str_starts_with($realDirectory . DIRECTORY_SEPARATOR, $prefix)) {
                throw new RuntimeException('TUF root storage must be outside the public web root.');
            }
        }

        $this->directory = $realDirectory;
        $this->rootPath = $realDirectory . DIRECTORY_SEPARATOR . 'tuf-root.json';
        $this->lockPath = $realDirectory . DIRECTORY_SEPARATOR . 'tuf-root.lock';
    }

    /** Return exact persisted root bytes, or null before first successful rotation. */
    public function load(): ?string
    {
        if (is_link($this->rootPath)) {
            throw new RuntimeException('Persisted TUF root must not be a symbolic link.');
        }
        if (!file_exists($this->rootPath)) {
            return null;
        }
        if (!is_file($this->rootPath) || !is_readable($this->rootPath)) {
            throw new RuntimeException('Persisted TUF root is not a readable regular file.');
        }

        $handle = @fopen($this->rootPath, 'rb');
        if ($handle === false) {
            throw new RuntimeException('Persisted TUF root could not be opened.');
        }
        try {
            $stat = fstat($handle);
            if (!is_array($stat) || (($stat['mode'] & 0170000) !== 0100000)
                || (($stat['mode'] & 0077) !== 0)) {
                throw new RuntimeException('Persisted TUF root permissions or file type are invalid.');
            }
            $bytes = stream_get_contents($handle, self::MAX_ROOT_BYTES + 1);
        } finally {
            fclose($handle);
        }

        if (!is_string($bytes) || $bytes === '' || strlen($bytes) > self::MAX_ROOT_BYTES) {
            throw new RuntimeException('Persisted TUF root is unreadable or invalid in size.');
        }
        $this->rootVersion($bytes);
        return $bytes;
    }

    /**
     * Persist a root already accepted by the TUF updater.
     * Rollbacks and same-version replacements with different bytes are rejected.
     */
    public function storeVerifiedRoot(string $verifiedRootBytes): void
    {
        $newVersion = $this->rootVersion($verifiedRootBytes);
        $this->withLock(function () use ($verifiedRootBytes, $newVersion): void {
            $currentBytes = $this->load();
            if ($currentBytes !== null) {
                $currentVersion = $this->rootVersion($currentBytes);
                if ($newVersion < $currentVersion
                    || ($newVersion === $currentVersion
                        && !hash_equals(hash('sha256', $currentBytes), hash('sha256', $verifiedRootBytes)))) {
                    throw new RuntimeException('TUF root rollback or same-version replacement rejected.');
                }
                if ($newVersion === $currentVersion) {
                    return;
                }
            }

            $temporary = $this->rootPath . '.tmp-' . bin2hex(random_bytes(16));
            $handle = @fopen($temporary, 'xb');
            if ($handle === false) {
                throw new RuntimeException('Unable to create temporary TUF root storage.');
            }

            $complete = false;
            try {
                if (!@chmod($temporary, 0600)) {
                    throw new RuntimeException('Unable to secure temporary TUF root storage.');
                }
                $length = strlen($verifiedRootBytes);
                $offset = 0;
                while ($offset < $length) {
                    $written = fwrite($handle, substr($verifiedRootBytes, $offset));
                    if (!is_int($written) || $written < 1) {
                        throw new RuntimeException('Unable to write complete TUF root metadata.');
                    }
                    $offset += $written;
                }
                if (!fflush($handle)) {
                    throw new RuntimeException('Unable to flush TUF root metadata.');
                }
                if (function_exists('fsync') && !@fsync($handle)) {
                    throw new RuntimeException('Unable to synchronize TUF root metadata.');
                }
                $complete = true;
            } finally {
                fclose($handle);
                if (!$complete) {
                    @unlink($temporary);
                }
            }

            if (is_link($this->rootPath) || !@rename($temporary, $this->rootPath)) {
                @unlink($temporary);
                throw new RuntimeException('Atomic TUF root persistence failed.');
            }
            if (!@chmod($this->rootPath, 0600)) {
                throw new RuntimeException('Unable to secure persisted TUF root metadata.');
            }
        });
    }

    private function withLock(callable $operation): void
    {
        if (is_link($this->lockPath)) {
            throw new RuntimeException('TUF root storage lock must not be a symbolic link.');
        }
        $handle = @fopen($this->lockPath, 'c');
        if ($handle === false) {
            throw new RuntimeException('Unable to open TUF root storage lock.');
        }

        try {
            if (!@chmod($this->lockPath, 0600) || !flock($handle, LOCK_EX)) {
                throw new RuntimeException('Unable to acquire TUF root storage lock.');
            }
            $stat = fstat($handle);
            if (!is_array($stat) || (($stat['mode'] & 0170000) !== 0100000)
                || (($stat['mode'] & 0077) !== 0)) {
                throw new RuntimeException('TUF root storage lock permissions or file type are invalid.');
            }
            $operation();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function rootVersion(string $bytes): int
    {
        if ($bytes === '' || strlen($bytes) > self::MAX_ROOT_BYTES) {
            throw new RuntimeException('TUF root metadata is empty or exceeds the size limit.');
        }
        try {
            $metadata = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('TUF root metadata is not valid JSON.', 0, $exception);
        }

        $signed = is_array($metadata) ? ($metadata['signed'] ?? null) : null;
        $version = is_array($signed) ? ($signed['version'] ?? null) : null;
        if (!is_array($signed) || ($signed['_type'] ?? null) !== 'root'
            || !is_int($version) || $version < 1) {
            throw new RuntimeException('TUF root metadata has an invalid type or version.');
        }
        return $version;
    }
}
