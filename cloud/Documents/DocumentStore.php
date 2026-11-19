<?php

declare(strict_types=1);

namespace SentryIQCloud\Documents;

use RuntimeException;
use Throwable;

final class DocumentStore
{
    public function __construct(private readonly string $path)
    {
        if ($this->path === '' || !str_starts_with($this->path, '/') || is_link($this->path)) {
            throw new RuntimeException('Document metadata path is invalid.');
        }

        $directory = dirname($this->path);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Document storage directory could not be created.');
        }
        $realDirectory = realpath($directory);
        if ($realDirectory === false || is_link($directory) || rtrim($realDirectory, '/') !== rtrim($directory, '/')) {
            throw new RuntimeException('Document storage directory path is not canonical.');
        }

        $documentRootValue = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
        $documentRoot = $documentRootValue !== '' ? realpath($documentRootValue) : false;
        if ($documentRootValue !== '' && ($documentRoot === false || !is_dir($documentRoot))) {
            throw new RuntimeException('Document root could not be resolved safely.');
        }
        if (is_string($documentRoot) && $documentRoot !== ''
            && ($realDirectory === $documentRoot
                || str_starts_with($realDirectory . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR))) {
            throw new RuntimeException('Document metadata must be stored outside the public web root.');
        }
        if (is_link($this->path)) {
            throw new RuntimeException('Document metadata file must not be a symbolic link.');
        }
    }

    public function all(): array
    {
        return $this->withLock(LOCK_SH, fn(): array => $this->readUnlocked());
    }

    public function put(string $id, array $metadata): void
    {
        $this->validateId($id);
        $this->mutate(static function (array &$data) use ($id, $metadata): void {
            $data[$id] = $metadata;
        });
    }

    public function remove(string $id): void
    {
        $this->validateId($id);
        $this->mutate(static function (array &$data) use ($id): void {
            unset($data[$id]);
        });
    }

    private function validateId(string $id): void
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            throw new \InvalidArgumentException('Invalid document identifier.');
        }
    }

    private function mutate(callable $callback): void
    {
        $this->withLock(LOCK_EX, function () use ($callback): void {
            $data = $this->readUnlocked();
            $callback($data);
            $this->writeUnlocked($data);
        });
    }

    private function withLock(int $operation, callable $callback): mixed
    {
        $lockPath = $this->path . '.lock';
        if (is_link($lockPath)) {
            throw new RuntimeException('Document metadata lock must not be a symbolic link.');
        }
        $lock = @fopen($lockPath, 'c');
        if ($lock === false) {
            throw new RuntimeException('Unable to open document metadata lock.');
        }
        try {
            $opened = fstat($lock);
            $linked = @lstat($lockPath);
            if (!is_array($opened) || !is_array($linked)
                || (($linked['mode'] & 0170000) !== 0100000)
                || $opened['dev'] !== $linked['dev']
                || $opened['ino'] !== $linked['ino']) {
                throw new RuntimeException('Document metadata lock path changed unexpectedly.');
            }
            @chmod($lockPath, 0600);
            if (!flock($lock, $operation)) {
                throw new RuntimeException('Unable to lock document metadata.');
            }
            return $callback();
        } finally {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function readUnlocked(): array
    {
        if (is_link($this->path)) {
            throw new RuntimeException('Document metadata file must not be a symbolic link.');
        }
        if (!file_exists($this->path)) return [];
        if (!is_file($this->path) || !is_readable($this->path)) {
            throw new RuntimeException('Document metadata file is unavailable.');
        }

        $handle = @fopen($this->path, 'rb');
        if ($handle === false) throw new RuntimeException('Document metadata file is unavailable.');
        try {
            $opened = fstat($handle);
            $linked = @lstat($this->path);
            if (!is_array($opened) || !is_array($linked)
                || (($linked['mode'] & 0170000) !== 0100000)
                || $opened['dev'] !== $linked['dev']
                || $opened['ino'] !== $linked['ino']) {
                throw new RuntimeException('Document metadata file path changed unexpectedly.');
            }
            if ((int)($opened['size'] ?? 0) > 16 * 1024 * 1024) {
                throw new RuntimeException('Document metadata file exceeds the size limit.');
            }
            $permissions = (int)($opened['mode'] ?? 0);
            if (($permissions & 0077) !== 0) {
                throw new RuntimeException('Document metadata file permissions must be owner-only.');
            }
            $raw = stream_get_contents($handle, 16 * 1024 * 1024 + 1);
        } finally {
            fclose($handle);
        }

        try {
            $data = is_string($raw) ? json_decode($raw, true, 32, JSON_THROW_ON_ERROR) : null;
        } catch (Throwable) {
            throw new RuntimeException('Document metadata file is invalid.');
        }
        if (!is_array($data)) throw new RuntimeException('Document metadata file is invalid.');
        return $data;
    }

    private function writeUnlocked(array $data): void
    {
        $temporary = $this->path . '.tmp-' . bin2hex(random_bytes(12));
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) throw new RuntimeException('Document metadata could not be saved.');
        try {
            @chmod($temporary, 0600);
            $length = strlen($json);
            $written = 0;
            while ($written < $length) {
                $count = fwrite($handle, substr($json, $written));
                if (!is_int($count) || $count <= 0) {
                    throw new RuntimeException('Document metadata could not be written.');
                }
                $written += $count;
            }
            if (!fflush($handle)) throw new RuntimeException('Document metadata could not be flushed.');
            if (function_exists('fsync')) @fsync($handle);
        } catch (Throwable $exception) {
            fclose($handle);
            @unlink($temporary);
            throw $exception;
        }
        fclose($handle);

        if (is_link($this->path) || !@rename($temporary, $this->path)) {
            @unlink($temporary);
            throw new RuntimeException('Document metadata could not be committed.');
        }
        @chmod($this->path, 0600);
    }
}
