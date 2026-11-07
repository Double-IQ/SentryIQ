<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use RuntimeException;

final class GalleryObjectStore
{
    private const ROLES = ['original', 'thumbnail', 'preview', 'metadata'];

    public function __construct(private readonly string $file)
    {
        if ($this->file === '' || !str_starts_with($this->file, '/') || is_link($this->file)) {
            throw new RuntimeException('Gallery object index path is invalid.');
        }
        $directory = realpath(dirname($this->file));
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if ($directory === false || is_link(dirname($this->file))
            || (is_string($documentRoot) && $documentRoot !== ''
                && ($directory === $documentRoot || str_starts_with($directory . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
            throw new RuntimeException('Gallery object storage must be outside the public web root.');
        }
    }

    public function createPending(string $photoId, array $objectKeys): void
    {
        $this->validatePhotoId($photoId);
        $this->validateObjectKeys($objectKeys);
        $this->mutate(function (array &$records) use ($photoId, $objectKeys): void {
            if (isset($records[$photoId])) throw new RuntimeException('Gallery object identifier already exists.');
            $records[$photoId] = [
                'status' => 'pending',
                'created_at' => time(),
                'objects' => array_map(static fn(string $key): array => ['key' => $key], $objectKeys),
            ];
        });
    }

    public function commit(string $photoId, array $envelopes, array $sizes): void
    {
        $this->validatePhotoId($photoId);
        $this->mutate(function (array &$records) use ($photoId, $envelopes, $sizes): void {
            $record = $records[$photoId] ?? null;
            if (!is_array($record) || ($record['status'] ?? '') !== 'pending' || !is_array($record['objects'] ?? null)) {
                throw new RuntimeException('Gallery upload reservation is unavailable or expired.');
            }
            if (array_diff(self::ROLES, array_keys($envelopes)) !== [] || array_diff(array_keys($envelopes), self::ROLES) !== []) {
                throw new RuntimeException('Gallery upload is missing an encrypted object envelope.');
            }
            foreach (self::ROLES as $role) {
                $envelope = $envelopes[$role] ?? null;
                $size = $sizes[$role] ?? null;
                if (!is_array($envelope) || ($envelope['version'] ?? null) !== 1
                    || ($envelope['algorithm'] ?? '') !== 'A256GCM'
                    || ($envelope['keyWrap'] ?? '') !== 'RSA-OAEP-256'
                    || ($envelope['photoId'] ?? '') !== $photoId
                    || ($envelope['role'] ?? '') !== $role
                    || !$this->isBase64Url($envelope['nonce'] ?? null, 16)
                    || !$this->isBase64Url($envelope['wrappedDek'] ?? null, 512)
                    || !is_int($size) || $size < 17 || $size > 52428800) {
                    throw new RuntimeException('Gallery encrypted object metadata is invalid.');
                }
                $record['objects'][$role]['envelope'] = $envelope;
                $record['objects'][$role]['size'] = $size;
            }
            $record['status'] = 'active';
            $record['uploaded_at'] = time();
            $records[$photoId] = $record;
        });
    }

    public function find(string $photoId): ?array
    {
        $this->validatePhotoId($photoId);
        $records = $this->read();
        return isset($records[$photoId]) && is_array($records[$photoId]) ? $records[$photoId] : null;
    }

    public function all(): array
    {
        $records = $this->read();
        $active = [];
        foreach ($records as $photoId => $record) {
            if (is_string($photoId) && is_array($record) && ($record['status'] ?? '') === 'active') {
                $active[$photoId] = $record;
            }
        }
        uasort($active, static fn(array $left, array $right): int => (int)($right['uploaded_at'] ?? 0) <=> (int)($left['uploaded_at'] ?? 0));
        return $active;
    }

    public function remove(string $photoId): ?array
    {
        $this->validatePhotoId($photoId);
        $removed = null;
        $this->mutate(function (array &$records) use ($photoId, &$removed): void {
            if (!isset($records[$photoId]) || !is_array($records[$photoId])) return;
            $removed = $records[$photoId];
            unset($records[$photoId]);
        });
        return $removed;
    }

    private function validateObjectKeys(array $objectKeys): void
    {
        if (array_diff(self::ROLES, array_keys($objectKeys)) !== [] || array_diff(array_keys($objectKeys), self::ROLES) !== []) {
            throw new RuntimeException('Gallery object roles are invalid.');
        }
        foreach (self::ROLES as $role) {
            $key = $objectKeys[$role] ?? null;
            if (!is_string($key) || !preg_match('#^gallery/v1/[a-f0-9]{64}/' . preg_quote($role, '#') . '$#', $key)) {
                throw new RuntimeException('Gallery object key is invalid.');
            }
        }
    }

    private function validatePhotoId(string $photoId): void
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $photoId)) throw new RuntimeException('Invalid Gallery photo identifier.');
    }

    private function isBase64Url(mixed $value, int $length): bool
    {
        return is_string($value) && strlen($value) === $length && preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1;
    }

    private function read(): array
    {
        if (!is_file($this->file)) return [];
        if (is_link($this->file) || !is_readable($this->file)) throw new RuntimeException('Gallery object index is unavailable.');
        $raw = @file_get_contents($this->file);
        $records = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($records)) throw new RuntimeException('Gallery object index is invalid.');
        return $records;
    }

    private function mutate(callable $callback): void
    {
        $lockPath = $this->file . '.lock';
        $lock = @fopen($lockPath, 'c');
        if ($lock === false) throw new RuntimeException('Unable to lock Gallery object index.');
        @chmod($lockPath, 0600);
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock Gallery object index.');
            $records = $this->read();
            $callback($records);
            $this->write($records);
        } finally {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function write(array $records): void
    {
        $json = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temporary = $this->file . '.tmp-' . bin2hex(random_bytes(12));
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) throw new RuntimeException('Unable to create Gallery object index.');
        try {
            @chmod($temporary, 0600);
            if (fwrite($handle, $json) !== strlen($json)) throw new RuntimeException('Unable to write Gallery object index.');
            fflush($handle);
            if (function_exists('fsync')) @fsync($handle);
        } finally {
            fclose($handle);
        }
        if (!@rename($temporary, $this->file)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to commit Gallery object index.');
        }
        @chmod($this->file, 0600);
    }
}
