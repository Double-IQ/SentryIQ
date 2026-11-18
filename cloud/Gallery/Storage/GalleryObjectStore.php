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

    public function createPending(string $photoId, array $objectKeys, ?string $keyId = null): void
    {
        $this->validatePhotoId($photoId);
        $this->validateObjectKeys($objectKeys);
        if ($keyId !== null && !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $keyId)) throw new RuntimeException('Invalid Gallery encryption key identifier.');
        $this->mutate(function (array &$records) use ($photoId, $objectKeys, $keyId): void {
            if (isset($records[$photoId])) throw new RuntimeException('Gallery object identifier already exists.');
            $records[$photoId] = [
                'status' => 'pending',
                'created_at' => time(),
                'key_id' => $keyId,
                'objects' => array_map(static fn(string $key): array => ['key' => $key], $objectKeys),
            ];
        });
    }

    public function commit(string $photoId, array $envelopes, array $sizes, array $allowedKeyIds = [], bool $requireKeyId = false): void
    {
        $this->validatePhotoId($photoId);
        $this->mutate(function (array &$records) use ($photoId, $envelopes, $sizes, $allowedKeyIds, $requireKeyId): void {
            $record = $records[$photoId] ?? null;
            if (!is_array($record) || ($record['status'] ?? '') !== 'pending' || !is_array($record['objects'] ?? null)) {
                throw new RuntimeException('Gallery upload reservation is unavailable or expired.');
            }
            if (array_diff(self::ROLES, array_keys($envelopes)) !== [] || array_diff(array_keys($envelopes), self::ROLES) !== []) {
                throw new RuntimeException('Gallery upload is missing an encrypted object envelope.');
            }
            if ($requireKeyId && (!is_string($record['key_id'] ?? null) || $record['key_id'] === '')) {
                throw new RuntimeException('Gallery upload reservation has no encryption key binding.');
            }
            foreach (self::ROLES as $role) {
                $envelope = $envelopes[$role] ?? null;
                $size = $sizes[$role] ?? null;
                if (!is_array($envelope) || ($envelope['version'] ?? null) !== 1
                    || ($envelope['algorithm'] ?? '') !== 'A256GCM'
                    || ($envelope['keyWrap'] ?? '') !== 'RSA-OAEP-256'
                    || ($envelope['photoId'] ?? '') !== $photoId
                    || ($envelope['role'] ?? '') !== $role
                    || ($requireKeyId && (!is_string($envelope['keyId'] ?? null)
                        || !hash_equals((string)$record['key_id'], (string)$envelope['keyId'])))
                    || (array_key_exists('keyId', $envelope)
                        && (!is_string($envelope['keyId']) || !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $envelope['keyId'])
                            || !in_array($envelope['keyId'], $allowedKeyIds, true)))
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

    /**
     * Count every key reference, including in-flight reservations. Legacy v1
     * envelopes without keyId are attributed to the original migrated key.
     */
    public function keyReferenceInventory(?string $legacyKeyId = null): array
    {
        if ($legacyKeyId !== null && !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $legacyKeyId)) {
            throw new RuntimeException('Invalid legacy Gallery key identifier.');
        }
        $inventory = [];
        foreach ($this->read() as $record) {
            if (!is_array($record)) continue;
            if (($record['status'] ?? '') === 'pending') {
                $keyId = $record['key_id'] ?? $legacyKeyId;
                if (is_string($keyId) && $keyId !== '') $inventory[$keyId] = ($inventory[$keyId] ?? 0) + 1;
                continue;
            }
            if (($record['status'] ?? '') !== 'active') continue;
            foreach ((array)($record['objects'] ?? []) as $object) {
                $envelope = is_array($object) ? ($object['envelope'] ?? null) : null;
                if (!is_array($envelope)) continue;
                $keyId = $envelope['keyId'] ?? $legacyKeyId;
                if (is_string($keyId) && $keyId !== '') $inventory[$keyId] = ($inventory[$keyId] ?? 0) + 1;
            }
        }
        return $inventory;
    }

    /**
     * Replace only an encrypted DEK envelope. The ciphertext object is never
     * downloaded or rewritten by the server. Hash comparison prevents stale
     * rotation workers from overwriting a newer envelope.
     */
    public function replaceEnvelope(
        string $photoId,
        string $role,
        string $expectedEnvelopeHash,
        array $newEnvelope,
        array $allowedKeyIds
    ): string {
        $this->validatePhotoId($photoId);
        if (!in_array($role, self::ROLES, true)) throw new RuntimeException('Invalid Gallery object role.');
        if (!preg_match('/^[a-f0-9]{64}$/', $expectedEnvelopeHash)) throw new RuntimeException('Invalid Gallery envelope revision.');
        $keyId = $newEnvelope['keyId'] ?? null;
        if (!is_string($keyId) || !preg_match('/^[A-Za-z0-9_-]{8,64}$/', $keyId)
            || !in_array($keyId, $allowedKeyIds, true)
            || ($newEnvelope['version'] ?? null) !== 1
            || ($newEnvelope['algorithm'] ?? '') !== 'A256GCM'
            || ($newEnvelope['keyWrap'] ?? '') !== 'RSA-OAEP-256'
            || ($newEnvelope['photoId'] ?? '') !== $photoId
            || ($newEnvelope['role'] ?? '') !== $role
            || !$this->isBase64Url($newEnvelope['nonce'] ?? null, 16)
            || !$this->isBase64Url($newEnvelope['wrappedDek'] ?? null, 512)) {
            throw new RuntimeException('Replacement Gallery object envelope is invalid.');
        }

        $updatedHash = '';
        $this->mutate(function (array &$records) use ($photoId, $role, $expectedEnvelopeHash, $newEnvelope, &$updatedHash): void {
            $record = $records[$photoId] ?? null;
            $current = is_array($record) ? ($record['objects'][$role]['envelope'] ?? null) : null;
            if (($record['status'] ?? '') !== 'active' || !is_array($current)) {
                throw new RuntimeException('Gallery object envelope is unavailable.');
            }
            $currentHash = self::envelopeHash($current);
            if (!hash_equals($currentHash, $expectedEnvelopeHash)) {
                throw new RuntimeException('Gallery object envelope changed; reload it before retrying.');
            }
            $records[$photoId]['objects'][$role]['envelope'] = $newEnvelope;
            $updatedHash = self::envelopeHash($newEnvelope);
        });
        return $updatedHash;
    }

    public static function envelopeHash(array $envelope): string
    {
        return hash('sha256', json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
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

    public function stalePending(int $minimumAgeSeconds = 600): array
    {
        $threshold = time() - max(600, $minimumAgeSeconds);
        $records = $this->read();
        $pending = [];
        foreach ($records as $photoId => $record) {
            if (is_string($photoId) && is_array($record) && ($record['status'] ?? '') === 'pending'
                && (int)($record['created_at'] ?? 0) <= $threshold) {
                $pending[$photoId] = $record;
            }
        }
        return $pending;
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
        $permissions = @fileperms($this->file);
        if (is_int($permissions) && (($permissions & 0077) !== 0)) {
            throw new RuntimeException('Gallery object index permissions must be owner-only (0600).');
        }
        $raw = @file_get_contents($this->file);
        $records = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($records)) throw new RuntimeException('Gallery object index is invalid.');
        return $records;
    }

    private function mutate(callable $callback): void
    {
        $lockPath = $this->file . '.lock';
        if (is_link($lockPath)) throw new RuntimeException('Gallery object index lock is invalid.');
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
