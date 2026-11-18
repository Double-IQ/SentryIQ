<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use RuntimeException;

/**
 * Durable, resumable RSA wrapping-key migration state. Object-level completion
 * is always derived from GalleryObjectStore's authoritative key inventory.
 */
final class GalleryRotationStore
{
    public function __construct(private readonly string $file)
    {
        if ($this->file === '' || !str_starts_with($this->file, '/') || is_link($this->file)) {
            throw new RuntimeException('Gallery rotation journal path is invalid.');
        }
        $directory = realpath(dirname($this->file));
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if ($directory === false || is_link(dirname($this->file))
            || (is_string($documentRoot) && $documentRoot !== ''
                && ($directory === $documentRoot
                    || str_starts_with($directory . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
            throw new RuntimeException('Gallery rotation journal must be outside the public web root.');
        }
    }

    public function current(): ?array
    {
        $data = $this->read();
        return is_array($data['rotation'] ?? null) ? $data['rotation'] : null;
    }

    public function begin(string $fromKeyId, string $toKeyId): array
    {
        $this->validateKeyId($fromKeyId);
        $this->validateKeyId($toKeyId);
        if ($fromKeyId === $toKeyId) throw new RuntimeException('Gallery rotation source and target keys must differ.');
        $this->mutate(function (array &$data) use ($fromKeyId, $toKeyId): void {
            $existing = $data['rotation'] ?? null;
            if (is_array($existing) && ($existing['status'] ?? '') === 'running') {
                if (($existing['from_key_id'] ?? '') === $fromKeyId && ($existing['to_key_id'] ?? '') === $toKeyId) return;
                throw new RuntimeException('Another Gallery key rotation is already in progress.');
            }
            $now = time();
            $data = [
                'version' => 1,
                'rotation' => [
                    'id' => bin2hex(random_bytes(16)),
                    'from_key_id' => $fromKeyId,
                    'to_key_id' => $toKeyId,
                    'status' => 'running',
                    'started_at' => $now,
                    'updated_at' => $now,
                ],
            ];
        });
        return $this->current() ?? throw new RuntimeException('Gallery rotation journal could not be read.');
    }

    public function abort(string $rotationId): array
    {
        return $this->transition($rotationId, 'aborted');
    }

    public function complete(string $rotationId): array
    {
        return $this->transition($rotationId, 'completed');
    }

    private function transition(string $rotationId, string $status): array
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $rotationId)) throw new RuntimeException('Invalid Gallery rotation identifier.');
        $this->mutate(function (array &$data) use ($rotationId, $status): void {
            $rotation = $data['rotation'] ?? null;
            if (!is_array($rotation) || ($rotation['id'] ?? '') !== $rotationId) {
                throw new RuntimeException('Gallery rotation is unavailable.');
            }
            if (($rotation['status'] ?? '') !== 'running') {
                if (($rotation['status'] ?? '') === $status) return;
                throw new RuntimeException('Gallery rotation is no longer active.');
            }
            $rotation['status'] = $status;
            $rotation['updated_at'] = time();
            $data['rotation'] = $rotation;
        });
        return $this->current() ?? throw new RuntimeException('Gallery rotation journal could not be read.');
    }

    private function validateKeyId(string $keyId): void
    {
        if (!preg_match('/^[A-Za-z0-9_-]{8,64}$/', $keyId)) {
            throw new RuntimeException('Invalid Gallery encryption key identifier.');
        }
    }

    private function read(): array
    {
        if (!is_file($this->file)) return ['version' => 1, 'rotation' => null];
        if (is_link($this->file) || !is_readable($this->file)) throw new RuntimeException('Gallery rotation journal is unavailable.');
        $permissions = @fileperms($this->file);
        if (is_int($permissions) && (($permissions & 0077) !== 0)) {
            throw new RuntimeException('Gallery rotation journal permissions must be owner-only (0600).');
        }
        $raw = @file_get_contents($this->file);
        $data = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($data) || ($data['version'] ?? null) !== 1
            || (isset($data['rotation']) && !is_array($data['rotation']))) {
            throw new RuntimeException('Gallery rotation journal is invalid.');
        }
        if (is_array($data['rotation'])) {
            $rotation = $data['rotation'];
            if (!preg_match('/^[a-f0-9]{32}$/', (string)($rotation['id'] ?? ''))
                || !in_array($rotation['status'] ?? '', ['running', 'aborted', 'completed'], true)) {
                throw new RuntimeException('Gallery rotation journal state is invalid.');
            }
            $this->validateKeyId((string)($rotation['from_key_id'] ?? ''));
            $this->validateKeyId((string)($rotation['to_key_id'] ?? ''));
        }
        return $data;
    }

    private function mutate(callable $callback): void
    {
        $lockPath = $this->file . '.lock';
        if (is_link($lockPath)) throw new RuntimeException('Gallery rotation journal lock is invalid.');
        $lock = @fopen($lockPath, 'c');
        if ($lock === false) throw new RuntimeException('Unable to lock Gallery rotation journal.');
        @chmod($lockPath, 0600);
        try {
            if (!flock($lock, LOCK_EX)) throw new RuntimeException('Unable to lock Gallery rotation journal.');
            $data = $this->read();
            $callback($data);
            $this->write($data);
        } finally {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function write(array $data): void
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temporary = $this->file . '.tmp-' . bin2hex(random_bytes(12));
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) throw new RuntimeException('Unable to create Gallery rotation journal.');
        try {
            @chmod($temporary, 0600);
            if (fwrite($handle, $json) !== strlen($json)) throw new RuntimeException('Unable to write Gallery rotation journal.');
            fflush($handle);
            if (function_exists('fsync')) @fsync($handle);
        } finally {
            fclose($handle);
        }
        if (!@rename($temporary, $this->file)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to commit Gallery rotation journal.');
        }
        @chmod($this->file, 0600);
    }
}
