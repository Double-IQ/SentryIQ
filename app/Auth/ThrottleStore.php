<?php

declare(strict_types=1);

namespace SentryIQ\Auth;

use RuntimeException;
use Throwable;

final class ThrottleStore
{
    public function __construct(private readonly string $path)
    {
        if ($this->path === '' || !str_starts_with($this->path, '/') || is_link($this->path)) {
            throw new RuntimeException('Authentication throttle path is invalid.');
        }
        $directory = dirname($this->path);
        $realDirectory = realpath($directory);
        if ($realDirectory === false || is_link($directory) || rtrim($realDirectory, '/') !== rtrim($directory, '/')) {
            throw new RuntimeException('Authentication throttle directory is not canonical.');
        }
        if (function_exists('sentryiq_path_is_outside_document_root')
            && !\sentryiq_path_is_outside_document_root($directory)) {
            throw new RuntimeException('Authentication throttle data must be outside the public web root.');
        }
    }

    public function blocked(string $scope, string $ip, int $limit, int $window, ?int $now = null): bool
    {
        $this->validatePolicy($scope, $ip, $limit, $window, 1);
        $now ??= time();
        return $this->withLock(LOCK_SH, function () use ($scope, $ip, $limit, $window, $now): bool {
            $data = $this->readUnlocked();
            $entry = $data[$this->key($scope, $ip)] ?? ['count' => 0, 'first' => 0, 'locked_until' => 0];
            $count = $entry['count'] ?? null;
            $first = $entry['first'] ?? null;
            $lockedUntil = $entry['locked_until'] ?? null;
            if (!is_int($count) || !is_int($first) || !is_int($lockedUntil)
                || $count < 0 || $first < 0 || $lockedUntil < 0
                || $first > $now + 5 || $lockedUntil > $now + 86400) {
                throw new RuntimeException('Authentication throttle state is invalid.');
            }
            if ($lockedUntil > $now) return true;
            if ($first === 0 || ($now - $first) > $window) return false;
            return $count >= $limit;
        });
    }

    public function failure(string $scope, string $ip, int $limit, int $window, int $lockout, ?int $now = null): void
    {
        $this->validatePolicy($scope, $ip, $limit, $window, $lockout);
        $now ??= time();
        $this->withLock(LOCK_EX, function () use ($scope, $ip, $limit, $window, $lockout, $now): void {
            $data = $this->readUnlocked();
            $key = $this->key($scope, $ip);
            $entry = $data[$key] ?? ['count' => 0, 'first' => $now, 'locked_until' => 0];
            $count = $entry['count'] ?? null;
            $first = $entry['first'] ?? null;
            $lockedUntil = $entry['locked_until'] ?? null;
            if (!is_int($count) || !is_int($first) || !is_int($lockedUntil)
                || $count < 0 || $first < 0 || $lockedUntil < 0
                || $first > $now + 5 || $lockedUntil > $now + 86400) {
                throw new RuntimeException('Authentication throttle state is invalid.');
            }
            if ($first === 0 || ($now - $first) > $window) {
                $entry = ['count' => 0, 'first' => $now, 'locked_until' => 0];
            }
            $entry['count']++;
            if ($entry['count'] >= $limit) $entry['locked_until'] = $now + $lockout;
            $data[$key] = $entry;
            $this->writeUnlocked($data);
        });
    }

    public function clear(string $scope, string $ip): void
    {
        $this->validatePolicy($scope, $ip, 1, 1, 1);
        $this->withLock(LOCK_EX, function () use ($scope, $ip): void {
            $data = $this->readUnlocked();
            unset($data[$this->key($scope, $ip)]);
            $this->writeUnlocked($data);
        });
    }

    private function validatePolicy(string $scope, string $ip, int $limit, int $window, int $lockout): void
    {
        if ($scope === '' || strlen($scope) > 32 || $limit < 1 || $limit > 1000
            || $window < 1 || $window > 86400 || $lockout < 1 || $lockout > 86400
            || strlen($ip) > 128) {
            throw new RuntimeException('Authentication throttle policy is invalid.');
        }
    }

    private function key(string $scope, string $ip): string
    {
        return hash('sha256', $scope . '|' . $ip);
    }

    private function withLock(int $operation, callable $callback): mixed
    {
        $lockPath = $this->path . '.lock';
        if (is_link($lockPath)) throw new RuntimeException('Authentication throttle lock is a symbolic link.');
        $handle = @fopen($lockPath, 'c');
        if ($handle === false) throw new RuntimeException('Unable to open authentication throttle lock.');
        try {
            $opened = fstat($handle);
            $linked = @lstat($lockPath);
            if (!is_array($opened) || !is_array($linked)
                || (($linked['mode'] & 0170000) !== 0100000)
                || $opened['dev'] !== $linked['dev']
                || $opened['ino'] !== $linked['ino']) {
                throw new RuntimeException('Authentication throttle lock path changed unexpectedly.');
            }
            @chmod($lockPath, 0600);
            if (!flock($handle, $operation)) throw new RuntimeException('Unable to lock authentication throttle state.');
            return $callback();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function readUnlocked(): array
    {
        if (is_link($this->path)) throw new RuntimeException('Authentication throttle state is a symbolic link.');
        if (!file_exists($this->path)) return [];
        if (!is_file($this->path) || !is_readable($this->path)) {
            throw new RuntimeException('Authentication throttle state is unavailable.');
        }
        $handle = @fopen($this->path, 'rb');
        if ($handle === false) throw new RuntimeException('Authentication throttle state is unavailable.');
        try {
            $opened = fstat($handle);
            $linked = @lstat($this->path);
            if (!is_array($opened) || !is_array($linked)
                || (($linked['mode'] & 0170000) !== 0100000)
                || $opened['dev'] !== $linked['dev']
                || $opened['ino'] !== $linked['ino']
                || (int)($opened['size'] ?? 0) > 1024 * 1024
                || (((int)($opened['mode'] ?? 0) & 0077) !== 0)) {
                throw new RuntimeException('Authentication throttle state failed filesystem validation.');
            }
            $raw = stream_get_contents($handle, 1024 * 1024 + 1);
        } finally {
            fclose($handle);
        }
        try {
            $data = is_string($raw) ? json_decode($raw, true, 16, JSON_THROW_ON_ERROR) : null;
        } catch (Throwable) {
            throw new RuntimeException('Authentication throttle state is corrupt.');
        }
        if (!is_array($data)) throw new RuntimeException('Authentication throttle state is corrupt.');
        return $data;
    }

    private function writeUnlocked(array $data): void
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temporary = $this->path . '.tmp-' . bin2hex(random_bytes(12));
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) throw new RuntimeException('Unable to create authentication throttle state.');
        try {
            @chmod($temporary, 0600);
            $length = strlen($json);
            $written = 0;
            while ($written < $length) {
                $count = fwrite($handle, substr($json, $written));
                if (!is_int($count) || $count <= 0) throw new RuntimeException('Unable to write authentication throttle state.');
                $written += $count;
            }
            if (!fflush($handle)) throw new RuntimeException('Unable to flush authentication throttle state.');
            if (function_exists('fsync')) @fsync($handle);
        } catch (Throwable $exception) {
            fclose($handle);
            @unlink($temporary);
            throw $exception;
        }
        fclose($handle);
        if (is_link($this->path) || !@rename($temporary, $this->path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to commit authentication throttle state.');
        }
        @chmod($this->path, 0600);
    }
}
