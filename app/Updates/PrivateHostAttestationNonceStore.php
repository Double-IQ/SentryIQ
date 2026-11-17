<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Durable single-use nonce registry for the isolated host attestation service.
 * Stores only keyed hashes of node/nonce pairs, never raw bearer credentials.
 */
final class PrivateHostAttestationNonceStore
{
    private string $statePath;
    private string $lockPath;
    private string $directory;

    public function __construct(string $privateDataDirectory, string $publicWebRoot)
    {
        $private = realpath($privateDataDirectory);
        $web = realpath($publicWebRoot);
        if (!is_string($private) || !is_dir($private) || is_link($privateDataDirectory)
            || !is_string($web) || !is_dir($web) || is_link($publicWebRoot)
            || $private === $web
            || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Attestation nonce storage must be a real directory outside the public webroot.');
        }
        // Validate rather than changing permissions on an operator-supplied
        // directory: this path may contain other private application data.
        if (((fileperms($private) ?: 0) & 0777) !== 0700) {
            throw new RuntimeException('Attestation nonce storage directory must already have exact 0700 permissions.');
        }
        $this->directory = $private;
        $this->statePath = $private . '/private-host-nonces.json';
        $this->lockPath = $private . '/private-host-nonces.lock';
    }

    public function consume(string $nodeId, string $nonce, int $expiresAt): bool
    {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b'], true)
            || !preg_match('/^[a-f0-9]{64}$/', $nonce)) {
            throw new RuntimeException('Attestation nonce registry received an invalid identity or nonce.');
        }
        $now = time();
        if ($expiresAt <= $now || $expiresAt > $now + 300) {
            throw new RuntimeException('Attestation nonce expiry is outside the accepted window.');
        }
        clearstatcache(true, $this->lockPath);
        clearstatcache(true, $this->statePath);
        if (is_link($this->lockPath) || is_link($this->statePath)
            || !is_file($this->lockPath)) {
            throw new RuntimeException('Attestation nonce state must not be a symlink and the lock must be pre-provisioned.');
        }
        $lockStat = @lstat($this->lockPath);
        if (!is_array($lockStat) || (($lockStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($lockStat['mode'] ?? 0) & 0777) !== 0600) {
            throw new RuntimeException('Attestation nonce lock must be a regular file with exact 0600 permissions.');
        }
        // Open an existing operator-provisioned lock without creating it or
        // changing its permissions. Verify the opened inode matches lstat.
        $lock = @fopen($this->lockPath, 'r+b');
        $openedStat = is_resource($lock) ? fstat($lock) : false;
        if ($lock === false || !is_array($openedStat)
            || ($openedStat['dev'] ?? null) !== ($lockStat['dev'] ?? null)
            || ($openedStat['ino'] ?? null) !== ($lockStat['ino'] ?? null)
            || (($openedStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($openedStat['mode'] ?? 0) & 0777) !== 0600) {
            if (is_resource($lock)) fclose($lock);
            throw new RuntimeException('Attestation nonce lock changed during open or has unsafe permissions.');
        }
        if (!flock($lock, LOCK_EX | LOCK_NB)) {
            fclose($lock);
            throw new RuntimeException('Attestation nonce registry is busy; request fails closed.');
        }

        try {
            $state = ['format' => 1, 'nonces' => []];
            if (file_exists($this->statePath)) {
                if (!is_file($this->statePath) || (((fileperms($this->statePath) ?: 0) & 0777) !== 0600)) {
                    throw new RuntimeException('Attestation nonce state has unsafe type or permissions.');
                }
                $bytes = @file_get_contents($this->statePath);
                if (!is_string($bytes) || $bytes === '' || strlen($bytes) > 1_048_576) {
                    throw new RuntimeException('Attestation nonce state is unreadable or exceeds its size limit.');
                }
                try {
                    $decoded = json_decode($bytes, true, 8, JSON_THROW_ON_ERROR);
                } catch (\JsonException $exception) {
                    throw new RuntimeException('Attestation nonce state is invalid JSON.', 0, $exception);
                }
                if (!is_array($decoded) || ($decoded['format'] ?? null) !== 1
                    || !is_array($decoded['nonces'] ?? null)) {
                    throw new RuntimeException('Attestation nonce state schema is invalid.');
                }
                $state = $decoded;
            }

            foreach ($state['nonces'] as $key => $expiry) {
                if (!is_string($key) || !preg_match('/^[a-f0-9]{64}$/', $key) || !is_int($expiry) || $expiry < 1) {
                    throw new RuntimeException('Attestation nonce state contains an invalid record.');
                }
                if ($expiry < $now) unset($state['nonces'][$key]);
            }
            $key = hash('sha256', $nodeId . ':' . $nonce);
            if (isset($state['nonces'][$key])) return false;
            if (count($state['nonces']) >= 10000) {
                throw new RuntimeException('Attestation nonce registry is full; refusing to discard replay history.');
            }
            $state['nonces'][$key] = $expiresAt;
            $encoded = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
            $temporary = $this->statePath . '.tmp-' . bin2hex(random_bytes(16));
            // Exclusive creation prevents a pre-planted symlink or file from
            // redirecting the write, even if the random name is observed.
            $handle = @fopen($temporary, 'x+b');
            if ($handle === false) {
                throw new RuntimeException('Unable to exclusively create attestation nonce state temporary file.');
            }
            try {
                if (!@chmod($temporary, 0600)) {
                    throw new RuntimeException('Unable to restrict attestation nonce state temporary file permissions.');
                }
                $offset = 0;
                $length = strlen($encoded);
                while ($offset < $length) {
                    $written = @fwrite($handle, substr($encoded, $offset));
                    if (!is_int($written) || $written < 1) {
                        throw new RuntimeException('Unable to write complete attestation nonce state.');
                    }
                    $offset += $written;
                }
                if (!@fflush($handle) || !@fsync($handle)) {
                    throw new RuntimeException('Unable to flush attestation nonce state to storage.');
                }
            } catch (\Throwable $exception) {
                fclose($handle);
                @unlink($temporary);
                throw $exception;
            }
            fclose($handle);
            if (!@rename($temporary, $this->statePath)) {
                @unlink($temporary);
                throw new RuntimeException('Unable to atomically persist attestation nonce state.');
            }
            return true;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
