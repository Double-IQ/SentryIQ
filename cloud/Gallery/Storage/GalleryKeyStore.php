<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use RuntimeException;

final class GalleryKeyStore
{
    public function __construct(private readonly string $file)
    {
        if ($this->file === '' || !str_starts_with($this->file, '/') || is_link($this->file)) {
            throw new RuntimeException('Gallery key storage path is invalid.');
        }
        $directory = realpath(dirname($this->file));
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if ($directory === false || is_link(dirname($this->file)) || (is_string($documentRoot) && $documentRoot !== ''
            && ($directory === $documentRoot || str_starts_with($directory . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
            throw new RuntimeException('Gallery key storage must be outside the public web root.');
        }
    }

    public function isInitialized(): bool
    {
        return $this->read() !== [];
    }

    public function publicKey(): ?array
    {
        $store = $this->read();
        return is_array($store['public_key'] ?? null) ? $store['public_key'] : null;
    }

    public function privateKeyEnvelope(): ?array
    {
        $store = $this->read();
        return is_array($store['private_key_envelope'] ?? null) ? $store['private_key_envelope'] : null;
    }

    public function recoveryEnvelope(): ?array
    {
        $store = $this->read();
        return is_array($store['recovery_envelope'] ?? null) ? $store['recovery_envelope'] : null;
    }

    public function accountSalt(): ?string
    {
        $store = $this->read();
        foreach ((array)($store['credential_envelopes'] ?? []) as $envelope) {
            if (is_array($envelope) && is_string($envelope['salt'] ?? null)) return $envelope['salt'];
        }
        return null;
    }

    public function credentialEnvelope(string $credentialId): ?array
    {
        $this->validateCredentialId($credentialId);
        $store = $this->read();
        $envelope = $store['credential_envelopes'][$credentialId] ?? null;
        return is_array($envelope) ? $envelope : null;
    }

    public function initialize(
        array $publicKey,
        array $privateKeyEnvelope,
        string $credentialId,
        array $credentialEnvelope,
        array $recoveryEnvelope
    ): void {
        $this->validatePublicKey($publicKey);
        $this->validatePrivateKeyEnvelope($privateKeyEnvelope);
        $this->validateCredentialId($credentialId);
        $this->validateCredentialEnvelope($credentialEnvelope, $credentialId);
        $this->validateRecoveryEnvelope($recoveryEnvelope);

        if ($this->read() !== []) {
            throw new RuntimeException('The Gallery encryption identity is already initialized.');
        }

        $this->write([
            'version' => 1,
            'public_key' => $publicKey,
            'private_key_envelope' => $privateKeyEnvelope,
            'credential_envelopes' => [$credentialId => $credentialEnvelope],
            'recovery_envelope' => $recoveryEnvelope,
            'created_at' => time(),
        ]);
    }

    public function addCredentialEnvelope(string $credentialId, array $envelope): void
    {
        $this->validateCredentialId($credentialId);
        $this->validateCredentialEnvelope($envelope, $credentialId);
        $store = $this->read();
        if ($store === []) throw new RuntimeException('The Gallery encryption identity has not been initialized.');
        if (isset($store['credential_envelopes'][$credentialId])) {
            throw new RuntimeException('This passkey already has a Gallery key envelope.');
        }
        $accountSalt = $this->accountSalt();
        if (!is_string($accountSalt) || !hash_equals($accountSalt, (string)$envelope['salt'])) {
            throw new RuntimeException('Gallery passkey envelope uses an unexpected PRF salt.');
        }
        $store['credential_envelopes'][$credentialId] = $envelope;
        $this->write($store);
    }

    public function removeCredentialEnvelope(string $credentialId): void
    {
        $this->validateCredentialId($credentialId);
        $store = $this->read();
        if ($store === [] || !isset($store['credential_envelopes'][$credentialId])) return;
        if (count($store['credential_envelopes']) <= 1) {
            throw new RuntimeException('The last Gallery passkey envelope cannot be removed.');
        }
        unset($store['credential_envelopes'][$credentialId]);
        $this->write($store);
    }

    private function read(): array
    {
        if (!is_file($this->file)) return [];
        if (is_link($this->file) || !is_readable($this->file)) throw new RuntimeException('Gallery key storage is unavailable.');
        $permissions = @fileperms($this->file);
        if (is_int($permissions) && (($permissions & 0077) !== 0)) {
            throw new RuntimeException('Gallery key storage permissions must be owner-only (0600).');
        }
        $raw = @file_get_contents($this->file);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($decoded) || ($decoded['version'] ?? null) !== 1
            || !is_array($decoded['public_key'] ?? null)
            || !is_array($decoded['private_key_envelope'] ?? null)
            || !is_array($decoded['credential_envelopes'] ?? null)
            || !is_array($decoded['recovery_envelope'] ?? null)) {
            throw new RuntimeException('Gallery key storage is invalid.');
        }
        return $decoded;
    }

    private function write(array $store): void
    {
        $directory = dirname($this->file);
        if (!is_dir($directory) || is_link($directory)) throw new RuntimeException('Gallery secure runtime is unavailable.');
        $json = json_encode($store, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $temporary = $this->file . '.tmp-' . bin2hex(random_bytes(12));
        $handle = @fopen($temporary, 'xb');
        if ($handle === false) throw new RuntimeException('Unable to create Gallery key storage.');
        try {
            @chmod($temporary, 0600);
            if (fwrite($handle, $json) !== strlen($json)) throw new RuntimeException('Unable to write Gallery key storage.');
            fflush($handle);
            if (function_exists('fsync')) @fsync($handle);
        } finally {
            fclose($handle);
        }
        if (!@rename($temporary, $this->file)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to activate Gallery key storage.');
        }
        @chmod($this->file, 0600);
    }

    private function validatePublicKey(array $key): void
    {
        if (($key['kty'] ?? '') !== 'RSA' || ($key['alg'] ?? '') !== 'RSA-OAEP-256'
            || !is_string($key['n'] ?? null) || !is_string($key['e'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{512}$/', $key['n'])
            || ($key['e'] !== 'AQAB')) {
            throw new RuntimeException('Invalid Gallery public key.');
        }
    }

    private function validatePrivateKeyEnvelope(array $envelope): void
    {
        if (($envelope['version'] ?? null) !== 1 || ($envelope['algorithm'] ?? '') !== 'A256GCM'
            || !$this->isBase64Url($envelope['iv'] ?? null, 16)
            || !$this->isBase64Url($envelope['ciphertext'] ?? null, 100, 12000)) {
            throw new RuntimeException('Invalid Gallery private-key envelope.');
        }
    }

    private function validateCredentialEnvelope(array $envelope, string $credentialId): void
    {
        if (($envelope['version'] ?? null) !== 1 || ($envelope['algorithm'] ?? '') !== 'A256GCM'
            || ($envelope['kdf'] ?? '') !== 'HKDF-SHA-256'
            || ($envelope['credentialId'] ?? '') !== $credentialId
            || !$this->isBase64Url($envelope['salt'] ?? null, 43)
            || !$this->isBase64Url($envelope['iv'] ?? null, 16)
            || !$this->isBase64Url($envelope['ciphertext'] ?? null, 64)) {
            throw new RuntimeException('Invalid Gallery passkey envelope.');
        }
    }

    private function validateRecoveryEnvelope(array $envelope): void
    {
        if (($envelope['version'] ?? null) !== 1 || ($envelope['algorithm'] ?? '') !== 'A256GCM'
            || ($envelope['kdf'] ?? '') !== 'HKDF-SHA-256'
            || !$this->isBase64Url($envelope['salt'] ?? null, 43)
            || !$this->isBase64Url($envelope['iv'] ?? null, 16)
            || !$this->isBase64Url($envelope['ciphertext'] ?? null, 64)) {
            throw new RuntimeException('Invalid Gallery recovery envelope.');
        }
    }

    private function validateCredentialId(string $credentialId): void
    {
        if (strlen($credentialId) < 16 || strlen($credentialId) > 2048
            || !preg_match('/^[A-Za-z0-9_-]+$/', $credentialId)) {
            throw new RuntimeException('Invalid passkey credential identifier.');
        }
    }

    private function isBase64Url(mixed $value, int $exactLength, ?int $maximumLength = null): bool
    {
        if (!is_string($value) || strlen($value) < $exactLength
            || ($maximumLength !== null && strlen($value) > $maximumLength)
            || ($maximumLength === null && strlen($value) !== $exactLength)) return false;
        return preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1;
    }
}
