<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use RuntimeException;

/**
 * Pure validation and transition rules for the next Gallery encryption-key
 * format. This deliberately does not change the live v1 key store or objects.
 */
final class GalleryKeyring
{
    public const VERSION = 2;

    public static function fromLegacy(array $legacy, string $keyId): array
    {
        self::validateKeyId($keyId);
        if (($legacy['version'] ?? null) !== 1
            || !is_array($legacy['public_key'] ?? null)
            || !is_array($legacy['private_key_envelope'] ?? null)
            || !is_array($legacy['credential_envelopes'] ?? null)
            || !is_array($legacy['recovery_envelope'] ?? null)) {
            throw new RuntimeException('Legacy Gallery identity cannot be converted to a keyring.');
        }

        $keyring = [
            'version' => self::VERSION,
            'active_key_id' => $keyId,
            'legacy_key_id' => $keyId,
            'keys' => [
                $keyId => [
                    'public_key' => $legacy['public_key'],
                    'private_key_envelope' => $legacy['private_key_envelope'],
                    'created_at' => (int)($legacy['created_at'] ?? time()),
                ],
            ],
            'credential_envelopes' => $legacy['credential_envelopes'],
            'recovery_envelope' => $legacy['recovery_envelope'],
            'created_at' => (int)($legacy['created_at'] ?? time()),
        ];
        self::validate($keyring);
        return $keyring;
    }

    public static function validate(array $keyring): void
    {
        if (($keyring['version'] ?? null) !== self::VERSION
            || !is_string($keyring['active_key_id'] ?? null)
            || !is_array($keyring['keys'] ?? null)
            || $keyring['keys'] === []
            || !is_array($keyring['credential_envelopes'] ?? null)
            || $keyring['credential_envelopes'] === []
            || !is_array($keyring['recovery_envelope'] ?? null)) {
            throw new RuntimeException('Gallery keyring structure is invalid.');
        }

        $active = $keyring['active_key_id'];
        self::validateKeyId($active);
        $legacy = $keyring['legacy_key_id'] ?? null;
        if ($legacy !== null) {
            if (!is_string($legacy)) throw new RuntimeException('Gallery legacy key identifier is invalid.');
            self::validateKeyId($legacy);
            if (!isset($keyring['keys'][$legacy])) throw new RuntimeException('Gallery legacy encryption key is missing.');
        }
        if (!isset($keyring['keys'][$active])) {
            throw new RuntimeException('Gallery active encryption key is missing.');
        }

        foreach ($keyring['keys'] as $keyId => $entry) {
            if (!is_string($keyId)) throw new RuntimeException('Gallery key identifier is invalid.');
            self::validateKeyId($keyId);
            if (!is_array($entry) || !is_array($entry['public_key'] ?? null)
                || !is_array($entry['private_key_envelope'] ?? null)) {
                throw new RuntimeException('Gallery keyring entry is invalid.');
            }
            self::validatePublicKey($entry['public_key']);
            self::validatePrivateEnvelope($entry['private_key_envelope']);
            if (isset($entry['created_at']) && (!is_int($entry['created_at']) || $entry['created_at'] < 0)) {
                throw new RuntimeException('Gallery key creation timestamp is invalid.');
            }
        }

        foreach ($keyring['credential_envelopes'] as $credentialId => $envelope) {
            if (!is_string($credentialId) || !preg_match('/^[A-Za-z0-9_-]{16,2048}$/', $credentialId)
                || !is_array($envelope) || ($envelope['credentialId'] ?? null) !== $credentialId
                || ($envelope['version'] ?? null) !== 1 || ($envelope['algorithm'] ?? '') !== 'A256GCM'
                || ($envelope['kdf'] ?? '') !== 'HKDF-SHA-256'
                || !self::encoded($envelope['salt'] ?? null, 43)
                || !self::encoded($envelope['iv'] ?? null, 16)
                || !self::encoded($envelope['ciphertext'] ?? null, 64)) {
                throw new RuntimeException('Gallery passkey envelope is invalid.');
            }
        }

        $recovery = $keyring['recovery_envelope'];
        if (($recovery['version'] ?? null) !== 1 || ($recovery['algorithm'] ?? '') !== 'A256GCM'
            || ($recovery['kdf'] ?? '') !== 'HKDF-SHA-256'
            || !self::encoded($recovery['salt'] ?? null, 43)
            || !self::encoded($recovery['iv'] ?? null, 16)
            || !self::encoded($recovery['ciphertext'] ?? null, 64)) {
            throw new RuntimeException('Gallery recovery envelope is invalid.');
        }
    }

    public static function addKey(array $keyring, string $keyId, array $publicKey, array $privateEnvelope): array
    {
        self::validate($keyring);
        self::validateKeyId($keyId);
        if (isset($keyring['keys'][$keyId])) throw new RuntimeException('Gallery key identifier already exists.');
        self::validatePublicKey($publicKey);
        self::validatePrivateEnvelope($privateEnvelope);
        $keyring['keys'][$keyId] = [
            'public_key' => $publicKey,
            'private_key_envelope' => $privateEnvelope,
            'created_at' => time(),
        ];
        self::validate($keyring);
        return $keyring;
    }

    public static function activate(array $keyring, string $keyId): array
    {
        self::validate($keyring);
        self::validateKeyId($keyId);
        if (!isset($keyring['keys'][$keyId])) throw new RuntimeException('Cannot activate an unknown Gallery key.');
        $keyring['active_key_id'] = $keyId;
        self::validate($keyring);
        return $keyring;
    }

    /**
     * Retire a key only with an explicit complete inventory produced while
     * holding the shared Gallery rotation lock. Empty inventories are valid
     * only when completeness is explicitly asserted by the trusted caller.
     */
    public static function retireWithInventory(array $keyring, string $keyId, array $inventory): array
    {
        self::validate($keyring);
        self::validateKeyId($keyId);
        if (!isset($keyring['keys'][$keyId])) throw new RuntimeException('Gallery key is already absent.');
        if ($keyring['active_key_id'] === $keyId) throw new RuntimeException('The active Gallery key cannot be retired.');
        if (($inventory['complete'] ?? false) !== true || !is_array($inventory['references'] ?? null)) {
            throw new RuntimeException('A complete authoritative Gallery object inventory is required before key retirement.');
        }
        foreach ($inventory['references'] as $referencedKeyId => $count) {
            if (!is_string($referencedKeyId) || !isset($keyring['keys'][$referencedKeyId])
                || !is_int($count) || $count < 1) {
                throw new RuntimeException('Gallery key reference inventory is invalid.');
            }
        }
        if (($inventory['references'][$keyId] ?? 0) !== 0) {
            throw new RuntimeException('Gallery key is still referenced by encrypted objects or pending uploads.');
        }
        if (count($keyring['keys']) <= 1) throw new RuntimeException('The final Gallery encryption key cannot be retired.');
        unset($keyring['keys'][$keyId]);
        if (($keyring['legacy_key_id'] ?? null) === $keyId) unset($keyring['legacy_key_id']);
        self::validate($keyring);
        return $keyring;
    }

    private static function validateKeyId(string $keyId): void
    {
        if (!preg_match('/^[A-Za-z0-9_-]{8,64}$/', $keyId)) {
            throw new RuntimeException('Invalid Gallery encryption key identifier.');
        }
    }

    private static function validatePublicKey(array $key): void
    {
        if (($key['kty'] ?? '') !== 'RSA' || ($key['alg'] ?? '') !== 'RSA-OAEP-256'
            || !is_string($key['n'] ?? null) || !is_string($key['e'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{512}$/', $key['n']) || $key['e'] !== 'AQAB') {
            throw new RuntimeException('Invalid Gallery public key.');
        }
    }

    private static function validatePrivateEnvelope(array $envelope): void
    {
        if (($envelope['version'] ?? null) !== 1 || ($envelope['algorithm'] ?? '') !== 'A256GCM'
            || !self::encoded($envelope['iv'] ?? null, 16)
            || !self::encoded($envelope['ciphertext'] ?? null, 100, 12000)) {
            throw new RuntimeException('Invalid Gallery private-key envelope.');
        }
    }

    private static function encoded(mixed $value, int $minimum, ?int $maximum = null): bool
    {
        return is_string($value) && strlen($value) >= $minimum
            && ($maximum === null || strlen($value) <= $maximum)
            && preg_match('/^[A-Za-z0-9_-]+$/', $value) === 1;
    }
}
