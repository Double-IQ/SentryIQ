<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryKeyStore.php';

use SentryIQCloud\Gallery\Storage\GalleryKeyStore;

function keyStoreCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function keyStoreMustFail(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$directory = sys_get_temp_dir() . '/sentryiq-gallery-keystore-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) throw new RuntimeException('Unable to create key-store test directory.');
$file = $directory . '/gallery_keys.json';

try {
    $store = new GalleryKeyStore($file);
    $credentialA = str_repeat('A', 32);
    $credentialB = str_repeat('B', 32);
    $publicA = ['kty' => 'RSA', 'alg' => 'RSA-OAEP-256', 'n' => str_repeat('A', 512), 'e' => 'AQAB'];
    $publicB = ['kty' => 'RSA', 'alg' => 'RSA-OAEP-256', 'n' => str_repeat('B', 512), 'e' => 'AQAB'];
    $privateA = ['version' => 1, 'algorithm' => 'A256GCM', 'iv' => str_repeat('C', 16), 'ciphertext' => str_repeat('D', 160)];
    $privateB = ['version' => 1, 'algorithm' => 'A256GCM', 'iv' => str_repeat('E', 16), 'ciphertext' => str_repeat('F', 160)];
    $credentialEnvelopeA = [
        'version' => 1, 'algorithm' => 'A256GCM', 'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('G', 43), 'iv' => str_repeat('H', 16),
        'ciphertext' => str_repeat('I', 64), 'credentialId' => $credentialA,
    ];
    $credentialEnvelopeB = [
        'version' => 1, 'algorithm' => 'A256GCM', 'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('G', 43), 'iv' => str_repeat('J', 16),
        'ciphertext' => str_repeat('K', 64), 'credentialId' => $credentialB,
    ];
    $recovery = [
        'version' => 1, 'algorithm' => 'A256GCM', 'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('L', 43), 'iv' => str_repeat('M', 16), 'ciphertext' => str_repeat('N', 64),
    ];

    $store->initialize($publicA, $privateA, $credentialA, $credentialEnvelopeA, $recovery);
    keyStoreCheck($store->keyring() === null, 'Fresh identity should remain in the legacy v1 format.');
    keyStoreCheck($store->publicKey() === $publicA, 'Legacy public-key accessor should remain unchanged.');
    keyStoreCheck($store->privateKeyEnvelope() === $privateA, 'Legacy private-key accessor should remain unchanged.');

    $ring = $store->migrateToKeyring('gallery-key-0001');
    keyStoreCheck(($ring['version'] ?? null) === 2, 'Migration should persist a v2 keyring.');
    keyStoreCheck($ring['active_key_id'] === 'gallery-key-0001', 'Migration must preserve the existing key as active.');
    keyStoreCheck(count($ring['keys']) === 1, 'Migration must not create or replace key material.');
    keyStoreCheck($store->publicKey() === $publicA, 'Existing callers should read the active v2 public key.');
    keyStoreCheck($store->privateKeyEnvelope() === $privateA, 'Existing callers should read the active v2 private envelope.');
    keyStoreCheck($store->credentialEnvelope($credentialA) === $credentialEnvelopeA, 'Passkey envelopes must survive migration.');
    keyStoreCheck($store->recoveryEnvelope() === $recovery, 'Recovery envelope must survive migration.');

    $ring = $store->addWrappingKey('gallery-key-0002', $publicB, $privateB);
    keyStoreCheck(count($ring['keys']) === 2, 'A second wrapping key should persist.');
    keyStoreCheck($ring['active_key_id'] === 'gallery-key-0001', 'Adding a key must not change the active key.');
    keyStoreCheck($store->publicKey() === $publicA, 'The legacy active key must remain selected for existing uploads.');
    keyStoreMustFail(
        fn() => $store->addWrappingKey('gallery-key-0002', $publicB, $privateB),
        'Duplicate wrapping key identifiers must be rejected.'
    );

    $store->addCredentialEnvelope($credentialB, $credentialEnvelopeB);
    keyStoreCheck($store->credentialEnvelope($credentialB) === $credentialEnvelopeB, 'Passkey enrollment must work with v2 keyring storage.');
    $store->removeCredentialEnvelope($credentialB);
    keyStoreCheck($store->credentialEnvelope($credentialB) === null, 'Passkey envelope removal must work with v2 keyring storage.');
    keyStoreCheck($store->keyring()['active_key_id'] === 'gallery-key-0001', 'Credential changes must not alter key selection.');

    keyStoreMustFail(
        fn() => $store->migrateToKeyring('invalid'),
        'A second migration attempt must not replace the persisted keyring.'
    );
    keyStoreCheck($store->keyring()['active_key_id'] === 'gallery-key-0001', 'Repeated migration must preserve the existing keyring.');

    echo "Gallery key-store v2 persistence tests passed.\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $entry) {
        if (is_file($entry) || is_link($entry)) @unlink($entry);
    }
    @rmdir($directory);
}
