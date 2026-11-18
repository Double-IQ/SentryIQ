<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryKeyring.php';

use SentryIQCloud\Gallery\Storage\GalleryKeyring;

function keyringCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function keyringMustFail(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$credentialId = str_repeat('A', 32);
$legacy = [
    'version' => 1,
    'public_key' => ['kty' => 'RSA', 'alg' => 'RSA-OAEP-256', 'n' => str_repeat('A', 512), 'e' => 'AQAB'],
    'private_key_envelope' => ['version' => 1, 'algorithm' => 'A256GCM', 'iv' => str_repeat('B', 16), 'ciphertext' => str_repeat('C', 160)],
    'credential_envelopes' => [$credentialId => [
        'version' => 1, 'algorithm' => 'A256GCM', 'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('D', 43), 'iv' => str_repeat('E', 16),
        'ciphertext' => str_repeat('F', 64), 'credentialId' => $credentialId,
    ]],
    'recovery_envelope' => [
        'version' => 1, 'algorithm' => 'A256GCM', 'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('G', 43), 'iv' => str_repeat('H', 16), 'ciphertext' => str_repeat('I', 64),
    ],
    'created_at' => 1000,
];
$firstId = 'gallery-key-0001';
$secondId = 'gallery-key-0002';
$keyring = GalleryKeyring::fromLegacy($legacy, $firstId);
keyringCheck($keyring['version'] === 2, 'Legacy identity should convert to the v2 in-memory keyring model.');
keyringCheck($keyring['active_key_id'] === $firstId, 'Legacy identity key should remain active after conversion.');
keyringCheck(count($keyring['keys']) === 1, 'Legacy conversion must preserve one existing key without rotating it.');

$newPublic = ['kty' => 'RSA', 'alg' => 'RSA-OAEP-256', 'n' => str_repeat('J', 512), 'e' => 'AQAB'];
$newPrivate = ['version' => 1, 'algorithm' => 'A256GCM', 'iv' => str_repeat('K', 16), 'ciphertext' => str_repeat('L', 160)];
$keyring = GalleryKeyring::addKey($keyring, $secondId, $newPublic, $newPrivate);
keyringCheck(count($keyring['keys']) === 2, 'Adding a key should preserve the previous key.');
keyringCheck($keyring['active_key_id'] === $firstId, 'Adding a key must not silently switch active uploads.');
keyringMustFail(fn() => GalleryKeyring::addKey($keyring, $secondId, $newPublic, $newPrivate), 'Duplicate key IDs must be rejected.');
$keyring = GalleryKeyring::activate($keyring, $secondId);
keyringCheck($keyring['active_key_id'] === $secondId, 'Activation should explicitly switch the active key.');
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $secondId, ['complete' => true, 'references' => []]),
    'The active key must never be retired, even with an empty complete inventory.'
);
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $firstId, ['complete' => false, 'references' => []]),
    'Retirement must require an explicitly complete authoritative inventory.'
);
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $firstId, ['complete' => true, 'references' => [$firstId => 1]]),
    'A key still referenced by an object must not be retired.'
);
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $firstId, ['complete' => true, 'references' => ['gk_unknown01' => 1]]),
    'An authoritative inventory that references an unknown key must be rejected.'
);
$keyring = GalleryKeyring::retireWithInventory($keyring, $firstId, ['complete' => true, 'references' => [$secondId => 1]]);
keyringCheck(!isset($keyring['keys'][$firstId]), 'An unreferenced inactive key may be retired only with a complete inventory.');
keyringCheck(isset($keyring['keys'][$secondId]), 'Retirement must preserve the active key.');
keyringMustFail(fn() => GalleryKeyring::activate($keyring, $firstId), 'A retired key must not be reactivated.');

$thirdId = 'gallery-key-0003';
$keyring = GalleryKeyring::addKey($keyring, $thirdId, $newPublic, $newPrivate);
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $thirdId, ['complete' => false, 'references' => []]),
    'Retirement must reject an inventory that is not explicitly complete.'
);
keyringMustFail(
    fn() => GalleryKeyring::retireWithInventory($keyring, $thirdId, ['complete' => true, 'references' => [$thirdId => 1]]),
    'Retirement must reject a key with remaining object references.'
);
$keyring = GalleryKeyring::retireWithInventory($keyring, $thirdId, ['complete' => true, 'references' => []]);
keyringCheck(!isset($keyring['keys'][$thirdId]), 'A complete empty inventory may authorize inactive-key retirement.');

echo "Gallery keyring tests passed.\n";
