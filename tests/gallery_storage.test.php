<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Gallery/Storage/BackblazeB2Signer.php';
require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryKeyStore.php';
require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryObjectStore.php';

use SentryIQCloud\Gallery\Storage\BackblazeB2Signer;
use SentryIQCloud\Gallery\Storage\GalleryKeyStore;
use SentryIQCloud\Gallery\Storage\GalleryObjectStore;

function check(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function expectFailure(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$signer = new BackblazeB2Signer([
    'bucket' => 'sentryiq-test-bucket',
    'region' => 'us-west-004',
    'key_id' => 'test-key-id',
    'application_key' => 'test-application-secret',
]);
$objectKey = BackblazeB2Signer::newObjectKey('original');
$now = new DateTimeImmutable('2026-11-07T00:00:00+00:00');
$putUrl = $signer->presign('PUT', $objectKey, 300, $now);
$getUrl = $signer->presign('GET', $objectKey, 300, $now);
$putParts = parse_url($putUrl);
parse_str((string)($putParts['query'] ?? ''), $putQuery);
check(($putParts['scheme'] ?? '') === 'https', 'B2 URL must use HTTPS.');
check(($putParts['host'] ?? '') === 's3.us-west-004.backblazeb2.com', 'B2 URL must use the configured regional endpoint.');
check(str_contains((string)($putParts['path'] ?? ''), '/sentryiq-test-bucket/gallery/v1/'), 'B2 URL must be scoped to the configured bucket and opaque object key.');
check(($putQuery['X-Amz-Expires'] ?? '') === '300', 'B2 URL must have the requested short expiry.');
check(($putQuery['X-Amz-SignedHeaders'] ?? '') === 'content-type;host', 'B2 PUT URL must bind the ciphertext content type.');
check(preg_match('/^[a-f0-9]{64}$/', (string)($putQuery['X-Amz-Signature'] ?? '')) === 1, 'B2 URL must contain a SigV4 signature.');
check(!str_contains($putUrl, 'test-application-secret'), 'B2 URL must not disclose the application key.');
check($putUrl !== $getUrl, 'PUT and GET authorizations must be method-scoped.');
expectFailure(fn() => $signer->presign('PUT', '../private/photo.webp'), 'Signer must reject arbitrary object paths.');
expectFailure(fn() => $signer->presign('PUT', $objectKey, 601, $now), 'Signer must reject long-lived URLs.');

$directory = sys_get_temp_dir() . '/sentryiq-gallery-test-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) throw new RuntimeException('Unable to create temporary test directory.');
try {
    $store = new GalleryKeyStore($directory . '/gallery_keys.json');
    $credentialOne = str_repeat('A', 32);
    $credentialTwo = str_repeat('B', 32);
    $publicKey = ['kty' => 'RSA', 'alg' => 'RSA-OAEP-256', 'n' => str_repeat('A', 512), 'e' => 'AQAB'];
    $privateEnvelope = ['version' => 1, 'algorithm' => 'A256GCM', 'iv' => str_repeat('A', 16), 'ciphertext' => str_repeat('B', 160)];
    $makeCredentialEnvelope = static fn(string $id): array => [
        'version' => 1,
        'algorithm' => 'A256GCM',
        'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('C', 43),
        'iv' => str_repeat('D', 16),
        'ciphertext' => str_repeat('E', 64),
        'credentialId' => $id,
    ];
    $recoveryEnvelope = [
        'version' => 1,
        'algorithm' => 'A256GCM',
        'kdf' => 'HKDF-SHA-256',
        'salt' => str_repeat('F', 43),
        'iv' => str_repeat('G', 16),
        'ciphertext' => str_repeat('H', 64),
    ];

    check(!$store->isInitialized(), 'Gallery key store should start uninitialized.');
    $store->initialize($publicKey, $privateEnvelope, $credentialOne, $makeCredentialEnvelope($credentialOne), $recoveryEnvelope);
    check($store->isInitialized(), 'Gallery key store should initialize.');
    check($store->credentialEnvelope($credentialOne) !== null, 'Initial passkey envelope should be stored.');
    check($store->accountSalt() === str_repeat('C', 43), 'Gallery account PRF salt should be stored with its first passkey envelope.');
    $store->addCredentialEnvelope($credentialTwo, $makeCredentialEnvelope($credentialTwo));
    $wrongSaltEnvelope = $makeCredentialEnvelope(str_repeat('Z', 32));
    $wrongSaltEnvelope['salt'] = str_repeat('L', 43);
    expectFailure(
        fn() => $store->addCredentialEnvelope(str_repeat('Z', 32), $wrongSaltEnvelope),
        'Additional passkeys must use the same dedicated Gallery PRF input salt.'
    );
    check($store->credentialEnvelope($credentialTwo) !== null, 'Additional passkey envelope should be stored.');
    $store->removeCredentialEnvelope($credentialOne);
    check($store->credentialEnvelope($credentialOne) === null, 'Removed passkey envelope should no longer be available.');
    check($store->accountSalt() === str_repeat('C', 43), 'Removing one passkey must preserve the Gallery PRF salt for remaining credentials.');
    expectFailure(
        fn() => $store->initialize($publicKey, $privateEnvelope, $credentialOne, $makeCredentialEnvelope($credentialOne), $recoveryEnvelope),
        'Gallery identity must not be initialized twice.'
    );
    $permissions = fileperms($directory . '/gallery_keys.json');
    check(is_int($permissions) && (($permissions & 0077) === 0), 'Gallery key file must not be accessible to group or other users.');

    $objectStore = new GalleryObjectStore($directory . '/gallery_objects.json');
    $photoId = bin2hex(random_bytes(16));
    $objectKeys = [];
    $envelopes = [];
    $sizes = [];
    foreach (['original', 'thumbnail', 'preview', 'metadata'] as $role) {
        $objectKeys[$role] = BackblazeB2Signer::newObjectKey($role);
        $envelopes[$role] = [
            'version' => 1,
            'algorithm' => 'A256GCM',
            'keyWrap' => 'RSA-OAEP-256',
            'nonce' => str_repeat('J', 16),
            'wrappedDek' => str_repeat('K', 512),
            'photoId' => $photoId,
            'role' => $role,
        ];
        $sizes[$role] = 100;
    }
    $objectStore->createPending($photoId, $objectKeys);
    check(($objectStore->find($photoId)['status'] ?? '') === 'pending', 'New object reservation must be pending.');
    $objectStore->commit($photoId, $envelopes, $sizes);
    check(($objectStore->find($photoId)['status'] ?? '') === 'active', 'Committed ciphertext objects must be active.');
    check(count($objectStore->all()) === 1, 'Active Gallery objects must be listed.');
    check(isset($objectStore->find($photoId)['objects']['metadata']['envelope']), 'Encrypted metadata envelope must be stored.');
    check($objectStore->remove($photoId) !== null, 'Gallery object record should be removable.');
    check($objectStore->all() === [], 'Removed Gallery object must no longer be listed.');
} finally {
    @unlink($directory . '/gallery_keys.json');
    @unlink($directory . '/gallery_keys.json.lock');
    @unlink($directory . '/gallery_objects.json');
    @unlink($directory . '/gallery_objects.json.lock');
    @rmdir($directory);
}

echo "Gallery storage tests passed.\n";
