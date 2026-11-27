<?php

declare(strict_types=1);

require_once __DIR__ . '/trust_bundle_validator.test.php';
require_once __DIR__ . '/../app/Security/BootstrapChallengeStore.php';
require_once __DIR__ . '/../app/Security/RegistryAnchorVerifier.php';
require_once __DIR__ . '/../app/Security/OwnerApprovalProofVerifier.php';
require_once __DIR__ . '/../app/Security/OwnerBootstrapApi.php';

use SentryIQ\Security\BootstrapChallengeStore;
use SentryIQ\Security\OwnerBootstrapApi;
use SentryIQ\Security\RegistryAnchorVerifier;

$registryPrivateKey = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]);
if ($registryPrivateKey === false) throw new RuntimeException('Unable to generate registry signer test key.');
$registryPem = openssl_pkey_get_details($registryPrivateKey)['key'];
$anchorObject = [
    'type' => 'SENTRYIQ-REGISTRY-ANCHOR',
    'schema_version' => 1,
    'owner_id' => 'owner-test-001',
    'sequence' => '1',
    'bundle_sha256' => $result['digest'],
    'issued_at' => $now - 10,
    'expires_at' => $now + 3600,
    'previous_bundle_sha256' => null,
    'signer_kid' => 'registry-anchor-1',
];
$anchorPayload = jcsForFixture((object)$anchorObject);
if (!openssl_sign($anchorPayload, $anchorDer, $registryPrivateKey, OPENSSL_ALGO_SHA256)) {
    throw new RuntimeException('Unable to sign registry anchor fixture.');
}
$anchorSignature = rtrim(strtr(base64_encode(derEcdsaToRaw($anchorDer)), '+/', '-_'), '=');
$registrySigners = [[
    'kid' => 'registry-anchor-1',
    'role' => 'registry-anchor',
    'alg' => 'ES256',
    'public_key_pem' => $registryPem,
]];

$privateDirectory = sys_get_temp_dir() . '/sentryiq-owner-bootstrap-api-' . bin2hex(random_bytes(8));
if (!mkdir($privateDirectory, 0700) || !chmod($privateDirectory, 0700)) {
    throw new RuntimeException('Unable to create private API test directory.');
}
try {
    $api = new OwnerBootstrapApi(
        new BootstrapChallengeStore($privateDirectory),
        $privateDirectory,
        $validator,
        new RegistryAnchorVerifier(),
        'owner-test-001',
        $valid,
        $anchorPayload,
        $anchorSignature,
        $registrySigners,
        $trusted,
        null,
        null,
        static fn(array $bundle): bool => ($bundle['sigstore_tuf']['root_version'] ?? null) === 1
    );

    $snapshot = $api->snapshot($now);
    trustBundleAssert(hash_equals($snapshot['bundle_sha256'], hash('sha256', $snapshot['canonical_bundle'])),
        'Bootstrap snapshot must return the exact canonical bundle bytes bound by its digest.');
    $challenge = $api->issueChallenge($now);
    $challengeRaw = base64_decode(strtr($challenge['challenge'] . '=', '-_', '+/'), true);
    trustBundleAssert(is_string($challengeRaw) && strlen($challengeRaw) === 32, 'API challenge must contain 32 random bytes.');

    $fields = static function (string $value): string {
        return pack('N', strlen($value)) . $value;
    };
    $transcript = "SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n"
        . $fields('owner-test-001')
        . hex2bin($snapshot['bundle_sha256'])
        . $fields('release-authorisation')
        . $fields('release-root-1')
        . hex2bin($result['key_fingerprints']['release-root-1'])
        . hex2bin($result['master_keyset_digest'])
        . $fields('bootstrap-release-root')
        . pack('N', strlen($challengeRaw)) . $challengeRaw
        . pack('N2', intdiv($challenge['expires_at'], 4294967296), $challenge['expires_at'] % 4294967296);
    if (!openssl_sign($transcript, $ownerDer, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Unable to sign owner bootstrap proof fixture.');
    }
    $proof = [
        'challenge' => $challenge['challenge'],
        'bundle_sha256' => $snapshot['bundle_sha256'],
        'root_role' => 'release-authorisation',
        'root_key_id' => 'release-root-1',
        'root_fingerprint' => $result['key_fingerprints']['release-root-1'],
        'device_keyset_digest' => $result['master_keyset_digest'],
        'purpose' => 'bootstrap-release-root',
        'signature' => rtrim(strtr(base64_encode(derEcdsaToRaw($ownerDer)), '+/', '-_'), '='),
    ];
    $approved = $api->approve($proof, $now);
    trustBundleAssert(preg_match('/^[a-f0-9]{32}$/D', $approved['receipt_id'] ?? '') === 1,
        'Valid native owner proof must return only a durable receipt identifier.');
    trustBundleReject(
        fn() => $api->approve($proof, $now),
        'Owner bootstrap API must reject replay of a consumed challenge.'
    );
} finally {
    foreach (glob($privateDirectory . '/*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) @unlink($file);
    }
    foreach (glob($privateDirectory . '/.*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) @unlink($file);
    }
    @rmdir($privateDirectory);
}

echo "Owner bootstrap API integration tests passed.\n";
