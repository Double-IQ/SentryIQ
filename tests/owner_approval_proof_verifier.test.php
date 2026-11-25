<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/BootstrapChallengeStore.php';
require_once __DIR__ . '/../app/Security/OwnerApprovalProofVerifier.php';

use SentryIQ\Security\BootstrapChallengeStore;
use SentryIQ\Security\OwnerApprovalProofVerifier;

function ownerApprovalAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}
function ownerApprovalReject(callable $fn, string $message): void
{
    try { $fn(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}
function ownerApprovalB64(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}
function ownerApprovalField(string $value): string
{
    return pack('N', strlen($value)) . $value;
}
function ownerApprovalTranscript(
    string $owner,
    string $bundleDigest,
    string $rootRole,
    string $rootKeyId,
    string $rootFingerprint,
    string $deviceKeysetDigest,
    string $purpose,
    string $challenge,
    int $expiry
): string {
    return "SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V2\n"
        . ownerApprovalField($owner)
        . hex2bin($bundleDigest)
        . ownerApprovalField($rootRole)
        . ownerApprovalField($rootKeyId)
        . hex2bin($rootFingerprint)
        . hex2bin($deviceKeysetDigest)
        . ownerApprovalField($purpose)
        . pack('N', strlen($challenge))
        . $challenge
        . pack('J', $expiry);
}

$dir = sys_get_temp_dir() . '/sentryiq-owner-approval-' . bin2hex(random_bytes(8));
if (!mkdir($dir, 0700, true)) throw new RuntimeException('Unable to create test storage.');
$challenges = new BootstrapChallengeStore($dir);
$owner = 'owner-test-approval';
$canonicalBundle = '{"type":"SENTRYIQ-TRUST-BUNDLE","schema_version":1}';
$digest = hash('sha256', $canonicalBundle);
$rootRole = 'release-authorisation';
$rootKeyId = 'release-root-1';
$rootFingerprint = hash('sha256', 'independent-release-root');
$keysetDigest = hash('sha256', 'device-keyset-public-identifiers');
$purpose = 'bootstrap-release-root';
$now = 1_800_000_000;
$expiry = $now + 300;

$config = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
$private = openssl_pkey_new($config);
if ($private === false) throw new RuntimeException('Unable to generate test P-256 key.');
$details = openssl_pkey_get_details($private);
if (!is_array($details) || !is_string($details['key'] ?? null)) throw new RuntimeException('Unable to export test public key.');
$publicPem = $details['key'];

$resolver = static function (string $requestedOwner) use ($publicPem, $keysetDigest): array {
    return [
        'owner_id' => $requestedOwner,
        'key_id' => 'master-signing-test-1',
        'role' => 'master-signing',
        'algorithm' => 'ES256',
        'status' => 'active',
        'device_keyset_digest' => $keysetDigest,
        'public_key_pem' => $publicPem,
    ];
};
$contextValidator = static function (
    string $bundle,
    string $role,
    string $keyId,
    string $rootFp,
    string $deviceDigest,
    string $operationPurpose
) use ($canonicalBundle, $rootRole, $rootKeyId, $rootFingerprint, $keysetDigest, $purpose): bool {
    return hash_equals($canonicalBundle, $bundle)
        && $role === $rootRole
        && $keyId === $rootKeyId
        && hash_equals($rootFingerprint, $rootFp)
        && hash_equals($keysetDigest, $deviceDigest)
        && $operationPurpose === $purpose;
};
$verifier = new OwnerApprovalProofVerifier($challenges, $dir, $resolver, $contextValidator);

$challenge = $challenges->issue($owner, $digest, $now, 300);
$challengeBytes = base64_decode(strtr($challenge . '=', '-_', '+/'), true);
$transcript = ownerApprovalTranscript(
    $owner, $digest, $rootRole, $rootKeyId, $rootFingerprint, $keysetDigest,
    $purpose, $challengeBytes, $expiry
);
if (!openssl_sign($transcript, $signature, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign V2 approval transcript.');
$receipt = $verifier->verifyAndRecord(
    $challenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
);
ownerApprovalAssert($receipt['owner_id'] === $owner, 'Receipt must bind the authenticated owner.');
ownerApprovalAssert($receipt['bundle_sha256'] === $digest, 'Receipt must bind the exact bundle digest.');
ownerApprovalAssert($receipt['master_key_id'] === 'master-signing-test-1', 'Receipt must identify the active master signing key.');
ownerApprovalAssert($receipt['root_role'] === $rootRole && $receipt['root_key_id'] === $rootKeyId, 'Receipt must bind root role and key ID.');
ownerApprovalAssert($receipt['root_fingerprint'] === $rootFingerprint, 'Receipt must bind the root SPKI fingerprint.');
ownerApprovalAssert($receipt['device_keyset_digest'] === $keysetDigest, 'Receipt must bind the active master device keyset.');
ownerApprovalAssert($receipt['purpose'] === $purpose, 'Receipt must bind the operation purpose.');

$receiptFile = $dir . '/.owner-approval-receipts.json';
$stored = json_decode((string)file_get_contents($receiptFile), true);
ownerApprovalAssert(count($stored['receipts'] ?? []) === 1, 'A successful proof must create exactly one durable receipt.');
ownerApprovalAssert(((fileperms($receiptFile) ?: 0) & 0777) === 0600, 'Receipt file must be owner-only.');
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $challenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
), 'A proof challenge must not be replayable.');

$bad = $challenges->issue($owner, $digest, $now, 300);
if (!openssl_sign($transcript . 'tampered', $badSignature, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to create negative signature fixture.');
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $bad, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($badSignature), $now
), 'Invalid signatures must fail.');
ownerApprovalReject(fn() => $challenges->consume($bad, $owner, $digest, $now), 'Failed signature submissions must burn their challenge.');

$malformed = $challenges->issue($owner, $digest, $now, 300);
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $malformed, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, 'not-a-signature', $now
), 'Malformed signatures must fail.');
ownerApprovalReject(fn() => $challenges->consume($malformed, $owner, $digest, $now), 'Malformed signature submissions must burn their challenge.');

$wrongContextVerifier = new OwnerApprovalProofVerifier(
    $challenges,
    $dir,
    $resolver,
    static fn(string $bundle, string $role, string $keyId, string $rootFp, string $deviceDigest, string $operationPurpose): bool => false
);
$wrongContextChallenge = $challenges->issue($owner, $digest, $now, 300);
ownerApprovalReject(fn() => $wrongContextVerifier->verifyAndRecord(
    $wrongContextChallenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
), 'An unvalidated root/purpose context must be rejected.');

$wrongKeyRoleResolver = static function (string $requestedOwner) use ($publicPem, $keysetDigest): array {
    return [
        'owner_id' => $requestedOwner, 'key_id' => 'release-key',
        'role' => 'release-authorisation', 'algorithm' => 'ES256', 'status' => 'active',
        'device_keyset_digest' => $keysetDigest, 'public_key_pem' => $publicPem,
    ];
};
$wrongKeyRoleVerifier = new OwnerApprovalProofVerifier($challenges, $dir, $wrongKeyRoleResolver, $contextValidator);
$wrongKeyRoleChallenge = $challenges->issue($owner, $digest, $now, 300);
ownerApprovalReject(fn() => $wrongKeyRoleVerifier->verifyAndRecord(
    $wrongKeyRoleChallenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
), 'A release key must not approve master bootstrap.');

$keysetMismatchResolver = static function (string $requestedOwner) use ($publicPem): array {
    return [
        'owner_id' => $requestedOwner, 'key_id' => 'master-signing-test-1',
        'role' => 'master-signing', 'algorithm' => 'ES256', 'status' => 'active',
        'device_keyset_digest' => str_repeat('0', 64), 'public_key_pem' => $publicPem,
    ];
};
$keysetMismatchVerifier = new OwnerApprovalProofVerifier($challenges, $dir, $keysetMismatchResolver, $contextValidator);
$keysetMismatchChallenge = $challenges->issue($owner, $digest, $now, 300);
ownerApprovalReject(fn() => $keysetMismatchVerifier->verifyAndRecord(
    $keysetMismatchChallenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
), 'A master keyset digest mismatch must be rejected.');

@unlink($receiptFile);
@unlink($dir . '/.owner-approval-receipts.lock');
@unlink($dir . '/.bootstrap-challenges.json');
@unlink($dir . '/.bootstrap-challenges.lock');
@rmdir($dir);
echo "Owner approval V2 proof verifier tests passed.\n";
