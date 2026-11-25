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
function ownerApprovalTranscript(string $owner, string $digest, string $challenge, int $expiry): string
{
    return "SENTRYIQ-OWNER-BOOTSTRAP-APPROVAL-V1\n"
        . pack('N', strlen($owner)) . $owner . hex2bin($digest)
        . pack('N', strlen($challenge)) . $challenge . pack('J', $expiry);
}

$dir = sys_get_temp_dir() . '/sentryiq-owner-approval-' . bin2hex(random_bytes(8));
if (!mkdir($dir, 0700, true)) throw new RuntimeException('Unable to create test storage.');
$challenges = new BootstrapChallengeStore($dir);
$owner = 'owner-test-approval';
$digest = hash('sha256', 'canonical trust bundle');
$now = 1_800_000_000;
$expiry = $now + 300;

$config = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
$private = openssl_pkey_new($config);
if ($private === false) throw new RuntimeException('Unable to generate test P-256 key.');
$details = openssl_pkey_get_details($private);
if (!is_array($details) || !is_string($details['key'] ?? null)) throw new RuntimeException('Unable to export test public key.');
$publicPem = $details['key'];
$resolver = static function (string $requestedOwner) use ($publicPem): array {
    return [
    'owner_id' => $requestedOwner, 'key_id' => 'master-signing-test-1',
    'role' => 'master-signing', 'algorithm' => 'ES256', 'status' => 'active',
    'public_key_pem' => $publicPem,
    ];
};
$verifier = new OwnerApprovalProofVerifier($challenges, $dir, $resolver);
$challenge = $challenges->issue($owner, $digest, $now, 300);
$challengeBytes = base64_decode(strtr($challenge . '=', '-_', '+/'), true);
$transcript = ownerApprovalTranscript($owner, $digest, $challengeBytes, $expiry);
if (!openssl_sign($transcript, $signature, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign approval transcript.');
$receipt = $verifier->verifyAndRecord($challenge, $owner, $digest, ownerApprovalB64($signature), $now);
ownerApprovalAssert($receipt['owner_id'] === $owner, 'Receipt must bind the authenticated owner.');
ownerApprovalAssert($receipt['bundle_sha256'] === $digest, 'Receipt must bind the exact bundle digest.');
ownerApprovalAssert($receipt['key_id'] === 'master-signing-test-1', 'Receipt must identify the registered master key.');
$receiptFile = $dir . '/.owner-approval-receipts.json';
$stored = json_decode((string)file_get_contents($receiptFile), true);
ownerApprovalAssert(count($stored['receipts'] ?? []) === 1, 'A successful proof must create exactly one durable receipt.');
ownerApprovalAssert(((fileperms($receiptFile) ?: 0) & 0777) === 0600, 'Receipt file must be owner-only.');
ownerApprovalReject(fn() => $verifier->verifyAndRecord($challenge, $owner, $digest, ownerApprovalB64($signature), $now), 'A proof challenge must not be replayable.');

$bad = $challenges->issue($owner, $digest, $now, 300);
if (!openssl_sign($transcript . 'tampered', $badSignature, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to create negative signature fixture.');
ownerApprovalReject(fn() => $verifier->verifyAndRecord($bad, $owner, $digest, ownerApprovalB64($badSignature), $now), 'Invalid signatures must fail.');
ownerApprovalReject(fn() => $challenges->consume($bad, $owner, $digest, $now), 'Failed signature submissions must burn their challenge.');

$wrongRoleResolverResult = new OwnerApprovalProofVerifier($challenges, $dir, static function (string $requestedOwner) use ($publicPem, $owner): array {
    return ['owner_id' => $owner, 'key_id' => 'release-key', 'role' => 'release-authorisation', 'algorithm' => 'ES256', 'status' => 'active', 'public_key_pem' => $publicPem];
});
$wrongRoleChallenge = $challenges->issue($owner, $digest, $now, 300);
ownerApprovalReject(fn() => $wrongRoleResolverResult->verifyAndRecord($wrongRoleChallenge, $owner, $digest, ownerApprovalB64($signature), $now), 'Release keys must not approve master bootstrap.');

@unlink($receiptFile);
@unlink($dir . '/.owner-approval-receipts.lock');
@unlink($dir . '/.bootstrap-challenges.json');
@unlink($dir . '/.bootstrap-challenges.lock');
@rmdir($dir);
echo "Owner approval proof verifier tests passed.\n";
