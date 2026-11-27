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
function ownerApprovalDerToRawLowS(string $der): string
{
    $offset = 0;
    if (ord($der[$offset++]) !== 0x30) throw new RuntimeException('Invalid ECDSA sequence.');
    $sequenceLength = ord($der[$offset++]);
    if ($sequenceLength !== strlen($der) - $offset || ord($der[$offset++]) !== 0x02) {
        throw new RuntimeException('Invalid ECDSA sequence length or R integer.');
    }
    $rLength = ord($der[$offset++]);
    $r = str_pad(ltrim(substr($der, $offset, $rLength), "\0"), 32, "\0", STR_PAD_LEFT);
    $offset += $rLength;
    if (ord($der[$offset++]) !== 0x02) throw new RuntimeException('Invalid ECDSA S integer.');
    $sLength = ord($der[$offset++]);
    $s = str_pad(ltrim(substr($der, $offset, $sLength), "\0"), 32, "\0", STR_PAD_LEFT);
    $half = hex2bin('7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8');
    if (strcmp($s, $half) > 0) {
        $order = array_values(unpack('C*', hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')));
        $bytes = array_values(unpack('C*', $s));
        $borrow = 0;
        for ($i = 31; $i >= 0; $i--) {
            $value = $order[$i] - $bytes[$i] - $borrow;
            $borrow = $value < 0 ? 1 : 0;
            $bytes[$i] = $value < 0 ? $value + 256 : $value;
        }
        $s = pack('C*', ...$bytes);
    }
    return $r . $s;
}

function ownerApprovalHighS(string $raw): string
{
    $order = array_values(unpack('C*', hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')));
    $bytes = array_values(unpack('C*', substr($raw, 32, 32)));
    $borrow = 0;
    for ($i = 31; $i >= 0; $i--) {
        $value = $order[$i] - $bytes[$i] - $borrow;
        $borrow = $value < 0 ? 1 : 0;
        $bytes[$i] = $value < 0 ? $value + 256 : $value;
    }
    return substr($raw, 0, 32) . pack('C*', ...$bytes);
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

// Shared V2 transcript golden vector also asserted by the Swift and Kotlin ceremony tests.
$goldenTranscriptHex = '53454e54525949512d4f574e45522d424f4f5453545241502d415050524f56414c2d56320a000000096f776e65722d31323387ffacd652854aba4246164ce5154c94d6d06b145eade6b33e93b1e53f74328d0000001572656c656173652d617574686f7269736174696f6e0000000e72656c656173652d726f6f742d31739cc47de826dd91653d08e80ac816b26e3b0b38cf782e506dadd4828a3050bc63053de68b07ab2d29fa13eee284d9ae272d1d228afc19c48cdb8486ab61e7d800000016626f6f7473747261702d72656c656173652d726f6f74000000205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a000000006553f1c8';
$goldenTranscript = ownerApprovalTranscript(
    'owner-123',
    hash('sha256', 'canonical-trust-bundle'),
    'release-authorisation',
    'release-root-1',
    hash('sha256', 'independent-release-root'),
    hash('sha256', 'device-keyset-public-identifiers'),
    'bootstrap-release-root',
    str_repeat("\x5a", 32),
    1_700_000_200
);
ownerApprovalAssert(bin2hex($goldenTranscript) === $goldenTranscriptHex, 'PHP V2 transcript must match the shared native golden vector.');

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
ownerApprovalReject(fn() => $challenges->issue('owner-é', $digest, $now), 'Challenge issuance must reject non-ASCII owner identifiers.');

$challenge = $challenges->issue($owner, $digest, $now, 300);
$challengeBytes = base64_decode(strtr($challenge . '=', '-_', '+/'), true);
$transcript = ownerApprovalTranscript(
    $owner, $digest, $rootRole, $rootKeyId, $rootFingerprint, $keysetDigest,
    $purpose, $challengeBytes, $expiry
);
if (!openssl_sign($transcript, $signatureDer, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign V2 approval transcript.');
$signature = ownerApprovalDerToRawLowS($signatureDer);
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
ownerApprovalAssert(($stored['receipts'][0]['challenge'] ?? null) === $challenge, 'Receipt must retain the exact consumed challenge.');
ownerApprovalAssert(($stored['receipts'][0]['signature'] ?? null) === ownerApprovalB64($signature), 'Receipt must retain the verifiable owner signature.');
ownerApprovalAssert(($stored['receipts'][0]['signature_encoding'] ?? null) === 'ecdsa-jose-raw-low-s-base64url', 'Receipt must identify canonical native JOSE signature encoding.');
ownerApprovalAssert(((fileperms($receiptFile) ?: 0) & 0777) === 0600, 'Receipt file must be owner-only.');
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $challenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($signature), $now
), 'A proof challenge must not be replayable.');

$highSChallenge = $challenges->issue($owner, $digest, $now, 300);
$highSChallengeBytes = base64_decode(strtr($highSChallenge . '=', '-_', '+/'), true);
$highSTranscript = ownerApprovalTranscript(
    $owner, $digest, $rootRole, $rootKeyId, $rootFingerprint, $keysetDigest,
    $purpose, $highSChallengeBytes, $expiry
);
if (!openssl_sign($highSTranscript, $highSSignatureDer, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign high-S fixture.');
$highSSignature = ownerApprovalHighS(ownerApprovalDerToRawLowS($highSSignatureDer));
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $highSChallenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($highSSignature), $now
), 'High-S JOSE signatures must be rejected as non-canonical.');
ownerApprovalReject(fn() => $challenges->consume($highSChallenge, $owner, $digest, $now), 'A high-S signature attempt must burn its challenge.');

$bad = $challenges->issue($owner, $digest, $now, 300);
if (!openssl_sign($transcript . 'tampered', $badSignatureDer, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to create negative signature fixture.');
$badSignature = ownerApprovalDerToRawLowS($badSignatureDer);
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

$ledger = json_decode((string)file_get_contents($receiptFile), true);
$ledger['receipts'][0]['approved_at'] = 'tampered';
file_put_contents($receiptFile, json_encode($ledger));
$ledgerChallenge = $challenges->issue($owner, $digest, $now, 300);
$ledgerChallengeBytes = base64_decode(strtr($ledgerChallenge . '=', '-_', '+/'), true);
$ledgerTranscript = ownerApprovalTranscript(
    $owner, $digest, $rootRole, $rootKeyId, $rootFingerprint, $keysetDigest,
    $purpose, $ledgerChallengeBytes, $expiry
);
if (!openssl_sign($ledgerTranscript, $ledgerSignatureDer, $private, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign receipt-corruption fixture.');
$ledgerSignature = ownerApprovalDerToRawLowS($ledgerSignatureDer);
ownerApprovalReject(fn() => $verifier->verifyAndRecord(
    $ledgerChallenge, $owner, $canonicalBundle, $digest, $rootRole, $rootKeyId,
    $rootFingerprint, $keysetDigest, $purpose, ownerApprovalB64($ledgerSignature), $now
), 'A corrupted receipt ledger must fail closed.');
ownerApprovalReject(fn() => $challenges->consume($ledgerChallenge, $owner, $digest, $now), 'Receipt-ledger failure must not permit challenge replay.');

@unlink($receiptFile);
@unlink($dir . '/.owner-approval-receipts.lock');
@unlink($dir . '/.bootstrap-challenges.json');
@unlink($dir . '/.bootstrap-challenges.lock');
@rmdir($dir);
echo "Owner approval V2 proof verifier tests passed.\n";
