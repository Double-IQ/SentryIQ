<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/RegistryAnchorVerifier.php';

use SentryIQ\Security\RegistryAnchorVerifier;

function anchorAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function anchorReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

function anchorCanonical(array $payload): string
{
    ksort($payload, SORT_STRING);
    $parts = [];
    foreach ($payload as $key => $value) {
        $parts[] = json_encode($key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR)
            . ':' . json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
    }
    return '{' . implode(',', $parts) . '}';
}

function anchorDerToRawLowS(string $der): string
{
    $offset = 2;
    if (ord($der[0]) !== 0x30) throw new RuntimeException('Invalid ECDSA sequence.');
    if (ord($der[$offset++]) !== 0x02) throw new RuntimeException('Invalid ECDSA R.');
    $rLength = ord($der[$offset++]);
    $r = str_pad(ltrim(substr($der, $offset, $rLength), "\0"), 32, "\0", STR_PAD_LEFT);
    $offset += $rLength;
    if (ord($der[$offset++]) !== 0x02) throw new RuntimeException('Invalid ECDSA S.');
    $sLength = ord($der[$offset++]);
    $s = str_pad(ltrim(substr($der, $offset, $sLength), "\0"), 32, "\0", STR_PAD_LEFT);
    $half = hex2bin('7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8');
    if (strcmp($s, $half) > 0) {
        $order = array_values(unpack('C*', hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')));
        $bytes = array_values(unpack('C*', $s));
        $borrow = 0;
        for ($i = 31; $i >= 0; $i--) {
            $v = $order[$i] - $bytes[$i] - $borrow;
            $borrow = $v < 0 ? 1 : 0;
            $bytes[$i] = $v < 0 ? $v + 256 : $v;
        }
        $s = pack('C*', ...$bytes);
    }
    return $r . $s;
}

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
$otherKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($key === false || $otherKey === false) throw new RuntimeException('Unable to generate test signing keys.');
$publicPem = openssl_pkey_get_details($key)['key'];
$otherPem = openssl_pkey_get_details($otherKey)['key'];
$signers = [['kid' => 'registry-test-1', 'role' => 'registry-anchor', 'alg' => 'ES256', 'public_key_pem' => $publicPem]];
$now = 1_800_000_000;
$payload = [
    'type' => 'SENTRYIQ-REGISTRY-ANCHOR',
    'schema_version' => 1,
    'owner_id' => 'owner-test-001',
    'sequence' => '1',
    'bundle_sha256' => hash('sha256', 'bundle-one'),
    'issued_at' => $now - 10,
    'expires_at' => $now + 3600,
    'previous_bundle_sha256' => null,
    'signer_kid' => 'registry-test-1',
];
$signed = anchorCanonical($payload);
$der = '';
if (!openssl_sign($signed, $der, $key, OPENSSL_ALGO_SHA256)) throw new RuntimeException('Unable to sign registry fixture.');
$signature = anchorDerToRawLowS($der);
$verifier = new RegistryAnchorVerifier();
$result = $verifier->verify($signed, $signature, $signers, 'owner-test-001', null, null, $now);
anchorAssert($result['sequence'] === '1' && $result['bundle_sha256'] === $payload['bundle_sha256'], 'Valid initial anchor should verify.');

$next = $payload;
$next['sequence'] = '2';
$next['previous_bundle_sha256'] = $payload['bundle_sha256'];
$next['bundle_sha256'] = hash('sha256', 'bundle-two');
$next['issued_at'] = $now;
$next['expires_at'] = $now + 7200;
$nextSigned = anchorCanonical($next);
openssl_sign($nextSigned, $nextDer, $key, OPENSSL_ALGO_SHA256);
$nextSignature = anchorDerToRawLowS($nextDer);
$advanced = $verifier->verify($nextSigned, $nextSignature, $signers, 'owner-test-001', '1', $payload['bundle_sha256'], $now);
anchorAssert($advanced['sequence'] === '2', 'Exactly sequential anchor with previous digest should verify.');
$same = $verifier->verify($signed, $signature, $signers, 'owner-test-001', '1', $payload['bundle_sha256'], $now);
anchorAssert($same['sequence'] === '1', 'Identical current anchor should remain loadable.');

anchorReject(fn() => $verifier->verify($signed, $signature, $signers, 'other-owner', null, null, $now), 'Cross-owner anchor replay must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, [['kid' => 'registry-test-1', 'role' => 'release-authorisation', 'alg' => 'ES256', 'public_key_pem' => $publicPem]], 'owner-test-001', null, null, $now), 'Wrong signer role must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, [$signers[0], $signers[0]], 'owner-test-001', null, null, $now), 'Duplicate independently pinned signer IDs must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, [['kid' => 'registry-test-1', 'role' => 'registry-anchor', 'alg' => 'ES256', 'public_key_pem' => $otherPem]], 'owner-test-001', null, null, $now), 'Unpinned key must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, $signers, 'owner-test-001', '1', hash('sha256', 'different'), $now), 'Same-sequence digest substitution must fail.');
anchorReject(fn() => $verifier->verify($nextSigned, $nextSignature, $signers, 'owner-test-001', '1', hash('sha256', 'different'), $now), 'Broken previous-digest chain must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, $signers, 'owner-test-001', '2', $next['bundle_sha256'], $now), 'Rollback must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, $signers, 'owner-test-001', null, null, $now + 86_401), 'Stale anchor must fail.');
anchorReject(fn() => $verifier->verify($signed, $signature, $signers, 'owner-test-001', null, null, $now + 3600), 'Expired anchor must fail.');
anchorReject(fn() => $verifier->verify($signed, substr($signature, 0, 63), $signers, 'owner-test-001', null, null, $now), 'Malformed signature length must fail.');
anchorReject(fn() => $verifier->verify(str_replace('"sequence":"1"', '"sequence":"1","sequence":"2"', $signed), $signature, $signers, 'owner-test-001', null, null, $now), 'Duplicate JSON members must fail.');
anchorReject(fn() => $verifier->verify(' ' . $signed, $signature, $signers, 'owner-test-001', null, null, $now), 'Non-canonical payload must fail.');

echo "Registry anchor verifier tests passed.\n";
