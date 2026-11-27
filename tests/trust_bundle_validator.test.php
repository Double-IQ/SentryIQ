<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/TrustBundleValidator.php';

use SentryIQ\Security\TrustBundleValidator;

function trustBundleAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function trustBundleReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

function jcsForFixture(mixed $value): string
{
    if ($value instanceof stdClass) {
        $fields = get_object_vars($value);
        ksort($fields, SORT_STRING);
        $parts = [];
        foreach ($fields as $key => $child) {
            $parts[] = json_encode((string)$key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR)
                . ':' . jcsForFixture($child);
        }
        return '{' . implode(',', $parts) . '}';
    }
    if (is_array($value)) {
        if (array_is_list($value)) return '[' . implode(',', array_map('jcsForFixture', $value)) . ']';
        return jcsForFixture((object)$value);
    }
    return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
}

function derEcdsaToRaw(string $der): string
{
    if (strlen($der) < 8 || ord($der[0]) !== 0x30 || ord($der[2]) !== 0x02) {
        throw new RuntimeException('Unexpected OpenSSL ECDSA signature encoding.');
    }
    $offset = 3;
    $rLength = ord($der[$offset++]);
    $r = substr($der, $offset, $rLength);
    $offset += $rLength;
    if (ord($der[$offset++]) !== 0x02) throw new RuntimeException('Invalid ECDSA S integer.');
    $sLength = ord($der[$offset++]);
    $s = substr($der, $offset, $sLength);
    $r = str_pad(ltrim($r, "\0"), 32, "\0", STR_PAD_LEFT);
    $s = str_pad(ltrim($s, "\0"), 32, "\0", STR_PAD_LEFT);
    $halfOrder = hex2bin('7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8');
    $order = hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    if (strcmp($s, $halfOrder) > 0) {
        $orderBytes = array_values(unpack('C*', $order));
        $sBytes = array_values(unpack('C*', $s));
        $borrow = 0;
        for ($i = 31; $i >= 0; $i--) {
            $value = $orderBytes[$i] - $sBytes[$i] - $borrow;
            $borrow = $value < 0 ? 1 : 0;
            if ($borrow) $value += 256;
            $sBytes[$i] = $value;
        }
        $s = pack('C*', ...$sBytes);
    }
    return $r . $s;
}

function highSFromLowSignature(string $raw): string
{
    $order = hex2bin('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    $orderBytes = array_values(unpack('C*', $order));
    $sBytes = array_values(unpack('C*', substr($raw, 32, 32)));
    $borrow = 0;
    for ($i = 31; $i >= 0; $i--) {
        $value = $orderBytes[$i] - $sBytes[$i] - $borrow;
        $borrow = $value < 0 ? 1 : 0;
        if ($borrow) $value += 256;
        $sBytes[$i] = $value;
    }
    return substr($raw, 0, 32) . pack('C*', ...$sBytes);
}

$key = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]);
if ($key === false) throw new RuntimeException('Unable to generate P-256 test key.');
$details = openssl_pkey_get_details($key);
$publicPem = $details['key'];
$agreementKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($agreementKey === false) throw new RuntimeException('Unable to generate P-256 agreement test key.');
$agreementPem = openssl_pkey_get_details($agreementKey)['key'];
$releaseKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($releaseKey === false) throw new RuntimeException('Unable to generate release-authorisation test key.');
$releasePem = openssl_pkey_get_details($releaseKey)['key'];
$privateKey = $releaseKey;
$validator = new TrustBundleValidator();
$now = 1795585200;
$issued = gmdate('Y-m-d\TH:i:s\Z', $now - 60);
$expires = gmdate('Y-m-d\TH:i:s\Z', $now + 86400);

$makeBundle = static function (array $overrides = []) use ($publicPem, $agreementPem, $releasePem, $privateKey, $issued, $expires): string {
    $bundle = [
        'type' => 'SENTRYIQ-TRUST-BUNDLE',
        'schema_version' => 1,
        'policy_version' => '1',
        'sequence' => '1',
        'previous_digest' => null,
        'issued_at' => $issued,
        'expires_at' => $expires,
        'owner_id' => 'owner-test-001',
        'master_keyset' => [
            'hardware_assurance' => 'secure-enclave',
            'signing' => ['kid' => 'master-sign-1', 'alg' => 'ES256', 'public_key_pem' => $publicPem],
            'key_agreement' => ['kid' => 'master-agree-1', 'alg' => 'ECDH-ES', 'public_key_pem' => $agreementPem],
        ],
        'release_authorisation' => [
            'keys' => [[
                'kid' => 'release-root-1',
                'alg' => 'ES256',
                'public_key_pem' => $releasePem,
                'purpose' => 'release-authorisation',
            ]],
        ],
        'verifier' => ['qualification_state' => 'pending', 'policy_version' => '1', 'keys' => []],
        'sigstore_tuf' => ['root_version' => 1, 'root_digest' => str_repeat('a', 64)],
        'revocations' => [],
        'signatures' => [],
    ];
    $bundle = array_replace($bundle, $overrides);
    $unsigned = (object)$bundle;
    unset($unsigned->signatures);
    $payload = jcsForFixture($unsigned);
    if (!openssl_sign($payload, $der, $privateKey, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException('Unable to sign trust bundle fixture.');
    }
    $raw = derEcdsaToRaw($der);
    $bundle['signatures'] = [[
        'kid' => 'release-root-1',
        'role' => 'release-authorisation',
        'alg' => 'ES256',
        'signature' => rtrim(strtr(base64_encode($raw), '+/', '-_'), '='),
    ]];
    return json_encode($bundle, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS | JSON_THROW_ON_ERROR);
};

$trusted = [[
    'kid' => 'release-root-1',
    'role' => 'release-authorisation',
    'alg' => 'ES256',
    'public_key_pem' => $releasePem,
]];
$valid = $makeBundle();
$result = $validator->validate($valid, $trusted, 'owner-test-001', null, null, $now);
trustBundleAssert($result['sequence'] === '1', 'Valid bootstrap bundle should retain its sequence.');
trustBundleAssert(strlen($result['digest']) === 64, 'Validated bundle should expose its canonical SHA-256 digest.');
trustBundleAssert(preg_match('/^[a-f0-9]{64}$/D', $result['master_keyset_digest'] ?? '') === 1,
    'Validated bundle should expose the cross-platform master keyset digest.');
trustBundleAssert($result['signer_kids'] === ['release-root-1'], 'Validated bundle should report its independently pinned signer.');
$releaseSpkiBody = preg_replace('/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/', '', $releasePem);
$releaseSpkiDer = is_string($releaseSpkiBody) ? base64_decode($releaseSpkiBody, true) : false;
trustBundleAssert(is_string($releaseSpkiDer) && hash_equals(
    hash('sha256', $releaseSpkiDer),
    $result['key_fingerprints']['release-root-1'] ?? ''
), 'Validator must expose SHA-256 of DER SubjectPublicKeyInfo, not PEM text.');

trustBundleReject(
    fn() => $validator->validate($valid, [], 'owner-test-001', null, null, $now),
    'A bundle signed only by an unpinned key must be rejected.'
);
trustBundleReject(
    fn() => $validator->validate($valid, $trusted, 'another-owner', null, null, $now),
    'Owner/account mismatch must be rejected.'
);
trustBundleReject(
    fn() => $validator->validate($valid, $trusted, 'owner-test-001', null, '1', $now),
    'Same-sequence replay must be rejected.'
);
trustBundleReject(
    fn() => $validator->validate($valid, $trusted, 'owner-test-001', null, '2', $now),
    'Lower sequence must be rejected.'
);

$nextValid = $makeBundle([
    'sequence' => '2',
    'previous_digest' => $result['digest'],
]);
$nextResult = $validator->validate($nextValid, $trusted, 'owner-test-001', $result['digest'], '1', $now);
trustBundleAssert($nextResult['sequence'] === '2', 'A correctly chained higher sequence should pass.');

$next = $makeBundle([
    'sequence' => '2',
    'previous_digest' => str_repeat('b', 64),
]);
trustBundleReject(
    fn() => $validator->validate($next, $trusted, 'owner-test-001', str_repeat('c', 64), '1', $now),
    'Broken previous-digest chain must be rejected.'
);

$expiredBundle = $makeBundle([
    'issued_at' => gmdate('Y-m-d\TH:i:s\Z', $now - 172800),
    'expires_at' => gmdate('Y-m-d\TH:i:s\Z', $now - 3600),
]);
trustBundleReject(
    fn() => $validator->validate($expiredBundle, $trusted, 'owner-test-001', null, null, $now),
    'Expired trust bundle must be rejected.'
);

$unqualifiedWithKey = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$unqualifiedWithKey['verifier']['keys'] = [[
    'kid' => 'premature-verifier',
    'alg' => 'ES256',
    'public_key_pem' => $publicPem,
    'purpose' => 'verifier-report',
]];
trustBundleReject(
    fn() => $validator->validate(json_encode($unqualifiedWithKey, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Unqualified verifier keys must not enter the trusted bundle.'
);

$wrongRole = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$wrongRole['signatures'][0]['role'] = 'verifier-report';
trustBundleReject(
    fn() => $validator->validate(json_encode($wrongRole, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Cross-role signature use must be rejected.'
);

$oldRoot = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
if ($oldRoot === false) throw new RuntimeException('Unable to generate retired-root test key.');
$oldRootPem = openssl_pkey_get_details($oldRoot)['key'];
$revokedBundle = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$revokedBundle['revocations'] = [[
    'kid' => 'old-release-root',
    'effective_at' => gmdate('Y-m-d\\TH:i:s\\Z', $now - 1),
    'reason' => 'compromised',
]];
$revokedUnsigned = (object)$revokedBundle;
unset($revokedUnsigned->signatures);
openssl_sign(jcsForFixture($revokedUnsigned), $revokedDer, $oldRoot, OPENSSL_ALGO_SHA256);
$revokedRaw = derEcdsaToRaw($revokedDer);
$revokedBundle['signatures'] = [[
    'kid' => 'old-release-root',
    'role' => 'release-authorisation',
    'alg' => 'ES256',
    'signature' => rtrim(strtr(base64_encode($revokedRaw), '+/', '-_'), '='),
]];
$oldTrusted = [[
    'kid' => 'old-release-root',
    'role' => 'release-authorisation',
    'alg' => 'ES256',
    'public_key_pem' => $oldRootPem,
]];
trustBundleReject(
    fn() => $validator->validate(json_encode($revokedBundle, JSON_THROW_ON_ERROR), $oldTrusted, 'owner-test-001', null, null, $now),
    'A signature from a root already revoked at the current time must be rejected.'
);

$badSignature = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$badSignature['signatures'][0]['signature'] = rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
trustBundleReject(
    fn() => $validator->validate(json_encode($badSignature, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Forged signature must be rejected.'
);

$highSBundle = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$lowRaw = base64_decode(strtr($highSBundle['signatures'][0]['signature'], '-_', '+/') . '==', true);
$highRaw = highSFromLowSignature($lowRaw);
$highSBundle['signatures'][0]['signature'] = rtrim(strtr(base64_encode($highRaw), '+/', '-_'), '=');
trustBundleReject(
    fn() => $validator->validate(json_encode($highSBundle, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'High-S ECDSA signature malleability must be rejected.'
);

$duplicate = str_replace('"schema_version":1', '"schema_version":1,"schema_version":1', $valid);
trustBundleReject(
    fn() => $validator->validate($duplicate, $trusted, 'owner-test-001', null, null, $now),
    'Duplicate JSON members must be rejected before decoding.'
);

$reusedKey = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$reusedKey['master_keyset']['signing']['public_key_pem'] = $releasePem;
$reusedUnsigned = (object)$reusedKey;
unset($reusedUnsigned->signatures);
$reusedPayload = jcsForFixture($reusedUnsigned);
openssl_sign($reusedPayload, $reusedDer, $privateKey, OPENSSL_ALGO_SHA256);
$reusedRaw = derEcdsaToRaw($reusedDer);
$reusedKey['signatures'][0]['signature'] = rtrim(strtr(base64_encode($reusedRaw), '+/', '-_'), '=');
trustBundleReject(
    fn() => $validator->validate(json_encode($reusedKey, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Public key material must not be reused across master and release roles.'
);

$escapedDuplicate = str_replace('"schema_version":1', '"schema_version":1,"schema\\u005fversion":1', $valid);
trustBundleReject(
    fn() => $validator->validate($escapedDuplicate, $trusted, 'owner-test-001', null, null, $now),
    'Duplicate JSON member names expressed with Unicode escapes must be rejected.'
);

$softwareMaster = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$softwareMaster['master_keyset']['hardware_assurance'] = 'software';
trustBundleReject(
    fn() => $validator->validate(json_encode($softwareMaster, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Software-only keys must not be accepted for master authority.'
);

$unknownField = json_decode($valid, true, 64, JSON_THROW_ON_ERROR);
$unknownField['unexpected'] = true;
trustBundleReject(
    fn() => $validator->validate(json_encode($unknownField, JSON_THROW_ON_ERROR), $trusted, 'owner-test-001', null, null, $now),
    'Unknown trust bundle fields must be rejected.'
);

echo "Trust bundle validator tests passed.
";
