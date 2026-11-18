<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Auth/WebAuthnCose.php';

use SentryIQ\Auth\WebAuthnCose;

function coseCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function coseReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function coseFixture(string $x, string $y, string $algorithm = "\x26", string $curve = "\x01"): string
{
    return "\xA5"
        . "\x01\x02"
        . "\x03" . $algorithm
        . "\x20" . $curve
        . "\x21\x58\x20" . $x
        . "\x22\x58\x20" . $y;
}

$key = openssl_pkey_new([
    'private_key_type' => OPENSSL_KEYTYPE_EC,
    'curve_name' => 'prime256v1',
]);
if ($key === false) throw new RuntimeException('Unable to generate P-256 test key.');
$details = openssl_pkey_get_details($key);
$x = $details['ec']['x'] ?? null;
$y = $details['ec']['y'] ?? null;
if (!is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
    throw new RuntimeException('OpenSSL did not return P-256 public coordinates.');
}

$coseBytes = coseFixture($x, $y);
$offset = 0;
$cose = WebAuthnCose::decodeFirst($coseBytes, $offset);
coseCheck(is_array($cose), 'COSE key must decode to a map.');
coseCheck($offset === strlen($coseBytes), 'COSE parser must consume exactly the encoded key.');

$expectedDer = hex2bin('3059301306072A8648CE3D020106082A8648CE3D03010703420004') . $x . $y;
$actualDer = WebAuthnCose::ec2P256SpkiDer($cose);
coseCheck(hash_equals($expectedDer, $actualDer), 'COSE coordinates did not produce the expected ES256 SPKI key.');

$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($expectedDer), 64, "\n") . "-----END PUBLIC KEY-----\n";
coseCheck(
    hash_equals($expectedDer, WebAuthnCose::pemToDer($pem)),
    'Submitted PEM key did not decode to the same SPKI DER.'
);

coseReject(
    fn() => WebAuthnCose::ec2P256SpkiDer(WebAuthnCose::decodeFirst(coseFixture($x, $y, "\x25"))),
    'A COSE key with a non-ES256 algorithm must be rejected.'
);
coseReject(
    fn() => WebAuthnCose::ec2P256SpkiDer(WebAuthnCose::decodeFirst(coseFixture($x, $y, "\x26", "\x02"))),
    'A COSE key with a non-P-256 curve must be rejected.'
);
coseReject(
    fn() => WebAuthnCose::ec2P256SpkiDer(WebAuthnCose::decodeFirst(coseFixture(substr($x, 1), $y))),
    'A COSE key with a truncated coordinate must be rejected.'
);
coseReject(
    fn() => WebAuthnCose::decodeFirst("\xA2\x01\x02\x01\x03"),
    'Duplicate CBOR map keys must be rejected.'
);
coseReject(
    fn() => WebAuthnCose::decodeFirst("\xA5\x01"),
    'Truncated CBOR maps must be rejected.'
);
coseReject(
    fn() => WebAuthnCose::pemToDer('not a public key'),
    'Malformed submitted PEM must be rejected.'
);

echo "WebAuthn attested COSE public-key binding tests passed.\\n";
