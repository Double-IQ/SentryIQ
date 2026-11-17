<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityNodeKeyGenerator.php';

use SentryIQ\\Updates\\IntegrityNodeKeyGenerator;

function keyGeneratorAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function keyGeneratorReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-node-keys-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/public';
mkdir($private, 0700, true);
mkdir($web, 0700, true);

try {
    $generator = new IntegrityNodeKeyGenerator();
    $result = $generator->generate('integrity-a', $private, $web);
    $secret = file_get_contents($result['private_key_path']);
    $public = file_get_contents($result['public_key_path']);
    keyGeneratorAssert(is_string($secret) && strlen($secret) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'Private Ed25519 key must be stored as raw secret-key bytes.');
    keyGeneratorAssert(is_string($public) && strlen($public) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'Public Ed25519 key must be stored as raw public-key bytes.');
    keyGeneratorAssert(base64_encode($public) === $result['public_key_base64'], 'Returned public-key encoding must match the public-key file.');
    keyGeneratorAssert(((fileperms($result['private_key_path']) ?: 0) & 0077) === 0, 'Private key file must not be accessible to group or other users.');
    keyGeneratorAssert(((fileperms($result['public_key_path']) ?: 0) & 0077) === 0, 'Public key file must remain in private node storage.');
    $message = 'SentryIQ independent node signing identity';
    $signature = sodium_crypto_sign_detached($message, $secret);
    keyGeneratorAssert(sodium_crypto_sign_verify_detached($signature, $message, $public), 'Generated private and public keys must form a valid Ed25519 pair.');
    keyGeneratorReject(fn() => $generator->generate('integrity-a', $private, $web), 'Existing node keys must never be overwritten.');
    keyGeneratorReject(fn() => $generator->generate('integrity-d', $private, $web), 'Unknown node identities must be rejected.');
    keyGeneratorReject(fn() => $generator->generate('integrity-b', $web, $web), 'Keys must not be stored inside the public webroot.');
    sodium_memzero($secret);
} finally {
    @unlink($private . '/integrity-a.ed25519.key');
    @unlink($private . '/integrity-a.ed25519.pub');
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}

echo "Integrity node key generator tests passed.\\n";
