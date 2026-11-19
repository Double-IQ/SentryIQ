<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationNonceStore.php';

use SentryIQ\Updates\PrivateHostAttestationNonceStore;

function nonceStoreAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function nonceStoreReject(callable $operation, string $message): void
{
    $rejected = false;
    try { $operation(); } catch (Throwable) { $rejected = true; }
    nonceStoreAssert($rejected, $message);
}

$root = sys_get_temp_dir() . '/sentryiq-private-host-nonce-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/httpdocs';
mkdir($private, 0700, true);
mkdir($web, 0700, true);
$lockPath = $private . '/private-host-nonces.lock';
$statePath = $private . '/private-host-nonces.json';
file_put_contents($lockPath, '');
chmod($lockPath, 0600);

try {
    $store = new PrivateHostAttestationNonceStore($private, $web);
    $nonce = bin2hex(random_bytes(32));
    nonceStoreAssert($store->consume('integrity-a', $nonce, time() + 120), 'A fresh nonce should be accepted once.');
    nonceStoreAssert(!$store->consume('integrity-a', $nonce, time() + 120), 'A replayed node/nonce pair must be rejected.');
    nonceStoreAssert($store->consume('integrity-b', $nonce, time() + 120), 'The same nonce value is independent across node identities.');

    file_put_contents($statePath, str_repeat('x', 1_048_577));
    chmod($statePath, 0600);
    nonceStoreReject(
        static fn() => $store->consume('integrity-a', bin2hex(random_bytes(32)), time() + 120),
        'An oversized nonce state file must be rejected before an unbounded read.'
    );

    unlink($statePath);
    $outside = $root . '/outside.json';
    file_put_contents($outside, '{"format":1,"nonces":[]}');
    chmod($outside, 0600);
    symlink($outside, $statePath);
    nonceStoreReject(
        static fn() => $store->consume('integrity-a', bin2hex(random_bytes(32)), time() + 120),
        'A symlinked nonce state file must be rejected.'
    );

    unlink($statePath);
    unlink($lockPath);
    symlink($outside, $lockPath);
    nonceStoreReject(
        static fn() => $store->consume('integrity-a', bin2hex(random_bytes(32)), time() + 120),
        'A symlinked nonce lock file must be rejected.'
    );

    echo "Private host attestation nonce store tests passed.\\n";
} finally {
    if (is_link($statePath) || is_file($statePath)) @unlink($statePath);
    if (is_link($lockPath) || is_file($lockPath)) @unlink($lockPath);
    @unlink($outside ?? '');
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}
