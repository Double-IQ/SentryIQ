<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/BootstrapTargetStore.php';

use SentryIQ\Security\BootstrapTargetStore;

function bootstrapTargetAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function bootstrapTargetReject(callable $operation, string $message): void
{
    try { $operation(); }
    catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-target-store-' . bin2hex(random_bytes(8));
$outside = sys_get_temp_dir() . '/sentryiq-target-outside-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700) || !mkdir($root . '/releases', 0700) || !chmod($root, 0700)) {
    throw new RuntimeException('Could not create private target-store fixture.');
}
file_put_contents($root . '/releases/app.bin', 'verified fixture bytes');
file_put_contents($outside, 'external bytes');
chmod($root . '/releases/app.bin', 0600);
chmod($outside, 0600);
try {
    $store = new BootstrapTargetStore($root);
    $verified = [
        'releases/app.bin' => [
            'sha256' => hash('sha256', 'verified fixture bytes'),
            'length' => strlen('verified fixture bytes'),
        ],
    ];
    bootstrapTargetAssert(
        $store->read('releases/app.bin', $verified) === 'verified fixture bytes',
        'Authorized target must be read exactly and verified against signed metadata.'
    );
    bootstrapTargetReject(
        fn() => $store->read('releases/app.bin', []),
        'Target store must reject a path not present in verified target metadata.'
    );
    bootstrapTargetReject(
        fn() => $store->read('releases/app.bin', ['releases/app.bin' => ['sha256' => str_repeat('0', 64), 'length' => strlen('verified fixture bytes')]]),
        'Target store must reject bytes that do not match the signed target digest.'
    );
    bootstrapTargetReject(
        fn() => $store->read('releases/app.bin', ['releases/app.bin' => ['sha256' => hash('sha256', 'verified fixture bytes'), 'length' => 1]]),
        'Target store must reject target size mismatches.'
    );
    foreach (['../outside', '/absolute', 'releases/../app.bin', 'releases//app.bin', 'releases\\app.bin', 'releases/.'] as $unsafe) {
        bootstrapTargetAssert(!BootstrapTargetStore::validRelativePath($unsafe), 'Unsafe target path must fail validation.');
    }
    bootstrapTargetReject(
        fn() => $store->read('../' . basename($outside), ['../' . basename($outside) => ['sha256' => hash('sha256', 'external bytes'), 'length' => strlen('external bytes')]]),
        'Target store must reject path traversal.'
    );

    if (function_exists('symlink') && @symlink($outside, $root . '/releases/escape.bin')) {
        bootstrapTargetReject(
            fn() => $store->read('releases/escape.bin', ['releases/escape.bin' => ['sha256' => hash('sha256', 'external bytes'), 'length' => strlen('external bytes')]]),
            'Target store must reject symbolic links.'
        );
    }

    bootstrapTargetReject(
        fn() => new BootstrapTargetStore($root . '/releases/app.bin'),
        'Target store root must be a directory.'
    );
} finally {
    @unlink($root . '/releases/escape.bin');
    @unlink($root . '/releases/app.bin');
    @rmdir($root . '/releases');
    @rmdir($root);
    @unlink($outside);
}

echo "Bootstrap target-store confinement tests passed.\n";
