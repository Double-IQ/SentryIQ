<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';

use SentryIQ\Updates\TufRootStore;

function rootStoreAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function rootStoreBytes(int $version, string $marker = 'trusted'): string
{
    return json_encode([
        'signed' => ['_type' => 'root', 'version' => $version, 'marker' => $marker],
        'signatures' => [],
    ], JSON_THROW_ON_ERROR);
}

$base = sys_get_temp_dir() . '/sentryiq-tuf-store-' . bin2hex(random_bytes(8));
$public = $base . '/httpdocs';
$private = $base . '/private';
if (!mkdir($public, 0700, true) || !mkdir($private, 0700, true)) {
    throw new RuntimeException('Unable to prepare TUF root-store test directories.');
}
$_SERVER['DOCUMENT_ROOT'] = $public;

try {
    $store = new TufRootStore($private);
    rootStoreAssert($store->load() === null, 'A new store must have no persisted root.');

    $v1 = rootStoreBytes(1);
    $v2 = rootStoreBytes(2);
    $store->storeVerifiedRoot($v1);
    rootStoreAssert($store->load() === $v1, 'Store must preserve exact root bytes.');
    $store->storeVerifiedRoot($v1);
    $store->storeVerifiedRoot($v2);
    rootStoreAssert($store->load() === $v2, 'A higher root version must replace the old root atomically.');
    rootStoreAssert((fileperms($private . '/tuf-root.json') & 0777) === 0600, 'Root file must be owner-only.');

    foreach ([
        static fn() => $store->storeVerifiedRoot($v1),
        static fn() => $store->storeVerifiedRoot(rootStoreBytes(2, 'different-bytes')),
    ] as $attempt) {
        $rejected = false;
        try { $attempt(); } catch (RuntimeException) { $rejected = true; }
        rootStoreAssert($rejected, 'Rollback and same-version replacement must be rejected.');
    }

    chmod($private . '/tuf-root.json', 0644);
    $permissionsRejected = false;
    try { $store->load(); } catch (RuntimeException) { $permissionsRejected = true; }
    rootStoreAssert($permissionsRejected, 'Group/world-readable root files must be rejected.');
    chmod($private . '/tuf-root.json', 0600);

    file_put_contents($private . '/tuf-root.json', '{corrupt');
    $corruptionRejected = false;
    try { $store->load(); } catch (RuntimeException) { $corruptionRejected = true; }
    rootStoreAssert($corruptionRejected, 'Corrupt persisted metadata must fail closed.');
    unlink($private . '/tuf-root.json');

    file_put_contents($base . '/outside-root.json', $v1);
    symlink($base . '/outside-root.json', $private . '/tuf-root.json');
    $symlinkRejected = false;
    try { $store->load(); } catch (RuntimeException) { $symlinkRejected = true; }
    rootStoreAssert($symlinkRejected, 'A symlinked root file must be rejected.');
    unlink($private . '/tuf-root.json');

    @unlink($private . '/tuf-root.lock');
    file_put_contents($base . '/outside-lock', '');
    symlink($base . '/outside-lock', $private . '/tuf-root.lock');
    $lockSymlinkRejected = false;
    try { $store->storeVerifiedRoot($v1); } catch (RuntimeException) { $lockSymlinkRejected = true; }
    rootStoreAssert($lockSymlinkRejected, 'A symlinked lock file must be rejected.');
    unlink($private . '/tuf-root.lock');

    $insidePublicRejected = false;
    try { new TufRootStore($public); } catch (RuntimeException) { $insidePublicRejected = true; }
    rootStoreAssert($insidePublicRejected, 'A directory inside the document root must be rejected.');

    chmod($private, 0755);
    $writableDirectoryRejected = false;
    try { new TufRootStore($private); } catch (RuntimeException) { $writableDirectoryRejected = true; }
    rootStoreAssert($writableDirectoryRejected, 'A group/world-writable private directory must be rejected.');

    echo "TUF root persistence boundary tests passed.\n";
} finally {
    foreach (glob($private . '/*') ?: [] as $file) if (is_file($file) || is_link($file)) @unlink($file);
    @rmdir($private);
    @rmdir($public);
    @unlink($base . '/outside-root.json');
    @unlink($base . '/outside-lock');
    @rmdir($base);
}
