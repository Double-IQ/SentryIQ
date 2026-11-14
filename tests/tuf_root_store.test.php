<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';

use SentryIQ\Updates\TufRootStore;

function rootStoreAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rootBytes(int $version, string $marker = 'trusted'): string
{
    return json_encode([
        'signed' => ['_type' => 'root', 'version' => $version, 'marker' => $marker],
        'signatures' => [],
    ], JSON_THROW_ON_ERROR);
}

$directory = sys_get_temp_dir() . '/sentryiq-tuf-store-' . bin2hex(random_bytes(6));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary root-store directory.');
}

try {
    $store = new TufRootStore($directory);
    rootStoreAssert($store->load() === null, 'A new store must have no persisted root.');

    $v1 = rootBytes(1);
    $v2 = rootBytes(2);
    $store->storeVerifiedRoot($v1);
    rootStoreAssert($store->load() === $v1, 'Store must preserve exact root bytes.');
    $store->storeVerifiedRoot($v2);
    rootStoreAssert($store->load() === $v2, 'A higher verified root must replace the old root atomically.');

    $mode = fileperms($directory . '/tuf-root.json') & 0777;
    rootStoreAssert($mode === 0600, 'Persisted root file must have mode 0600.');

    $rollbackRejected = false;
    try {
        $store->storeVerifiedRoot($v1);
    } catch (RuntimeException) {
        $rollbackRejected = true;
    }
    rootStoreAssert($rollbackRejected, 'Older root versions must be rejected.');

    $sameVersionReplacementRejected = false;
    try {
        $store->storeVerifiedRoot(rootBytes(2, 'attacker-replacement'));
    } catch (RuntimeException) {
        $sameVersionReplacementRejected = true;
    }
    rootStoreAssert($sameVersionReplacementRejected, 'Different bytes at the same root version must be rejected.');

    $corruptPath = $directory . '/tuf-root.json';
    file_put_contents($corruptPath, '{corrupt');
    $corruptionRejected = false;
    try {
        $store->load();
    } catch (RuntimeException) {
        $corruptionRejected = true;
    }
    rootStoreAssert($corruptionRejected, 'Corrupt persisted metadata must fail closed.');

    echo "TUF root persistence boundary tests passed.\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $file) {
        if (is_file($file) || is_link($file)) {
            @unlink($file);
        }
    }
    @rmdir($directory);
}
