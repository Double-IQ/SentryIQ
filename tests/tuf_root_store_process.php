<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';

use SentryIQ\Updates\TufRootStore;

if ($argc !== 3) {
    fwrite(STDERR, "Usage: php tuf_root_store_process.php <write|read> <private-directory>\n");
    exit(2);
}

[$program, $action, $directory] = $argv;
$expected = json_encode([
    'signed' => ['_type' => 'root', 'version' => 7],
    'signatures' => [],
], JSON_THROW_ON_ERROR);

$store = new TufRootStore($directory);

if ($action === 'write') {
    $store->storeVerifiedRoot($expected);
    echo "writer process persisted root\n";
    exit(0);
}

if ($action === 'read') {
    $actual = $store->load();
    if ($actual !== $expected) {
        fwrite(STDERR, "A fresh PHP process did not reload the exact persisted root.\n");
        exit(1);
    }
    echo "fresh reader process reloaded exact root bytes\n";
    exit(0);
}

fwrite(STDERR, "Unknown action.\n");
exit(2);
