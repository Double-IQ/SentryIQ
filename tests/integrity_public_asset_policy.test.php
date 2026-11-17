<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityPublicAssetPolicy.php';

use SentryIQ\Updates\IntegrityPublicAssetPolicy;

function publicAssetAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function publicAssetReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$entries = [
    'assets/app.js' => ['path' => 'assets/app.js', 'size' => 10, 'sha256' => str_repeat('a', 64)],
    'index.php' => ['path' => 'index.php', 'size' => 100, 'sha256' => str_repeat('b', 64)],
    'runtime/secret.php' => ['path' => 'runtime/secret.php', 'size' => 20, 'sha256' => str_repeat('c', 64)],
];
$manifest = [
    'public_files' => ['assets/app.js', 'index.php'],
    'public_http_files' => ['assets/app.js'],
    'runtime_files' => ['secret.php'],
];
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($manifest, $entries, []) === ['assets/app.js'],
    'Empty config must use the complete signed static asset allowlist.'
);
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['assets/app.js']) === ['assets/app.js'],
    'An explicit static subset should be accepted.'
);
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['index.php']),
    'Dynamic PHP source must never be fetched and compared as an HTTP response.'
);
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['runtime/secret.php']),
    'Private runtime files must never be included in public HTTP checks.'
);

$legacy = ['public_files' => ['assets/app.js', 'index.php', 'runtime/secret.php']];
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($legacy, $entries, []) === ['assets/app.js'],
    'Legacy format-2 manifests must safely derive static assets without including PHP.'
);

echo "Integrity public asset policy tests passed.\n";
