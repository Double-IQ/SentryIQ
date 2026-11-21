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
    'VERSION' => ['path' => 'VERSION', 'size' => 6, 'sha256' => str_repeat('d', 64)],
    'assets/app.js' => ['path' => 'assets/app.js', 'size' => 10, 'sha256' => str_repeat('a', 64)],
    'index.php' => ['path' => 'index.php', 'size' => 100, 'sha256' => str_repeat('b', 64)],
    'runtime/secret.php' => ['path' => 'runtime/secret.php', 'size' => 20, 'sha256' => str_repeat('c', 64)],
];
$manifest = [
    'public_files' => ['VERSION', 'assets/app.js', 'index.php'],
    'public_http_files' => ['VERSION', 'assets/app.js'],
    'runtime_files' => ['secret.php'],
];
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($manifest, $entries, []) === ['VERSION', 'assets/app.js'],
    'Empty config must use the complete signed static asset allowlist.'
);
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['VERSION']) === ['VERSION'],
    'The exact root VERSION marker should be accepted as a signed static asset.'
);
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['index.php']),
    'Dynamic PHP source must never be fetched and compared as an HTTP response.'
);
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['runtime/secret.php']),
    'Private runtime files must never be included in public HTTP checks.'
);

$legacy = ['public_files' => ['VERSION', 'assets/app.js', 'index.php', 'runtime/secret.php']];
publicAssetAssert(
    IntegrityPublicAssetPolicy::resolve($legacy, $entries, []) === ['VERSION', 'assets/app.js'],
    'Legacy format-2 manifests must safely derive static assets without including PHP.'
);

publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($manifest, $entries, ['VERSION', 'VERSION']),
    'Configured public asset paths must not contain duplicates.'
);
$duplicatePublicFiles = $manifest;
$duplicatePublicFiles['public_files'][] = 'VERSION';
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($duplicatePublicFiles, $entries, []),
    'Signed public file inventory must not contain duplicates.'
);
$duplicateHttpFiles = $manifest;
$duplicateHttpFiles['public_http_files'][] = 'VERSION';
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve($duplicateHttpFiles, $entries, []),
    'Signed HTTP asset inventory must not contain duplicates.'
);
$largeEntries = [];
$largeManifestPaths = [];
for ($index = 0; $index < 99; $index++) {
    $path = 'assets/file-' . $index . '.js';
    $largeEntries[$path] = ['path' => $path, 'size' => 1, 'sha256' => str_repeat('a', 64)];
    $largeManifestPaths[] = $path;
}
publicAssetReject(
    fn() => IntegrityPublicAssetPolicy::resolve(
        ['public_files' => $largeManifestPaths, 'public_http_files' => $largeManifestPaths],
        $largeEntries,
        []
    ),
    'Public asset selection must reserve report slots for mandatory security evidence markers.'
);

echo "Integrity public asset policy tests passed.\n";
