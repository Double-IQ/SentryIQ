<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/UpdateManager.php';

use SentryIQ\Updates\UpdateManager;

function archiveBoundaryAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function archiveBoundaryReject(UpdateManager $manager, string $zipPath, string $destination, string $label): void
{
    $method = new ReflectionMethod(UpdateManager::class, 'extractAndValidate');
    $method->setAccessible(true);
    $rejected = false;
    try { $method->invoke($manager, $zipPath, $destination, '1.2.3'); }
    catch (Throwable) { $rejected = true; }
    archiveBoundaryAssert($rejected, 'Unsafe archive was not rejected: ' . $label);
}

function archiveBoundaryCreate(string $path, array $entries): void
{
    $zip = new ZipArchive();
    if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create archive boundary fixture.');
    }
    foreach ($entries as $name => $contents) {
        if (!$zip->addFromString($name, $contents)) throw new RuntimeException('Unable to add archive fixture entry.');
    }
    if (!$zip->close()) throw new RuntimeException('Unable to close archive boundary fixture.');
}

if (!class_exists(ZipArchive::class)) {
    throw new RuntimeException('The archive boundary tests require PHP ZipArchive.');
}

$root = sys_get_temp_dir() . '/sentryiq-update-archive-' . bin2hex(random_bytes(8));
$app = $root . '/httpdocs';
$data = $root . '/private';
if (!mkdir($app, 0700, true) || !mkdir($data, 0700, true)) {
    throw new RuntimeException('Unable to prepare archive boundary workspace.');
}
$_SERVER['DOCUMENT_ROOT'] = $app;

try {
    $manager = new UpdateManager($app, $data);
    $manifest = json_encode(['version' => '1.2.3'], JSON_THROW_ON_ERROR);
    $method = new ReflectionMethod(UpdateManager::class, 'extractAndValidate');
    $method->setAccessible(true);

    $validZip = $root . '/valid.zip';
    archiveBoundaryCreate($validZip, [
        'update-manifest.json' => $manifest,
        'index.php' => '<?php // valid fixture',
        'runtime/vault_engine.php' => '<?php // valid runtime fixture',
    ]);
    $validDestination = $root . '/valid-stage';
    $method->invoke($manager, $validZip, $validDestination, '1.2.3');
    archiveBoundaryAssert(is_file($validDestination . '/index.php'), 'A safe release archive should extract.');

    $traversalZip = $root . '/traversal.zip';
    archiveBoundaryCreate($traversalZip, [
        'update-manifest.json' => $manifest,
        '../escape.php' => '<?php // traversal',
    ]);
    archiveBoundaryReject($manager, $traversalZip, $root . '/traversal-stage', 'parent traversal');

    $backslashZip = $root . '/backslash.zip';
    archiveBoundaryCreate($backslashZip, [
        'update-manifest.json' => $manifest,
        '..\\escape.php' => '<?php // backslash traversal',
    ]);
    archiveBoundaryReject($manager, $backslashZip, $root . '/backslash-stage', 'backslash traversal');

    $driveZip = $root . '/drive.zip';
    archiveBoundaryCreate($driveZip, [
        'update-manifest.json' => $manifest,
        'C:/escape.php' => '<?php // drive path',
    ]);
    archiveBoundaryReject($manager, $driveZip, $root . '/drive-stage', 'drive-prefixed path');

    $symlinkZip = $root . '/symlink.zip';
    $zip = new ZipArchive();
    if ($zip->open($symlinkZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException('Unable to create symlink archive fixture.');
    }
    $zip->addFromString('update-manifest.json', $manifest);
    $zip->addFromString('linked.php', 'outside.php');
    if (!$zip->setExternalAttributesName('linked.php', ZipArchive::OPSYS_UNIX, 0120777 << 16)) {
        throw new RuntimeException('Unable to mark archive entry as a symlink.');
    }
    $zip->close();
    archiveBoundaryReject($manager, $symlinkZip, $root . '/symlink-stage', 'symlink entry');

    archiveBoundaryAssert(!file_exists($root . '/escape.php'), 'Unsafe archive extraction wrote outside the staging directory.');
    echo "Updater archive boundary tests passed.\\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
        else @unlink($item->getPathname());
    }
    @rmdir($root);
}
