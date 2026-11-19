<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/SecurityBootstrap.php';
require_once __DIR__ . '/../app/Updates/UpdateManager.php';

use SentryIQ\Updates\UpdateManager;

function privatePathCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function privatePathReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function privatePathRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) rmdir($item->getPathname());
        else unlink($item->getPathname());
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . '/sentryiq-private-path-' . bin2hex(random_bytes(8));
$webRoot = $root . '/public';
$inside = $webRoot . '/private_data';
$outside = $root . '/private_data';
$app = $root . '/app';
foreach ([$webRoot, $inside, $outside, $app] as $directory) {
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to prepare private path test directory.');
    }
}

try {
    $_SERVER['DOCUMENT_ROOT'] = $webRoot;

    privatePathCheck(
        !sentryiq_path_is_outside_document_root($webRoot),
        'The document root itself must not be accepted as private storage.'
    );
    privatePathCheck(
        !sentryiq_path_is_outside_document_root($inside),
        'A directory nested inside the document root must be rejected.'
    );
    privatePathCheck(
        sentryiq_path_is_outside_document_root($outside),
        'A canonical sibling directory outside the document root should be accepted.'
    );

    $linkedParent = $webRoot . '/linked-parent';
    if (!symlink($root, $linkedParent)) {
        throw new RuntimeException('Unable to create symlink fixture.');
    }
    privatePathCheck(
        !sentryiq_path_is_outside_document_root($linkedParent . '/private_data'),
        'A path escaping through a symlinked parent must be rejected.'
    );

    privatePathReject(
        fn() => new UpdateManager($app, $inside),
        'UpdateManager must reject private data stored under DOCUMENT_ROOT.'
    );
    new UpdateManager($app, $outside);

    unset($_SERVER['DOCUMENT_ROOT']);
    privatePathCheck(
        sentryiq_path_is_outside_document_root($outside),
        'CLI operation without DOCUMENT_ROOT should retain canonical private-path validation.'
    );

    echo "Private data directory boundary tests passed.\\n";
} finally {
    unset($_SERVER['DOCUMENT_ROOT']);
    privatePathRemoveTree($root);
}
