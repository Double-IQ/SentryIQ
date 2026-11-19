<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/SecurityBootstrap.php';
require_once __DIR__ . '/../app/Security/BoundedLog.php';

use SentryIQ\Security\BoundedLog;

function boundedLogCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function boundedLogReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function boundedLogRemoveTree(string $path): void
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

$root = sys_get_temp_dir() . '/sentryiq-bounded-log-' . bin2hex(random_bytes(8));
$public = $root . '/public';
$private = $root . '/private';
foreach ([$public, $private] as $directory) {
    if (!mkdir($directory, 0700, true)) throw new RuntimeException('Unable to prepare bounded log workspace.');
}
try {
    $_SERVER['DOCUMENT_ROOT'] = $public;
    $path = $private . '/diagnostic.log';
    $line = str_repeat('x', 600) . PHP_EOL;
    for ($i = 0; $i < 10; $i++) BoundedLog::append($path, $line, 1024, 2);
    boundedLogCheck(is_file($path) && is_file($path . '.1') && is_file($path . '.2'), 'Bounded log should retain the current file and two rotated segments.');
    boundedLogCheck(!file_exists($path . '.3'), 'Bounded log should prune segments beyond the retention count.');
    boundedLogCheck((int)filesize($path) <= 1024, 'Current bounded log must stay within its configured size.');
    boundedLogCheck(((int)fileperms($path) & 0077) === 0, 'Current bounded log must be owner-only.');
    boundedLogCheck(((int)fileperms($path . '.1') & 0077) === 0, 'Rotated bounded logs must be owner-only.');

    boundedLogReject(
        fn() => BoundedLog::append($public . '/web.log', 'test' . PHP_EOL),
        'Logs inside DOCUMENT_ROOT must be rejected.'
    );

    $outside = $root . '/outside.log';
    file_put_contents($outside, 'unchanged');
    $symlink = $private . '/symlink.log';
    if (!symlink($outside, $symlink)) throw new RuntimeException('Unable to create bounded log symlink fixture.');
    boundedLogReject(
        fn() => BoundedLog::append($symlink, 'attack' . PHP_EOL),
        'Symlinked bounded log paths must be rejected.'
    );
    boundedLogCheck(file_get_contents($outside) === 'unchanged', 'Bounded log writer must not follow symlink targets.');

    $lockSymlink = $private . '/lock.log';
    if (!symlink($outside, $lockSymlink . '.lock')) throw new RuntimeException('Unable to create bounded log lock symlink fixture.');
    boundedLogReject(
        fn() => BoundedLog::append($lockSymlink, 'attack' . PHP_EOL),
        'Symlinked bounded log lock paths must be rejected.'
    );

    echo "Bounded diagnostic log tests passed.\\n";
} finally {
    unset($_SERVER['DOCUMENT_ROOT']);
    boundedLogRemoveTree($root);
}
