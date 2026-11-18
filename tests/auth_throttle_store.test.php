<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Auth/ThrottleStore.php';

use SentryIQ\Auth\ThrottleStore;

function throttleCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function throttleReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function throttleRemoveTree(string $path): void
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

$root = sys_get_temp_dir() . '/sentryiq-throttle-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700, true)) throw new RuntimeException('Unable to create throttle test directory.');
try {
    $path = $root . '/auth_throttle.json';
    $store = new ThrottleStore($path);
    $ip = '192.0.2.10';
    throttleCheck(!$store->blocked('master', $ip, 5, 900), 'A new throttle scope must start unblocked.');
    for ($i = 0; $i < 4; $i++) $store->failure('master', $ip, 5, 900, 900, 1000 + $i);
    throttleCheck(!$store->blocked('master', $ip, 5, 900, 1004), 'Throttle must remain open before the limit.');
    $store->failure('master', $ip, 5, 900, 900, 1004);
    throttleCheck($store->blocked('master', $ip, 5, 900, 1005), 'Throttle must block at the configured failure limit.');
    $store->clear('master', $ip);
    throttleCheck(!$store->blocked('master', $ip, 5, 900, 1005), 'Clearing the throttle must remove the lockout.');

    // Independent PHP processes increment the same counter concurrently.
    $concurrentPath = $root . '/concurrent.json';
    $childCode = 'require ' . var_export(dirname(__DIR__) . '/app/Auth/ThrottleStore.php', true) . ';'
        . '$s=new \\SentryIQ\\Auth\\ThrottleStore($argv[1]);'
        . 'for($i=0;$i<10;$i++){ $s->failure("master","198.51.100.10",15,900,900); }';
    $processes = [];
    foreach ([1, 2] as $_worker) {
        $pipes = [];
        $process = proc_open([PHP_BINARY, '-r', $childCode, $concurrentPath], [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!is_resource($process)) throw new RuntimeException('Unable to start concurrent throttle writer.');
        fclose($pipes[0]);
        $processes[] = [$process, $pipes];
    }
    foreach ($processes as [$process, $pipes]) {
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);
        throttleCheck($exit === 0, 'Concurrent throttle writer failed: ' . $stderr . $stdout);
    }
    $concurrent = new ThrottleStore($concurrentPath);
    throttleCheck(
        $concurrent->blocked('master', '198.51.100.10', 15, 900),
        'Concurrent failures must not be lost; the shared throttle must reach its limit.'
    );

    $symlinkPath = $root . '/symlink.json';
    $symlinkStore = new ThrottleStore($symlinkPath);
    file_put_contents($root . '/outside.json', '{}');
    if (!symlink($root . '/outside.json', $symlinkPath . '.lock')) throw new RuntimeException('Unable to create throttle lock symlink.');
    throttleReject(
        fn() => $symlinkStore->blocked('master', $ip, 5, 900),
        'Symlinked throttle lock files must be rejected.'
    );
    unlink($symlinkPath . '.lock');

    file_put_contents($symlinkPath, '{bad json');
    chmod($symlinkPath, 0600);
    throttleReject(
        fn() => $symlinkStore->blocked('master', $ip, 5, 900),
        'Corrupt throttle state must fail closed.'
    );

    echo "Atomic authentication throttle tests passed.\\n";
} finally {
    throttleRemoveTree($root);
}
