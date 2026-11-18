<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Documents/DocumentStore.php';

use SentryIQCloud\Documents\DocumentStore;

function documentStoreCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function documentStoreReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

function documentStoreRemoveTree(string $path): void
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

$root = sys_get_temp_dir() . '/sentryiq-document-store-' . bin2hex(random_bytes(8));
$public = $root . '/public';
$private = $root . '/private';
foreach ([$public, $private] as $directory) {
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to prepare DocumentStore test workspace.');
    }
}

try {
    $_SERVER['DOCUMENT_ROOT'] = $public;
    documentStoreReject(
        fn() => new DocumentStore($public . '/documents.json'),
        'Document metadata inside DOCUMENT_ROOT must be rejected.'
    );

    $path = $private . '/documents.json';
    $store = new DocumentStore($path);
    $idOne = str_repeat('1', 32);
    $idTwo = str_repeat('2', 32);
    $store->put($idOne, ['name' => 'one']);
    $store->put($idTwo, ['name' => 'two']);
    documentStoreCheck(count($store->all()) === 2, 'Document metadata writes should be visible.');

    $store->remove($idOne);
    documentStoreCheck(!isset($store->all()[$idOne]), 'Document metadata removal should be committed.');
    documentStoreReject(
        fn() => $store->remove('../invalid'),
        'Invalid document identifiers must be rejected before mutation.'
    );

    $symlinkParent = $public . '/linked-private';
    if (!symlink($private, $symlinkParent)) throw new RuntimeException('Unable to create parent symlink fixture.');
    documentStoreReject(
        fn() => new DocumentStore($symlinkParent . '/documents.json'),
        'A symlinked parent directory must be rejected.'
    );

    $linkedFile = $private . '/linked.json';
    $outsideFile = $root . '/outside.json';
    file_put_contents($outsideFile, '{}');
    if (!symlink($outsideFile, $linkedFile)) throw new RuntimeException('Unable to create file symlink fixture.');
    documentStoreReject(
        fn() => new DocumentStore($linkedFile),
        'A symlinked metadata file must be rejected.'
    );

    $lockPath = $private . '/locked.json';
    $lockStore = new DocumentStore($lockPath);
    file_put_contents($private . '/target.json', '{}');
    if (!symlink($private . '/target.json', $lockPath . '.lock')) throw new RuntimeException('Unable to create lock symlink fixture.');
    documentStoreReject(
        fn() => $lockStore->all(),
        'A symlinked metadata lock must be rejected.'
    );
    unlink($lockPath . '.lock');

    $permissionsPath = $private . '/bad-permissions.json';
    file_put_contents($permissionsPath, '{}');
    chmod($permissionsPath, 0644);
    $permissionsStore = new DocumentStore($permissionsPath);
    documentStoreReject(
        fn() => $permissionsStore->all(),
        'Metadata files readable by group/other must be rejected.'
    );

    // Concurrent independent writers must not lose each other's updates.
    $concurrentPath = $private . '/concurrent.json';
    $childCode = 'require ' . var_export(dirname(__DIR__) . '/cloud/Documents/DocumentStore.php', true) . ';'
        . '$s=new \\\\SentryIQCloud\\\\Documents\\\\DocumentStore($argv[1]);'
        . 'for($i=0;$i<20;$i++){ $id=sprintf("%032x", ((int)$argv[2])*100+$i+1); $s->put($id,["worker"=>(int)$argv[2],"index"=>$i]); }';
    $processes = [];
    foreach ([1, 2] as $worker) {
        $pipes = [];
        $process = proc_open([PHP_BINARY, '-r', $childCode, $concurrentPath, (string)$worker], [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);
        if (!is_resource($process)) throw new RuntimeException('Unable to start concurrent DocumentStore writer.');
        fclose($pipes[0]);
        $processes[] = [$process, $pipes];
    }
    foreach ($processes as [$process, $pipes]) {
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($process);
        documentStoreCheck($exit === 0, 'Concurrent writer failed: ' . $stderr . $stdout);
    }
    $concurrent = (new DocumentStore($concurrentPath))->all();
    documentStoreCheck(count($concurrent) === 40, 'Concurrent metadata updates were lost.');

    echo "Document metadata locking and path tests passed.\\n";
} finally {
    unset($_SERVER['DOCUMENT_ROOT']);
    documentStoreRemoveTree($root);
}
