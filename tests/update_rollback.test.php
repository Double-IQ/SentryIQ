<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/UpdateManager.php';

use SentryIQ\Updates\UpdateManager;

function rollbackCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rollbackWrite(string $path, string $contents): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create test directory.');
    }
    if (file_put_contents($path, $contents) === false) {
        throw new RuntimeException('Unable to write test fixture.');
    }
}

function rollbackRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) {
            rmdir($item->getPathname());
        } else {
            unlink($item->getPathname());
        }
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . '/sentryiq-update-rollback-' . bin2hex(random_bytes(8));
$app = $root . '/app';
$data = $root . '/data';
$backup = $root . '/backup/public';
if (!mkdir($app, 0700, true) || !mkdir($data, 0700, true) || !mkdir($backup, 0700, true)) {
    throw new RuntimeException('Unable to prepare rollback test workspace.');
}

try {
    $manager = new UpdateManager($app, $data);
    $backupCopy = new ReflectionMethod(UpdateManager::class, 'copyAndVerifyBackup');
    $backupCopy->setAccessible(true);
    rollbackWrite($app . '/backup-source.bin', "backup-integrity-check");
    rollbackCheck(
        $backupCopy->invoke($manager, $app . '/backup-source.bin', $backup . '/verified-copy.bin') === true,
        'A valid backup copy should pass its size and SHA-256 verification.'
    );
    rollbackCheck(
        hash_file('sha256', $app . '/backup-source.bin') === hash_file('sha256', $backup . '/verified-copy.bin'),
        'Verified backup copy digest differs from its source.'
    );
    rollbackCheck(
        (fileperms($backup . '/verified-copy.bin') & 0777) === 0600,
        'Verified backup copy must be restricted to owner read/write permissions.'
    );
    rollbackCheck(
        $backupCopy->invoke($manager, $app . '/backup-source.bin', $backup . '/verified-copy.bin') === false,
        'Backup creation must refuse to overwrite an existing destination.'
    );
    $method = new ReflectionMethod(UpdateManager::class, 'rollbackTargets');
    $method->setAccessible(true);

    // Regression: an existing file without a completed backup must be preserved,
    // not treated as a newly-created file and deleted.
    rollbackWrite($app . '/existing-without-backup.php', 'original-existing-content');
    $errors = $method->invoke(
        $manager,
        ['existing-without-backup.php'],
        ['existing-without-backup.php' => true],
        [],
        $app,
        $backup,
        0644
    );
    rollbackCheck(
        file_get_contents($app . '/existing-without-backup.php') === 'original-existing-content',
        'An existing file without a completed backup was modified or deleted.'
    );
    rollbackCheck($errors !== [], 'Rollback must report an existing file with no completed backup.');

    // Existing files with completed backups are restored.
    rollbackWrite($app . '/existing.php', 'new-version-content');
    rollbackWrite($backup . '/existing.php', 'original-version-content');
    $errors = $method->invoke(
        $manager,
        ['existing.php'],
        ['existing.php' => true],
        ['existing.php' => true],
        $app,
        $backup,
        0644
    );
    rollbackCheck($errors === [], 'A valid backup should restore without errors.');
    rollbackCheck(
        file_get_contents($app . '/existing.php') === 'original-version-content',
        'The original file contents were not restored.'
    );

    // Files absent before the update may be removed during rollback.
    rollbackWrite($app . '/new-file.php', 'new-file-content');
    $errors = $method->invoke(
        $manager,
        ['new-file.php'],
        ['new-file.php' => false],
        [],
        $app,
        $backup,
        0644
    );
    rollbackCheck($errors === [], 'A newly-created file should be removed cleanly.');
    rollbackCheck(!file_exists($app . '/new-file.php'), 'A file absent before update was not removed.');

    echo "Updater rollback regression tests passed.\n";
} finally {
    rollbackRemoveTree($root);
}
