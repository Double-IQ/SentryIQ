<?php

declare(strict_types=1);

require_once __DIR__ . '/../cloud/Gallery/Storage/GalleryRotationLock.php';

use SentryIQCloud\Gallery\Storage\GalleryRotationLock;

$directory = sys_get_temp_dir() . '/sentryiq-gallery-lock-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700, true)) throw new RuntimeException('Unable to create Gallery lock test directory.');

try {
    $result = GalleryRotationLock::synchronized($directory, static fn(): string => 'locked');
    if ($result !== 'locked') throw new RuntimeException('Gallery shared lock did not return the operation result.');

    $lockPath = $directory . '/gallery_rotation.lock';
    $permissions = fileperms($lockPath);
    if (!is_int($permissions) || (($permissions & 0077) !== 0)) {
        throw new RuntimeException('Gallery shared lock must be owner-only.');
    }

    try {
        GalleryRotationLock::synchronized($directory, static function (): void {
            throw new RuntimeException('expected operation failure');
        });
        throw new RuntimeException('Gallery shared lock must propagate operation failures.');
    } catch (RuntimeException $exception) {
        if ($exception->getMessage() !== 'expected operation failure') throw $exception;
    }

    $again = GalleryRotationLock::synchronized($directory, static fn(): bool => true);
    if ($again !== true) throw new RuntimeException('Gallery shared lock was not released after an exception.');

    echo "Gallery shared rotation lock tests passed.\n";
} finally {
    @unlink($directory . '/gallery_rotation.lock');
    @rmdir($directory);
}
