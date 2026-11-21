<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use RuntimeException;

/**
 * Shared transaction lock for operations spanning the keyring and object index.
 * Every upload reservation, commit, envelope replacement and final key retirement
 * must use this same lock to make the final reference check authoritative.
 */
final class GalleryRotationLock
{
    public static function synchronized(string $directory, callable $operation): mixed
    {
        if ($directory === '' || !str_starts_with($directory, '/') || !is_dir($directory) || is_link($directory)) {
            throw new RuntimeException('Gallery rotation lock directory is invalid.');
        }
        $realDirectory = realpath($directory);
        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if ($realDirectory === false
            || (is_string($documentRoot) && $documentRoot !== ''
                && ($realDirectory === $documentRoot
                    || str_starts_with($realDirectory . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
            throw new RuntimeException('Gallery rotation lock must be outside the public web root.');
        }

        $lockPath = $realDirectory . DIRECTORY_SEPARATOR . 'gallery_rotation.lock';
        if (is_link($lockPath)) throw new RuntimeException('Gallery rotation lock is invalid.');
        $handle = @fopen($lockPath, 'c');
        if ($handle === false) throw new RuntimeException('Unable to acquire Gallery rotation lock.');
        @chmod($lockPath, 0600);
        try {
            if (!flock($handle, LOCK_EX)) throw new RuntimeException('Unable to acquire Gallery rotation lock.');
            return $operation();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
