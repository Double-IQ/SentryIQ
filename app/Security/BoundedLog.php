<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;
use Throwable;

final class BoundedLog
{
    public static function append(string $path, string $line, int $maxBytes = 1048576, int $retained = 2): void
    {
        if ($path === '' || !str_starts_with($path, '/') || $maxBytes < 1024 || $maxBytes > 10485760
            || $retained < 1 || $retained > 5 || strlen($line) > $maxBytes) {
            throw new RuntimeException('Bounded log parameters are invalid.');
        }
        $directory = dirname($path);
        $realDirectory = realpath($directory);
        if ($realDirectory === false || is_link($directory) || rtrim($realDirectory, '/') !== rtrim($directory, '/')) {
            throw new RuntimeException('Bounded log directory is not canonical.');
        }
        if (function_exists('sentryiq_path_is_outside_document_root')
            && !\sentryiq_path_is_outside_document_root($directory)) {
            throw new RuntimeException('Bounded logs must be stored outside the public web root.');
        }

        self::withLock($path . '.lock', function () use ($path, $line, $maxBytes, $retained): void {
            if (is_link($path)) throw new RuntimeException('Log path must not be a symbolic link.');
            if (file_exists($path) && !is_file($path)) throw new RuntimeException('Log path is not a regular file.');
            $currentSize = is_file($path) ? (int)@filesize($path) : 0;
            if ($currentSize + strlen($line) > $maxBytes) {
                for ($index = $retained; $index >= 1; $index--) {
                    $source = $index === 1 ? $path : $path . '.' . ($index - 1);
                    $target = $path . '.' . $index;
                    if (is_link($source) || is_link($target)) {
                        throw new RuntimeException('Log rotation encountered a symbolic link.');
                    }
                    if (is_file($target) && !@unlink($target)) {
                        throw new RuntimeException('Unable to prune rotated log.');
                    }
                    if (is_file($source)) {
                        if (!@rename($source, $target)) throw new RuntimeException('Unable to rotate log.');
                        @chmod($target, 0600);
                    }
                }
            }

            if (is_link($path)) throw new RuntimeException('Log path must not be a symbolic link.');
            $handle = @fopen($path, 'ab');
            if ($handle === false) throw new RuntimeException('Unable to open bounded log.');
            try {
                $opened = fstat($handle);
                $linked = @lstat($path);
                if (!is_array($opened) || !is_array($linked)
                    || (($linked['mode'] & 0170000) !== 0100000)
                    || $opened['dev'] !== $linked['dev']
                    || $opened['ino'] !== $linked['ino']) {
                    throw new RuntimeException('Log path changed unexpectedly.');
                }
                @chmod($path, 0600);
                $written = fwrite($handle, $line);
                if (!is_int($written) || $written !== strlen($line) || !fflush($handle)) {
                    throw new RuntimeException('Unable to append bounded log.');
                }
                if (function_exists('fsync')) @fsync($handle);
            } finally {
                fclose($handle);
            }
        });
    }

    private static function withLock(string $lockPath, callable $callback): void
    {
        if (is_link($lockPath)) throw new RuntimeException('Log lock must not be a symbolic link.');
        $handle = @fopen($lockPath, 'c');
        if ($handle === false) throw new RuntimeException('Unable to open log lock.');
        try {
            $opened = fstat($handle);
            $linked = @lstat($lockPath);
            if (!is_array($opened) || !is_array($linked)
                || (($linked['mode'] & 0170000) !== 0100000)
                || $opened['dev'] !== $linked['dev']
                || $opened['ino'] !== $linked['ino']) {
                throw new RuntimeException('Log lock path changed unexpectedly.');
            }
            @chmod($lockPath, 0600);
            if (!flock($handle, LOCK_EX)) throw new RuntimeException('Unable to lock log.');
            $callback();
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
