<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;

/**
 * Confined read-only target byte resolver.
 *
 * Authorization is deliberately separate: callers must supply the exact target
 * paths produced by an independently verified TUF metadata/delegation walk.
 */
final class BootstrapTargetStore
{
    private const MAX_TARGET_BYTES = 16 * 1024 * 1024;

    private readonly string $root;

    public function __construct(string $targetRoot)
    {
        $real = realpath($targetRoot);
        if ($real === false || !is_dir($real) || is_link($targetRoot)
            || (((fileperms($real) ?: 0) & 0077) !== 0)
            || !self::outsideDocumentRoot($real)) {
            throw new RuntimeException('Bootstrap target storage must be a private directory outside the document root.');
        }
        $this->root = rtrim($real, DIRECTORY_SEPARATOR);
    }

    /**
     * @param list<string> $authorizedTargetPaths exact paths from verified signed TUF metadata
     */
    public function read(string $relativePath, array $authorizedTargetPaths): string
    {
        if (!self::validRelativePath($relativePath)
            || !array_is_list($authorizedTargetPaths)
            || !in_array($relativePath, $authorizedTargetPaths, true)) {
            throw new RuntimeException('Bootstrap target is not authorized.');
        }

        $path = $this->root;
        $segments = explode('/', $relativePath);
        foreach ($segments as $index => $segment) {
            $path .= DIRECTORY_SEPARATOR . $segment;
            $stat = @lstat($path);
            if (!is_array($stat) || (($stat['mode'] & 0170000) === 0120000) {
                throw new RuntimeException('Bootstrap target path contains a missing entry or symbolic link.');
            }
            if ($index < count($segments) - 1 && (($stat['mode'] & 0170000) !== 0040000)) {
                throw new RuntimeException('Bootstrap target parent is not a directory.');
            }
        }

        $real = realpath($path);
        if ($real === false || !str_starts_with($real, $this->root . DIRECTORY_SEPARATOR)
            || !is_file($real) || is_link($path)) {
            throw new RuntimeException('Bootstrap target escaped its private store or is not a regular file.');
        }
        $size = filesize($real);
        if (!is_int($size) || $size < 1 || $size > self::MAX_TARGET_BYTES) {
            throw new RuntimeException('Bootstrap target is empty or exceeds the size limit.');
        }
        $bytes = @file_get_contents($real);
        if (!is_string($bytes) || strlen($bytes) !== $size) {
            throw new RuntimeException('Bootstrap target read was incomplete.');
        }
        return $bytes;
    }

    public static function validRelativePath(string $path): bool
    {
        if ($path === '' || strlen($path) > 512 || str_starts_with($path, '/') ||
            str_ends_with($path, '/') || str_contains($path, '//') ||
            str_contains($path, '\\') || str_contains($path, "\0") ||
            !preg_match('~^[A-Za-z0-9._/-]+$~D', $path)) {
            return false;
        }
        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..' || $segment === '') return false;
        }
        return true;
    }

    private static function outsideDocumentRoot(string $directory): bool
    {
        $documentRoot = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
        if ($documentRoot === '') return PHP_SAPI === 'cli';
        $realRoot = realpath($documentRoot);
        if ($realRoot === false || !is_dir($realRoot)) return false;
        $root = rtrim($realRoot, DIRECTORY_SEPARATOR);
        return $directory !== $root && !str_starts_with($directory, $root . DIRECTORY_SEPARATOR);
    }
}
