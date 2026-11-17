<?php

declare(strict_types=1);

/**
 * Resolves first-run paths from app/Security without assuming that the
 * account home directory and public web root are the same directory.
 */
final class FirstRunPaths
{
    public static function accountRoot(string $securityDirectory): string
    {
        return rtrim(dirname($securityDirectory, 3), '/');
    }

    public static function dataDirectory(string $securityDirectory): string
    {
        return self::accountRoot($securityDirectory) . '/private_data';
    }

    public static function bundledPrivateDirectory(string $securityDirectory): string
    {
        return rtrim(dirname($securityDirectory, 2), '/') . '/runtime';
    }

    /**
     * Return the known sibling private Composer autoloader when it is present.
     * An absent or unsafe dependency directory leaves updates disabled; the
     * updater itself fails closed until a valid path is configured.
     */
    public static function sigstoreAutoload(string $securityDirectory): string
    {
        $accountRoot = self::accountRoot($securityDirectory);
        $dependencyDirectory = $accountRoot . '/sentryiq-tuf-patched-private';
        $vendorDirectory = $dependencyDirectory . '/vendor';
        $autoload = $vendorDirectory . '/autoload.php';
        $publicRoot = rtrim(dirname($securityDirectory, 2), '/') . '/';

        if (is_link($accountRoot) || is_link($dependencyDirectory) || is_link($vendorDirectory) || is_link($autoload)
            || !is_dir($vendorDirectory) || !is_file($autoload) || !is_readable($autoload)) {
            return '';
        }

        $resolved = realpath($autoload);
        $resolvedPublicRoot = realpath(rtrim($publicRoot, '/'));
        if (!is_string($resolved) || $resolved === ''
            || (is_string($resolvedPublicRoot) && str_starts_with($resolved, rtrim($resolvedPublicRoot, '/') . '/'))) {
            return '';
        }

        return $resolved;
    }
}
