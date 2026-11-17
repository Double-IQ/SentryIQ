<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Selects only byte-for-byte static public assets for HTTP hash comparison.
 * Dynamic PHP endpoints are never compared with their packaged source bytes.
 * Every selected path must also exist in the signed public_files and files inventories.
 */
final class IntegrityPublicAssetPolicy
{
    private const STATIC_EXTENSIONS = [
        'css', 'js', 'mjs', 'json', 'webmanifest', 'svg', 'png', 'jpg',
        'jpeg', 'gif', 'webp', 'avif', 'ico', 'woff', 'woff2', 'ttf',
        'otf', 'eot', 'txt', 'xml', 'pdf', 'wasm', 'map', 'html',
    ];

    /**
     * @param array<string,array{path:string,size:int,sha256:string}> $entries
     * @param list<string> $configuredPaths Optional explicit subset. Empty means all signed static public assets.
     * @return list<string>
     */
    public static function resolve(array $manifest, array $entries, array $configuredPaths): array
    {
        if (!array_is_list($configuredPaths)) {
            throw new RuntimeException('Configured public asset paths must be a list.');
        }

        $publicFiles = $manifest['public_files'] ?? null;
        $publicFileSet = null;
        if ($publicFiles !== null) {
            if (!is_array($publicFiles) || !array_is_list($publicFiles)) {
                throw new RuntimeException('Release manifest public file inventory is invalid.');
            }
            foreach ($publicFiles as $publicPath) {
                if (!is_string($publicPath) || !self::isSafePath($publicPath)) {
                    throw new RuntimeException('Release manifest contains an unsafe public file path.');
                }
            }
            $publicFileSet = array_fill_keys($publicFiles, true);
        }

        $manifestPaths = $manifest['public_http_files'] ?? null;
        if ($manifestPaths === null) {
            // Backward compatibility for older format-2 manifests: derive the
            // static set from the signed public_files inventory.
            $manifestPaths = $manifest['public_files'] ?? array_keys($entries);
            if (!is_array($manifestPaths) || !array_is_list($manifestPaths)) {
                throw new RuntimeException('Release manifest public file inventory is invalid.');
            }
            $manifestPaths = array_values(array_filter(
                $manifestPaths,
                static fn(mixed $path): bool => is_string($path)
                    && !str_starts_with($path, 'runtime/')
                    && self::isStaticPath($path)
            ));
        }
        if (!is_array($manifestPaths) || !array_is_list($manifestPaths)) {
            throw new RuntimeException('Release manifest static public asset inventory is invalid.');
        }

        $allowed = [];
        foreach ($manifestPaths as $path) {
            if (!is_string($path) || !self::isSafePath($path) || !self::isStaticPath($path)
                || str_starts_with($path, 'runtime/') || !isset($entries[$path])
                || ($publicFileSet !== null && !isset($publicFileSet[$path])) || isset($allowed[$path])) {
                throw new RuntimeException('Release manifest contains an unsafe, dynamic or unknown public HTTP asset path.');
            }
            $allowed[$path] = true;
        }

        $selected = $configuredPaths === [] ? array_keys($allowed) : $configuredPaths;
        foreach ($selected as $path) {
            if (!is_string($path) || !self::isSafePath($path) || !isset($allowed[$path])) {
                throw new RuntimeException('Configured public path is not in the signed static-asset allowlist.');
            }
        }
        if (count($selected) > 99) {
            throw new RuntimeException('Release manifest exceeds the signed event evidence path limit.');
        }
        if ($selected === []) {
            throw new RuntimeException('Release manifest contains no byte-verifiable public static assets.');
        }
        return array_values(array_unique($selected));
    }

    private static function isStaticPath(string $path): bool
    {
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        return $extension !== '' && in_array($extension, self::STATIC_EXTENSIONS, true);
    }

    private static function isSafePath(string $path): bool
    {
        return $path !== '' && strlen($path) <= 512 && !str_starts_with($path, '/')
            && !str_contains($path, '\\') && !str_contains($path, '//') && !preg_match('~(^|/)\.\.?(/|$)~', $path)
            && !preg_match('/[%?#\\x00-\\x1f]/', $path);
    }
}
