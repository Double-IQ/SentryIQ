<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Downloads the canonical release manifest and ZIP into private node storage.
 * The caller must still verify both files with NativeSigstoreIntegrityAttestationVerifier
 * before trusting either file or using the manifest as expected state.
 */
final class IntegrityReleaseArtifactFetcher
{
    private const RELEASE_BASE = 'https://github.com/Double-IQ/SentryIQ/releases/download/';
    private const REDIRECT_HOSTS = [
        'github.com',
        'release-assets.githubusercontent.com',
        'objects.githubusercontent.com',
    ];

    /** @return array{manifest_path:string,artifact_path:string} */
    public function fetch(string $releaseVersion, string $privateDirectory, string $publicRoot): array
    {
        $version = trim($releaseVersion);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Release asset version must use stable MAJOR.MINOR.PATCH format.');
        }

        if ($publicRoot === '' || !str_starts_with($publicRoot, DIRECTORY_SEPARATOR) || is_link($publicRoot)) {
            throw new RuntimeException('A real public webroot path is required to protect release staging.');
        }
        $realPublicRoot = realpath($publicRoot);
        if (!is_string($realPublicRoot) || !is_dir($realPublicRoot)) {
            throw new RuntimeException('Configured public webroot cannot be resolved.');
        }
        $requestedDirectory = preg_replace('#/+#', '/', $privateDirectory);
        if (!is_string($requestedDirectory) || preg_match('~(^|/)\\.\\.?(/|$)~', $requestedDirectory)
            || $requestedDirectory === $realPublicRoot
            || str_starts_with($requestedDirectory, rtrim($realPublicRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Release staging directory must be outside the public webroot.');
        }
        $directory = $this->ensurePrivateDirectory($privateDirectory);
        if ($directory === $realPublicRoot
            || str_starts_with($directory, rtrim($realPublicRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
            || basename(dirname($directory)) !== 'integrity-releases') {
            throw new RuntimeException('Release staging directory must be an integrity-releases child outside the public webroot.');
        }
        $releaseRoot = dirname($directory);
        if (!@chmod($releaseRoot, 0700) || !@chmod($directory, 0700)) {
            throw new RuntimeException('Unable to enforce private release staging directory permissions.');
        }
        foreach ([$releaseRoot, $directory] as $privatePath) {
            clearstatcache(true, $privatePath);
            $privateStat = @lstat($privatePath);
            if (!is_array($privateStat) || (($privateStat['mode'] ?? 0) & 0170000) !== 0040000
                || (($privateStat['mode'] ?? 0) & 0777) !== 0700) {
                throw new RuntimeException('Release staging directories must be real exact 0700 directories.');
            }
        }

        $manifest = $directory . '/release-manifest.json';
        $artifact = $directory . '/sentryiq-' . $version . '.zip';
        $metadata = $directory . '/.integrity-cache.json';
        if (!$this->isReusableCache($version, $manifest, $artifact, $metadata)) {
            $this->download(self::RELEASE_BASE . 'v' . $version . '/release-manifest.json', $manifest, 5_000_000);
            $this->download(self::RELEASE_BASE . 'v' . $version . '/sentryiq-' . $version . '.zip', $artifact, 250_000_000);
            $manifestDigest = @hash_file('sha256', $manifest);
            $artifactDigest = @hash_file('sha256', $artifact);
            if (!is_string($manifestDigest) || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
                || !is_string($artifactDigest) || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
                throw new RuntimeException('Unable to fingerprint staged release artifacts for safe cache reuse.');
            }
            $this->writeCacheMetadata($metadata, $version, $manifestDigest, $artifactDigest);
        }
        $this->pruneOldVersionDirectories($releaseRoot, $version);

        return ['manifest_path' => $manifest, 'artifact_path' => $artifact];
    }

    private function isReusableCache(string $version, string $manifest, string $artifact, string $metadataPath): bool
    {
        if (is_link($manifest) || is_link($artifact) || is_link($metadataPath)) {
            throw new RuntimeException('Release artifact cache must not contain symlinks.');
        }
        if (!is_file($manifest) || !is_file($artifact) || !is_file($metadataPath)) return false;

        foreach ([[$manifest, 5_000_000], [$artifact, 250_000_000], [$metadataPath, 1024]] as [$path, $maximum]) {
            clearstatcache(true, $path);
            $stat = @lstat($path);
            if (!is_array($stat) || (($stat['mode'] ?? 0) & 0170000) !== 0100000
                || (($stat['mode'] ?? 0) & 0777) !== 0600) {
                throw new RuntimeException('Release artifact cache file type or permissions are unsafe.');
            }
            if (($stat['size'] ?? 0) < 1 || ($stat['size'] ?? 0) > $maximum) return false;
        }

        $raw = @file_get_contents($metadataPath);
        if (!is_string($raw) || $raw === '') return false;
        try {
            $metadata = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            return false;
        }
        if (!is_array($metadata) || array_is_list($metadata)) return false;
        $keys = array_keys($metadata);
        sort($keys);
        $expectedKeys = ['artifact_sha256', 'manifest_sha256', 'schema_version', 'version'];
        sort($expectedKeys);
        if ($keys !== $expectedKeys || ($metadata['schema_version'] ?? null) !== 1
            || ($metadata['version'] ?? null) !== $version
            || !is_string($metadata['manifest_sha256'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $metadata['manifest_sha256'])
            || !is_string($metadata['artifact_sha256'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $metadata['artifact_sha256'])) {
            return false;
        }
        $manifestDigest = @hash_file('sha256', $manifest);
        $artifactDigest = @hash_file('sha256', $artifact);
        return is_string($manifestDigest) && is_string($artifactDigest)
            && hash_equals($metadata['manifest_sha256'], $manifestDigest)
            && hash_equals($metadata['artifact_sha256'], $artifactDigest);
    }

    private function writeCacheMetadata(string $path, string $version, string $manifestDigest, string $artifactDigest): void
    {
        if (is_link($path)) throw new RuntimeException('Release artifact cache metadata must not be a symlink.');
        $bytes = json_encode([
            'schema_version' => 1,
            'version' => $version,
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\\n";
        $temporary = $path . '.tmp-' . bin2hex(random_bytes(8));
        $handle = @fopen($temporary, 'x+b');
        if ($handle === false) throw new RuntimeException('Unable to create release artifact cache metadata.');
        $ok = @chmod($temporary, 0600);
        $offset = 0;
        while ($ok && $offset < strlen($bytes)) {
            $written = @fwrite($handle, substr($bytes, $offset));
            if (!is_int($written) || $written < 1) {
                $ok = false;
                break;
            }
            $offset += $written;
        }
        if ($ok) $ok = @fflush($handle);
        if ($ok && function_exists('fsync')) $ok = @fsync($handle);
        $stat = @fstat($handle);
        $ok = $ok && is_array($stat) && (($stat['mode'] ?? 0) & 0170000) === 0100000
            && (($stat['mode'] ?? 0) & 0777) === 0600 && $offset === strlen($bytes);
        fclose($handle);
        if (!$ok || !@rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to atomically publish release artifact cache metadata.');
        }
        if (!@chmod($path, 0600)) {
            @unlink($path);
            throw new RuntimeException('Unable to enforce release artifact cache metadata permissions.');
        }
        clearstatcache(true, $path);
        $final = @lstat($path);
        if (!is_array($final) || (($final['mode'] ?? 0) & 0170000) !== 0100000
            || (($final['mode'] ?? 0) & 0777) !== 0600) {
            @unlink($path);
            throw new RuntimeException('Release artifact cache metadata permissions are unsafe.');
        }
    }

    private function pruneOldVersionDirectories(string $releaseRoot, string $currentVersion): void
    {
        $entries = @scandir($releaseRoot);
        if (!is_array($entries)) throw new RuntimeException('Unable to enumerate private release cache directories.');
        $versions = [];
        foreach ($entries as $entry) {
            if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $entry)) continue;
            $path = $releaseRoot . DIRECTORY_SEPARATOR . $entry;
            clearstatcache(true, $path);
            $stat = @lstat($path);
            if (!is_array($stat) || (($stat['mode'] ?? 0) & 0170000) !== 0040000
                || (($stat['mode'] ?? 0) & 0777) !== 0700 || is_link($path)) {
                throw new RuntimeException('Release cache version directory has unsafe type or permissions.');
            }
            $versions[] = $entry;
        }
        usort($versions, static fn(string $left, string $right): int => version_compare($right, $left));
        $keep = array_slice(array_values(array_unique(array_merge([$currentVersion], $versions)), 0, 3);
        foreach ($versions as $version) {
            if (in_array($version, $keep, true)) continue;
            $path = $releaseRoot . DIRECTORY_SEPARATOR . $version;
            $allowed = ['release-manifest.json', 'sentryiq-' . $version . '.zip', '.integrity-cache.json'];
            $files = @scandir($path);
            if (!is_array($files)) continue;
            $safeToDelete = true;
            foreach ($files as $file) {
                if ($file === '.' || $file === '..') continue;
                if (!in_array($file, $allowed, true)) {
                    $safeToDelete = false;
                    break;
                }
                $filePath = $path . DIRECTORY_SEPARATOR . $file;
                clearstatcache(true, $filePath);
                $fileStat = @lstat($filePath);
                if (!is_array($fileStat) || (($fileStat['mode'] ?? 0) & 0170000) !== 0100000
                    || (($fileStat['mode'] ?? 0) & 0777) !== 0600) {
                    $safeToDelete = false;
                    break;
                }
            }
            if (!$safeToDelete) continue;
            foreach ($allowed as $file) {
                $filePath = $path . DIRECTORY_SEPARATOR . $file;
                if (file_exists($filePath) && !@unlink($filePath)) {
                    $safeToDelete = false;
                    break;
                }
            }
            if ($safeToDelete) @rmdir($path);
        }
    }

    /**
     * Create the staging path while rejecting symlinks in every existing
     * component, not merely at the final directory.
     */
    private function ensurePrivateDirectory(string $path): string
    {
        if ($path === '' || !str_starts_with($path, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Release staging directory must be an absolute path.');
        }
        $parts = array_values(array_filter(explode(DIRECTORY_SEPARATOR, $path), static fn(string $part): bool => $part !== ''));
        if ($parts === []) {
            throw new RuntimeException('Release staging directory cannot be the filesystem root.');
        }
        $current = DIRECTORY_SEPARATOR;
        foreach ($parts as $part) {
            if ($part === '.' || $part === '..') {
                throw new RuntimeException('Release staging path must not contain dot segments.');
            }
            $current = rtrim($current, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $part;
            if (is_link($current)) {
                throw new RuntimeException('Release staging path must not contain symlink components.');
            }
            if (file_exists($current)) {
                if (!is_dir($current)) {
                    throw new RuntimeException('Release staging path component is not a directory.');
                }
                continue;
            }
            if (!@mkdir($current, 0700) && !is_dir($current)) {
                throw new RuntimeException('Unable to create private release staging directory.');
            }
            if (is_link($current) || !is_dir($current)) {
                throw new RuntimeException('Release staging path changed during directory creation.');
            }
        }
        $resolved = realpath($current);
        if (!is_string($resolved) || !is_dir($resolved)) {
            throw new RuntimeException('Private release staging directory is invalid.');
        }
        return $resolved;
    }

    private function download(string $url, string $destination, int $maxBytes): void
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required to fetch release assets.');
        }
        $temporary = $destination . '.tmp-' . bin2hex(random_bytes(8));
        $current = $url;
        try {
            for ($redirect = 0; $redirect <= 3; $redirect++) {
                $parts = parse_url($current);
                $host = strtolower((string)($parts['host'] ?? ''));
                if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
                    || !in_array($host, self::REDIRECT_HOSTS, true)
                    || (isset($parts['port']) && $parts['port'] !== 443)
                    || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
                    throw new RuntimeException('Release asset URL is outside the HTTPS GitHub host allowlist.');
                }

                $stream = @fopen($temporary, 'xb');
                if ($stream === false) {
                    throw new RuntimeException('Unable to create private release download file.');
                }
                if (!@chmod($temporary, 0600)) {
                    fclose($stream);
                    @unlink($temporary);
                    throw new RuntimeException('Unable to enforce private release artifact file permissions.');
                }
                $openedTemporaryStat = @fstat($stream);
                if (!is_array($openedTemporaryStat) || (($openedTemporaryStat['mode'] ?? 0) & 0170000) !== 0100000
                    || (($openedTemporaryStat['mode'] ?? 0) & 0777) !== 0600) {
                    fclose($stream);
                    @unlink($temporary);
                    throw new RuntimeException('Release artifact temporary file permissions are unsafe.');
                }
                $location = null;
                $written = 0;
                $handle = curl_init($current);
                if ($handle === false) {
                    fclose($stream);
                    throw new RuntimeException('Unable to initialize release asset download.');
                }
                curl_setopt_array($handle, [
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_CONNECTTIMEOUT => 10,
                    CURLOPT_TIMEOUT => 90,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                    CURLOPT_USERAGENT => 'SentryIQ-Integrity-Node/1.0',
                    CURLOPT_HEADERFUNCTION => static function ($curl, string $header) use (&$location): int {
                        if (stripos($header, 'Location:') === 0) {
                            $location = trim(substr($header, 9));
                        }
                        return strlen($header);
                    },
                    CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use ($stream, &$written, $maxBytes): int {
                        $length = strlen($chunk);
                        if ($written + $length > $maxBytes) return 0;
                        $count = fwrite($stream, $chunk);
                        if ($count === false) return 0;
                        $written += $count;
                        return $count;
                    },
                ]);
                $ok = curl_exec($handle);
                $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
                curl_close($handle);
                $flushed = @fflush($stream);
                $synced = !function_exists('fsync') || @fsync($stream);
                fclose($stream);

                if ($ok === true && $status === 200 && $written > 0 && $flushed && $synced) {
                    if (!@rename($temporary, $destination)) {
                        throw new RuntimeException('Unable to atomically publish downloaded release asset.');
                    }
                    if (!@chmod($destination, 0600)) {
                        @unlink($destination);
                        throw new RuntimeException('Unable to enforce downloaded release artifact permissions.');
                    }
                    clearstatcache(true, $destination);
                    $destinationStat = @lstat($destination);
                    if (!is_array($destinationStat) || (($destinationStat['mode'] ?? 0) & 0170000) !== 0100000
                        || (($destinationStat['mode'] ?? 0) & 0777) !== 0600) {
                        @unlink($destination);
                        throw new RuntimeException('Downloaded release artifact permissions are unsafe.');
                    }
                    return;
                }

                @unlink($temporary);
                if ($status >= 300 && $status < 400 && is_string($location) && $location !== '' && $redirect < 3) {
                    $current = $this->resolveLocation($current, $location);
                    continue;
                }
                throw new RuntimeException('Release asset download failed or exceeded its size limit.');
            }
        } finally {
            if (is_file($temporary)) @unlink($temporary);
        }
        throw new RuntimeException('Release asset exceeded the redirect limit.');
    }

    private function resolveLocation(string $current, string $location): string
    {
        if (str_starts_with($location, 'https://')) return $location;
        if (str_starts_with($location, '/')) {
            $parts = parse_url($current);
            return 'https://' . strtolower((string)$parts['host']) . $location;
        }
        throw new RuntimeException('Release asset redirect must use an absolute HTTPS URL or root-relative path.');
    }
}
