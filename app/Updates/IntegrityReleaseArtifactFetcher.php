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
    public function fetch(string $releaseVersion, string $privateDirectory): array
    {
        $version = trim($releaseVersion);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Release asset version must use stable MAJOR.MINOR.PATCH format.');
        }

        $directory = $this->ensurePrivateDirectory($privateDirectory);
        @chmod($directory, 0700);

        $manifest = $directory . '/release-manifest.json';
        $artifact = $directory . '/sentryiq-' . $version . '.zip';
        $this->download(self::RELEASE_BASE . 'v' . $version . '/release-manifest.json', $manifest, 5_000_000);
        $this->download(self::RELEASE_BASE . 'v' . $version . '/sentryiq-' . $version . '.zip', $artifact, 250_000_000);

        return ['manifest_path' => $manifest, 'artifact_path' => $artifact];
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
                    || isset($parts['user']) || isset($parts['pass'])) {
                    throw new RuntimeException('Release asset URL is outside the HTTPS GitHub host allowlist.');
                }

                $stream = @fopen($temporary, 'xb');
                if ($stream === false) {
                    throw new RuntimeException('Unable to create private release download file.');
                }
                @chmod($temporary, 0600);
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
                fclose($stream);

                if ($ok === true && $status === 200 && $written > 0) {
                    if (!@rename($temporary, $destination)) {
                        throw new RuntimeException('Unable to atomically publish downloaded release asset.');
                    }
                    @chmod($destination, 0600);
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
