<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use ZipArchive;

final class UpdateManager
{
    private const REPOSITORY = 'BTM-SA/SentryIQ';
    private const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
    private const CACHE_TTL = 21600;

    public function __construct(
        private readonly string $applicationRoot,
        private readonly string $dataDir,
        private readonly ?string $sigstoreAutoloadPath = null,
    ) {
        if ($this->applicationRoot === '' || !str_starts_with($this->applicationRoot, '/') || !is_dir($this->applicationRoot)) {
            throw new RuntimeException('Invalid SentryIQ application root.');
        }
        if ($this->dataDir === '' || !str_starts_with($this->dataDir, '/') || !is_dir($this->dataDir) || is_link($this->dataDir)) {
            throw new RuntimeException('Invalid SentryIQ secure data directory.');
        }
    }

    public function currentVersion(): string
    {
        $path = $this->applicationRoot . '/VERSION';
        $version = is_file($path) && !is_link($path) ? trim((string)@file_get_contents($path)) : '';
        return $this->normalizeVersion($version);
    }

    public function checkLatest(bool $force = false): array
    {
        $cachePath = $this->dataDir . '/update_check.json';
        if (!$force && is_file($cachePath) && !is_link($cachePath)) {
            $cached = json_decode((string)@file_get_contents($cachePath), true);
            if (is_array($cached) && (int)($cached['checked_at'] ?? 0) + self::CACHE_TTL > time()) {
                return $cached;
            }
        }

        try {
            $release = $this->httpJson('https://api.github.com/repos/' . self::REPOSITORY . '/releases/latest');
        } catch (RuntimeException $exception) {
            if (str_starts_with($exception->getMessage(), 'github_http_status:404')) {
                return [
                    'checked_at' => time(),
                    'current_version' => $this->currentVersion(),
                    'latest_version' => $this->currentVersion(),
                    'update_available' => false,
                    'release_available' => false,
                    'name' => '',
                    'published_at' => '',
                    'html_url' => '',
                    'body' => '',
                    'tag_name' => '',
                    'assets' => [],
                    'message' => 'No stable SentryIQ release has been published yet.',
                ];
            }
            throw $exception;
        }

        if (($release['draft'] ?? false) || ($release['prerelease'] ?? false)) {
            throw new RuntimeException('No stable SentryIQ release is currently available.');
        }

        $latest = $this->normalizeVersion((string)($release['tag_name'] ?? ''));
        if ($latest === '') throw new RuntimeException('The SentryIQ release version is invalid.');

        $result = [
            'checked_at' => time(),
            'current_version' => $this->currentVersion(),
            'latest_version' => $latest,
            'update_available' => version_compare($latest, $this->currentVersion(), '>'),
            'name' => trim((string)($release['name'] ?? ('SentryIQ ' . $latest))),
            'published_at' => (string)($release['published_at'] ?? ''),
            'html_url' => (string)($release['html_url'] ?? ''),
            'body' => (string)($release['body'] ?? ''),
            'tag_name' => (string)($release['tag_name'] ?? ''),
            'assets' => is_array($release['assets'] ?? null) ? $release['assets'] : [],
        ];

        $temporary = $cachePath . '.tmp-' . bin2hex(random_bytes(8));
        if (@file_put_contents($temporary, json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR), LOCK_EX) !== false) {
            @chmod($temporary, 0600);
            @rename($temporary, $cachePath);
            @chmod($cachePath, 0600);
        } else {
            @unlink($temporary);
        }

        return $result;
    }

    public function applyLatest(): array
    {
        $lockPath = $this->dataDir . '/update.lock';
        $handle = @fopen($lockPath, 'c');
        if ($handle === false || !@flock($handle, LOCK_EX | LOCK_NB)) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Another SentryIQ update is already running.');
        }

        try {
            $release = $this->checkLatest(true);
            $current = $this->currentVersion();
            $latest = (string)($release['latest_version'] ?? '');
            if ($latest === '' || !version_compare($latest, $current, '>')) {
                throw new RuntimeException('SentryIQ is already up to date.');
            }

            $assets = $release['assets'] ?? [];
            $packageAsset = $this->findAsset($assets, 'sentryiq-' . $latest . '.zip');
            $checksumAsset = $this->findAsset($assets, 'sentryiq-' . $latest . '.zip.sha256');
            if ($packageAsset === null || $checksumAsset === null) {
                throw new RuntimeException('The release package or checksum is missing.');
            }

            $updatesRoot = $this->dataDir . '/updates';
            $downloadRoot = $updatesRoot . '/downloads';
            $stagingRoot = $updatesRoot . '/staging';
            if (!$this->ensureDirectory($downloadRoot, 0700) || !$this->ensureDirectory($stagingRoot, 0700)) {
                throw new RuntimeException('Unable to prepare the secure update workspace.');
            }

            $nonce = bin2hex(random_bytes(8));
            $zipPath = $downloadRoot . '/sentryiq-' . $latest . '-' . $nonce . '.zip';
            $checksumPath = $zipPath . '.sha256';
            $stagingPath = $stagingRoot . '/sentryiq-' . $latest . '-' . $nonce;

            $this->download((string)($packageAsset['browser_download_url'] ?? ''), $zipPath);
            $this->download((string)($checksumAsset['browser_download_url'] ?? ''), $checksumPath);

            $expectedHash = trim((string)@file_get_contents($checksumPath));
            if (!preg_match('/^([a-f0-9]{64})\s+(?:\*|\S+)\s*$/i', $expectedHash, $matches)) {
                throw new RuntimeException('The release checksum file is invalid.');
            }
            $actualHash = hash_file('sha256', $zipPath);
            if (!is_string($actualHash) || !hash_equals(strtolower($matches[1]), strtolower($actualHash))) {
                throw new RuntimeException('The release package checksum does not match.');
            }

            // Cryptographic provenance verification MUST precede ZIP extraction.
            if ($this->sigstoreAutoloadPath === null || $this->sigstoreAutoloadPath === '') {
                throw new RuntimeException('Native Sigstore verification is not configured; refusing to install an unattested release.');
            }
            require_once __DIR__ . '/TufRootStore.php';
            require_once __DIR__ . '/ReleaseTrustPolicy.php';
            require_once __DIR__ . '/SigstoreProvenance.php';
            require_once __DIR__ . '/NativeSigstoreReleaseVerifier.php';
            $nativeVerifier = new NativeSigstoreReleaseVerifier($this->sigstoreAutoloadPath, $this->dataDir);
            $verifiedClaims = $nativeVerifier->verifyRelease($zipPath, $latest);
            $trustPolicy = new ReleaseTrustPolicy();
            $trustPolicy->assertTrustedRelease(
                $verifiedClaims,
                $latest,
                (string)($verifiedClaims['source_commit'] ?? ''),
                $actualHash,
                $current,
            );

            $this->extractAndValidate($zipPath, $stagingPath, $latest);
            $manifest = json_decode((string)@file_get_contents($stagingPath . '/update-manifest.json'), true);
            if (!is_array($manifest) || (string)($manifest['version'] ?? '') !== $latest) {
                throw new RuntimeException('The update manifest is invalid.');
            }

            $publicFiles = $this->filesUnder($stagingPath, '', static fn(string $relative): bool => $relative !== 'update-manifest.json' && !str_starts_with($relative, 'runtime/'));
            $runtimeFiles = $this->filesUnder($stagingPath . '/runtime', '', static fn(string $relative): bool => preg_match('/^[a-z0-9_.-]+\.php$/i', $relative) === 1);

            if ($publicFiles === [] || $runtimeFiles === []) {
                throw new RuntimeException('The release package is incomplete.');
            }

            $backupRoot = $updatesRoot . '/backups/' . date('Ymd-His') . '-' . $current . '-to-' . $latest . '-' . $nonce;
            if (!$this->ensureDirectory($backupRoot, 0700) || !$this->ensureDirectory($backupRoot . '/public', 0700) || !$this->ensureDirectory($backupRoot . '/runtime', 0700)) {
                throw new RuntimeException('Unable to prepare the update backup.');
            }

            $backedPublic = [];
            $backedRuntime = [];
            try {
                foreach ($publicFiles as $relative) {
                    $source = $stagingPath . '/' . $relative;
                    $target = $this->applicationRoot . '/' . $relative;
                    if (is_link($target)) throw new RuntimeException('Refusing to update a symbolic link: ' . $relative);
                    if (is_file($target)) {
                        $backup = $backupRoot . '/public/' . $relative;
                        $this->ensureDirectory(dirname($backup), 0700);
                        if (!@copy($target, $backup)) throw new RuntimeException('Unable to back up ' . $relative . '.');
                        $backedPublic[$relative] = true;
                    }
                    $this->ensureDirectory(dirname($target), 0755);
                }

                foreach ($runtimeFiles as $relative) {
                    $source = $stagingPath . '/runtime/' . $relative;
                    $target = $this->dataDir . '/' . $relative;
                    if (is_link($target)) throw new RuntimeException('Refusing to update a symbolic runtime file: ' . $relative);
                    if (is_file($target)) {
                        $backup = $backupRoot . '/runtime/' . $relative;
                        $this->ensureDirectory(dirname($backup), 0700);
                        if (!@copy($target, $backup)) throw new RuntimeException('Unable to back up runtime file ' . $relative . '.');
                        $backedRuntime[$relative] = true;
                    }
                }

                foreach ($publicFiles as $relative) {
                    $this->replaceFile($stagingPath . '/' . $relative, $this->applicationRoot . '/' . $relative);
                }
                foreach ($runtimeFiles as $relative) {
                    $this->replaceFile($stagingPath . '/runtime/' . $relative, $this->dataDir . '/' . $relative, 0600);
                }

                $this->invalidateOpcache($publicFiles, $runtimeFiles);
                $installed = $this->currentVersion();
                if ($installed !== $latest) {
                    throw new RuntimeException('The application version could not be verified after update.');
                }

                $this->pruneBackups($updatesRoot . '/backups', 2);
                @unlink($zipPath);
                @unlink($checksumPath);
                $this->removeDirectory($stagingPath);

                return [
                    'status' => 'updated',
                    'from' => $current,
                    'to' => $latest,
                    'backup' => basename($backupRoot),
                ];
            } catch (\Throwable $exception) {
                foreach ($publicFiles as $relative) {
                    $target = $this->applicationRoot . '/' . $relative;
                    if (isset($backedPublic[$relative])) {
                        $this->replaceFile($backupRoot . '/public/' . $relative, $target);
                    } elseif (is_file($target) && !is_link($target)) {
                        @unlink($target);
                    }
                }
                foreach ($runtimeFiles as $relative) {
                    $target = $this->dataDir . '/' . $relative;
                    if (isset($backedRuntime[$relative])) {
                        $this->replaceFile($backupRoot . '/runtime/' . $relative, $target, 0600);
                    } elseif (is_file($target) && !is_link($target)) {
                        @unlink($target);
                    }
                }
                $this->invalidateOpcache($publicFiles, $runtimeFiles);
                throw $exception;
            }
        } finally {
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    private function normalizeVersion(string $value): string
    {
        $value = trim($value);
        if (str_starts_with($value, 'v')) $value = substr($value, 1);
        return preg_match('/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/', $value) ? $value : '';
    }

    private function httpJson(string $url): array
    {
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL is required for update checks.');
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER => ['Accept: application/vnd.github+json', 'User-Agent: SentryIQ-Updater/1.0'],
        ]);
        $body = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if (!is_string($body) || $status < 200 || $status >= 300) {
            throw new RuntimeException('github_http_status:' . $status . ($error !== '' ? ' ' . $error : ''));
        }
        $data = json_decode($body, true);
        if (!is_array($data)) throw new RuntimeException('GitHub returned an invalid release response.');
        return $data;
    }

    private function download(string $url, string $target): void
    {
        if (!preg_match('#^https://github\.com/#i', $url)) throw new RuntimeException('Update download source is not trusted.');
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL is required for application updates.');
        $fp = @fopen($target, 'wb');
        if ($fp === false) throw new RuntimeException('Unable to create the update download.');
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_HTTPHEADER => ['User-Agent: SentryIQ-Updater/1.0'],
            CURLOPT_FAILONERROR => true,
            CURLOPT_MAXFILESIZE => self::MAX_DOWNLOAD_BYTES,
        ]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        fclose($fp);
        if ($ok !== true || $status < 200 || $status >= 300) {
            @unlink($target);
            throw new RuntimeException('SentryIQ update download failed.' . ($error !== '' ? ' ' . $error : ''));
        }
        $size = @filesize($target);
        if ($size === false || $size <= 0 || $size > self::MAX_DOWNLOAD_BYTES) {
            @unlink($target);
            throw new RuntimeException('The downloaded update is too large or empty.');
        }
    }

    private function findAsset(array $assets, string $name): ?array
    {
        foreach ($assets as $asset) {
            if (!is_array($asset)) continue;
            if ((string)($asset['name'] ?? '') === $name) return $asset;
        }
        return null;
    }

    private function extractAndValidate(string $zipPath, string $destination, string $expectedVersion): void
    {
        if (!class_exists(ZipArchive::class)) throw new RuntimeException('PHP ZipArchive is required for application updates.');
        $zip = new ZipArchive();
        if ($zip->open($zipPath) !== true) throw new RuntimeException('Unable to open the SentryIQ update package.');
        try {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $entry = $zip->getNameIndex($i);
                if (!is_string($entry) || $entry === '' || str_starts_with($entry, '/') || str_contains(str_replace('\\', '/', $entry), '../')) {
                    throw new RuntimeException('The update package contains an invalid path.');
                }
            }
            if (!$this->ensureDirectory($destination, 0700) || !$zip->extractTo($destination)) {
                throw new RuntimeException('Unable to extract the SentryIQ update package.');
            }
        } finally {
            $zip->close();
        }
        $manifestPath = $destination . '/update-manifest.json';
        if (!is_file($manifestPath) || is_link($manifestPath)) throw new RuntimeException('The update manifest is missing.');
        $manifest = json_decode((string)@file_get_contents($manifestPath), true);
        if (!is_array($manifest) || $this->normalizeVersion((string)($manifest['version'] ?? '')) !== $expectedVersion) {
            throw new RuntimeException('The update package version is invalid.');
        }
    }

    private function filesUnder(string $root, string $prefix, callable $filter): array
    {
        if (!is_dir($root) || is_link($root)) return [];
        $result = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_FILEINFO),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || !$file->isFile() || $file->isLink()) throw new RuntimeException('The update package contains an invalid file.');
            $relative = $prefix . str_replace('\\', '/', $iterator->getSubPathname());
            if ($filter($relative)) $result[] = $relative;
        }
        sort($result);
        return $result;
    }

    private function replaceFile(string $source, string $target, int $mode = 0644): void
    {
        $dir = dirname($target);
        if (!$this->ensureDirectory($dir, 0755)) throw new RuntimeException('Unable to create update target directory.');
        $temporary = $target . '.update-' . bin2hex(random_bytes(8));
        if (!@copy($source, $temporary)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to stage update file: ' . basename($target));
        }
        @chmod($temporary, $mode);
        if (!@rename($temporary, $target)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to activate update file: ' . basename($target));
        }
        @chmod($target, $mode);
    }

    private function ensureDirectory(string $directory, int $mode): bool
    {
        if ($directory === '' || is_link($directory)) return false;
        if (is_dir($directory)) return true;
        return @mkdir($directory, $mode, true) || is_dir($directory);
    }

    private function invalidateOpcache(array $publicFiles, array $runtimeFiles): void
    {
        if (!function_exists('opcache_invalidate')) return;
        foreach ($publicFiles as $relative) {
            $path = $this->applicationRoot . '/' . $relative;
            @opcache_invalidate($path, true);
        }
        foreach ($runtimeFiles as $relative) {
            @opcache_invalidate($this->dataDir . '/' . $relative, true);
        }
    }

    private function pruneBackups(string $root, int $keep): void
    {
        if (!is_dir($root)) return;
        $entries = array_values(array_filter(scandir($root) ?: [], static fn(string $v): bool => $v !== '.' && $v !== '..' && is_dir($root . '/' . $v)));
        rsort($entries, SORT_STRING);
        foreach (array_slice($entries, $keep) as $entry) $this->removeDirectory($root . '/' . $entry);
    }

    private function removeDirectory(string $directory): void
    {
        if (!is_dir($directory) || is_link($directory)) return;
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($iterator as $file) {
            $path = $file->getPathname();
            if ($file->isDir() && !$file->isLink()) @rmdir($path);
            else @unlink($path);
        }
        @rmdir($directory);
    }
}
