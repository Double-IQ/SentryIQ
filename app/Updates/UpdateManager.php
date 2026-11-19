<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use ZipArchive;

require_once __DIR__ . '/ReleaseTrustPolicy.php';
require_once __DIR__ . '/GitHubCliAttestationVerifier.php';
require_once __DIR__ . '/ReleaseDownloadPolicy.php';
require_once dirname(__DIR__) . '/Security/SecurityBootstrap.php';

final class UpdateManager
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';
    private const ALLOWED_RUNTIME_FILES = ['email_template.php', 'vault_engine.php', 'vault_icon_cache.php', 'VaultKdfPolicy.php'];
    private const MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024;
    private const MAX_API_BYTES = 2 * 1024 * 1024;
    private const MAX_ARCHIVE_ENTRIES = 5000;
    private const MAX_EXTRACTED_BYTES = 250 * 1024 * 1024;
    private const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
    private const CACHE_TTL = 21600;

    private readonly ?GitHubCliAttestationVerifier $attestationVerifier;
    private readonly ?string $sigstoreAutoloadPath;
    /** @var callable|null Test seam for GitHub API responses. */
    private $httpJsonRunner;
    /** @var callable|null Test seam for release asset downloads; never set in production. */
    private $downloadRunner;

    public function __construct(
        private readonly string $applicationRoot,
        private readonly string $dataDir,
        ?GitHubCliAttestationVerifier $attestationVerifier = null,
        ?callable $httpJsonRunner = null,
        ?callable $downloadRunner = null,
        ?string $sigstoreAutoloadPath = null,
    ) {
        if ($this->applicationRoot === '' || !str_starts_with($this->applicationRoot, '/') || !is_dir($this->applicationRoot)) {
            throw new RuntimeException('Invalid SentryIQ application root.');
        }
        if ($this->dataDir === '' || !str_starts_with($this->dataDir, '/') || !is_dir($this->dataDir) || is_link($this->dataDir)) {
            throw new RuntimeException('Invalid SentryIQ secure data directory.');
        }
        if (!sentryiq_path_is_outside_document_root($this->dataDir)) {
            throw new RuntimeException('SentryIQ secure data directory must resolve outside the public web root.');
        }
        $this->attestationVerifier = $attestationVerifier;
        if ($sigstoreAutoloadPath !== null && $sigstoreAutoloadPath !== '') {
            $realDataDirectory = realpath($this->dataDir);
            $realAutoloadPath = realpath($sigstoreAutoloadPath);
            if (!is_string($realDataDirectory) || !is_string($realAutoloadPath)
                || is_link($sigstoreAutoloadPath) || !is_file($realAutoloadPath) || !is_readable($realAutoloadPath)
                || $realAutoloadPath !== $sigstoreAutoloadPath
                || !str_starts_with($realAutoloadPath, rtrim($realDataDirectory, '/') . DIRECTORY_SEPARATOR)) {
                throw new RuntimeException('Native Sigstore Composer dependencies must be a canonical file inside the private data directory.');
            }
            $this->sigstoreAutoloadPath = $realAutoloadPath;
        } else {
            $this->sigstoreAutoloadPath = null;
        }
        $this->httpJsonRunner = $httpJsonRunner;
        $this->downloadRunner = $downloadRunner;
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

        $zipPath = null;
        $checksumPath = null;
        $stagingPath = null;

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

            // The adjacent checksum is only transport integrity. Trust comes from
            // GitHub's cryptographic attestation, checked against the independently
            // resolved immutable tag commit and the local ZIP digest.
            $expectedCommit = $this->verifyReleaseArtifact($zipPath, $latest, $current);

            $this->extractAndValidate($zipPath, $stagingPath, $latest);
            $manifest = json_decode((string)@file_get_contents($stagingPath . '/update-manifest.json'), true);
            if (!is_array($manifest)) {
                throw new RuntimeException('The update manifest is invalid.');
            }
            $this->assertManifestMatchesPackage($manifest, $stagingPath, $latest, $expectedCommit);

            $publicFiles = $this->filesUnder($stagingPath, '', static fn(string $relative): bool => $relative !== 'update-manifest.json' && !str_starts_with($relative, 'runtime/'));
            $runtimeFiles = $this->filesUnder($stagingPath . '/runtime', '', static fn(string $relative): bool => preg_match('/^[a-z0-9_.-]+\\.php$/i', $relative) === 1);

            if ($publicFiles === [] || $runtimeFiles === []) {
                throw new RuntimeException('The release package is incomplete.');
            }

            $backupRoot = $updatesRoot . '/backups/' . date('Ymd-His') . '-' . $current . '-to-' . $latest . '-' . $nonce;
            if (!$this->ensureDirectory($backupRoot, 0700) || !$this->ensureDirectory($backupRoot . '/public', 0700) || !$this->ensureDirectory($backupRoot . '/runtime', 0700)) {
                throw new RuntimeException('Unable to prepare the update backup.');
            }

            $backedPublic = [];
            $backedRuntime = [];
            $originalPublic = [];
            $originalRuntime = [];
            $replacementStarted = false;
            try {
                // Snapshot every target before preparing any backup. A missing backup
                // must never be mistaken for a file that did not exist originally.
                foreach ($publicFiles as $relative) {
                    $target = $this->applicationRoot . '/' . $relative;
                    if (is_link($target)) throw new RuntimeException('Refusing to update a symbolic link: ' . $relative);
                    $originalPublic[$relative] = file_exists($target);
                    if ($originalPublic[$relative] && !is_file($target)) {
                        throw new RuntimeException('Refusing to replace a non-file target: ' . $relative);
                    }
                    if (!$this->ensureDirectory(dirname($target), 0755)) {
                        throw new RuntimeException('Unable to prepare update target directory: ' . $relative);
                    }
                }
                foreach ($runtimeFiles as $relative) {
                    $target = $this->dataDir . '/' . $relative;
                    if (is_link($target)) throw new RuntimeException('Refusing to update a symbolic runtime file: ' . $relative);
                    $originalRuntime[$relative] = file_exists($target);
                    if ($originalRuntime[$relative] && !is_file($target)) {
                        throw new RuntimeException('Refusing to replace a non-file runtime target: ' . $relative);
                    }
                }

                // Complete all backups before the first live file is changed.
                foreach ($publicFiles as $relative) {
                    if (!$originalPublic[$relative]) continue;
                    $target = $this->applicationRoot . '/' . $relative;
                    $backup = $backupRoot . '/public/' . $relative;
                    if (!$this->ensureDirectory(dirname($backup), 0700) || !$this->copyAndVerifyBackup($target, $backup)) {
                        throw new RuntimeException('Unable to create and verify backup for ' . $relative . '.');
                    }
                    $backedPublic[$relative] = true;
                }
                foreach ($runtimeFiles as $relative) {
                    if (!$originalRuntime[$relative]) continue;
                    $target = $this->dataDir . '/' . $relative;
                    $backup = $backupRoot . '/runtime/' . $relative;
                    if (!$this->ensureDirectory(dirname($backup), 0700) || !$this->copyAndVerifyBackup($target, $backup)) {
                        throw new RuntimeException('Unable to create and verify runtime backup for ' . $relative . '.');
                    }
                    $backedRuntime[$relative] = true;
                }

                // No live file is touched until every required backup succeeds.
                $replacementStarted = true;

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
                if ($replacementStarted) {
                    $rollbackErrors = [];
                    $rollbackErrors = array_merge(
                        $rollbackErrors,
                        $this->rollbackTargets($publicFiles, $originalPublic, $backedPublic, $this->applicationRoot, $backupRoot . '/public', 0644)
                    );
                    $rollbackErrors = array_merge(
                        $rollbackErrors,
                        $this->rollbackTargets($runtimeFiles, $originalRuntime, $backedRuntime, $this->dataDir, $backupRoot . '/runtime', 0600)
                    );
                    $this->invalidateOpcache($publicFiles, $runtimeFiles);
                    if ($rollbackErrors !== []) {
                        throw new RuntimeException(
                            'The update failed and rollback was incomplete. Preserve backup ' . basename($backupRoot) . ' and restore it before reopening the application. Details: ' . implode('; ', $rollbackErrors),
                            0,
                            $exception
                        );
                    }
                }
                // Backup-preparation failures occur before any live replacement.
                // Keep original files untouched and retain the partial backup.
                throw $exception;
            }
        } finally {
            $this->cleanupWorkspaceArtifacts($zipPath, $checksumPath, $stagingPath);
            @flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Remove only this update attempt's temporary download and staging artifacts.
     * The separately-created backup directory is intentionally retained on failure.
     */
    private function cleanupWorkspaceArtifacts(?string $zipPath, ?string $checksumPath, ?string $stagingPath): void
    {
        foreach ([$zipPath, $checksumPath] as $file) {
            if ($file !== null && is_file($file) && !is_link($file)) {
                @unlink($file);
            }
        }
        if ($stagingPath !== null && is_dir($stagingPath) && !is_link($stagingPath)) {
            $this->removeDirectory($stagingPath);
        }
    }

    /**
     * Resolve the release tag to its immutable commit independently of the
     * attestation payload, then require the configured GitHub CLI verifier.
     */
    private function verifyReleaseArtifact(string $artifactPath, string $version, string $installedVersion): string
    {
        $expectedCommit = $this->resolveReleaseCommit($version);
        if ($this->sigstoreAutoloadPath !== null) {
            require_once __DIR__ . '/TufRootStore.php';
            require_once __DIR__ . '/FulcioCertificateClaims.php';
            require_once __DIR__ . '/SnappyBlockDecoder.php';
            require_once __DIR__ . '/SigstoreProvenance.php';
            require_once __DIR__ . '/NativeSigstoreReleaseVerifier.php';
            $verifier = new NativeSigstoreReleaseVerifier($this->sigstoreAutoloadPath, $this->dataDir);
            $claims = $verifier->verifyRelease($artifactPath, $version);
            $digest = hash_file('sha256', $artifactPath);
            if (!is_string($digest)) {
                throw new RuntimeException('Unable to calculate the downloaded release artifact digest.');
            }
            (new ReleaseTrustPolicy())->assertTrustedRelease(
                $claims,
                $version,
                $expectedCommit,
                $digest,
                $installedVersion
            );
            return $expectedCommit;
        }
        if ($this->attestationVerifier !== null) {
            $this->attestationVerifier->assertTrustedArtifact(
                $artifactPath,
                $version,
                $expectedCommit,
                $installedVersion
            );
            return $expectedCommit;
        }
        throw new RuntimeException('Native Sigstore verification is not configured; refusing to install an unattested release.');
    }

    /**
     * Resolve lightweight and annotated Git tags without trusting the
     * mutable target_commitish field returned by the Releases API.
     */
    private function resolveReleaseCommit(string $version): string
    {
        $version = $this->normalizeVersion($version);
        if ($version === '') {
            throw new RuntimeException('Cannot resolve an invalid SentryIQ release tag.');
        }

        $expectedRef = 'refs/tags/v' . $version;
        $reference = $this->httpJson(
            'https://api.github.com/repos/' . self::REPOSITORY . '/git/ref/tags/v' . $version
        );
        if ((string)($reference['ref'] ?? '') !== $expectedRef) {
            throw new RuntimeException('GitHub returned a different release tag reference.');
        }
        $object = $reference['object'] ?? null;
        if (!is_array($object)) {
            throw new RuntimeException('GitHub release tag reference is malformed.');
        }

        for ($depth = 0; $depth < 5; $depth++) {
            $sha = strtolower((string)($object['sha'] ?? ''));
            $type = (string)($object['type'] ?? '');
            if (!preg_match('/^[a-f0-9]{40}$/', $sha)) {
                throw new RuntimeException('GitHub release tag contains an invalid Git object SHA.');
            }
            if ($type === 'commit') {
                return $sha;
            }
            if ($type !== 'tag') {
                throw new RuntimeException('GitHub release tag does not resolve to a commit.');
            }
            $tagObject = $this->httpJson(
                'https://api.github.com/repos/' . self::REPOSITORY . '/git/tags/' . $sha
            );
            if ((string)($tagObject['tag'] ?? '') !== 'v' . $version) {
                throw new RuntimeException('GitHub annotated tag name does not match the requested release.');
            }
            $object = $tagObject['object'] ?? null;
            if (!is_array($object)) {
                throw new RuntimeException('GitHub annotated release tag is malformed.');
            }
        }

        throw new RuntimeException('GitHub release tag has too many nested tag objects.');
    }

    /**
     * Verify every file against the manifest embedded in the attested ZIP.
     * The manifest itself is bound by the ZIP's verified subject digest.
     *
     * @param array<string, mixed> $manifest
     */
    private function assertManifestMatchesPackage(
        array $manifest,
        string $stagingRoot,
        string $version,
        string $expectedCommit
    ): void {
        if (($manifest['format'] ?? null) !== 2
            || (string)($manifest['repository'] ?? '') !== self::REPOSITORY
            || (string)($manifest['repository_id'] ?? '') !== self::REPOSITORY_ID
            || (string)($manifest['version'] ?? '') !== $version
            || strtolower((string)($manifest['commit'] ?? '')) !== $expectedCommit
            || (string)($manifest['workflow_path'] ?? '') !== self::WORKFLOW_PATH) {
            throw new RuntimeException('The attested release manifest identity does not match this release.');
        }

        $entries = $manifest['files'] ?? null;
        if (!is_array($entries) || $entries === [] || !array_is_list($entries)) {
            throw new RuntimeException('The release manifest file inventory is invalid.');
        }

        $root = realpath($stagingRoot);
        if ($root === false || !is_dir($root) || is_link($stagingRoot)) {
            throw new RuntimeException('The extracted release directory is invalid.');
        }

        $expectedPaths = [];
        $expectedPublic = [];
        $expectedRuntime = [];
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                throw new RuntimeException('The release manifest contains an invalid file entry.');
            }
            $relative = $entry['path'] ?? null;
            $size = $entry['size'] ?? null;
            $digest = strtolower((string)($entry['sha256'] ?? ''));
            $segments = is_string($relative) ? explode('/', $relative) : [];
            if (!is_string($relative)
                || $relative === ''
                || str_contains($relative, '\\')
                || str_contains($relative, "\0")
                || preg_match('/[\x00-\x1F\x7F]/', $relative)
                || str_starts_with($relative, '/')
                || preg_match('/^[a-zA-Z]:/', $relative)
                || in_array('.', $segments, true)
                || in_array('..', $segments, true)
                || in_array('', $segments, true)
                || $relative === 'update-manifest.json'
                || isset($expectedPaths[$relative])
                || !is_int($size)
                || $size < 0
                || !preg_match('/^[a-f0-9]{64}$/', $digest)) {
                throw new RuntimeException('The release manifest contains an unsafe or duplicate file entry.');
            }

            $filePath = $root . '/' . $relative;
            $realFile = realpath($filePath);
            if ($realFile === false
                || !is_file($realFile)
                || is_link($filePath)
                || !str_starts_with($realFile, $root . DIRECTORY_SEPARATOR)) {
                throw new RuntimeException('A manifest-listed release file is missing or escapes the staging directory.');
            }
            $actualSize = filesize($realFile);
            $actualDigest = hash_file('sha256', $realFile);
            if ($actualSize !== $size || !is_string($actualDigest) || !hash_equals($digest, strtolower($actualDigest))) {
                throw new RuntimeException('A release file does not match its attested manifest entry: ' . $relative);
            }

            $expectedPaths[$relative] = true;
            if (str_starts_with($relative, 'runtime/')) {
                $runtimeName = substr($relative, strlen('runtime/'));
                if ($runtimeName === '' || str_contains($runtimeName, '/')) {
                    throw new RuntimeException('Runtime release files must be top-level PHP templates.');
                }
                $expectedRuntime[] = $runtimeName;
            } else {
                $expectedPublic[] = $relative;
            }
        }

        $actualPaths = $this->filesUnder(
            $stagingRoot,
            '',
            static fn(string $relative): bool => $relative !== 'update-manifest.json'
        );
        sort($actualPaths, SORT_STRING);
        $manifestPaths = array_keys($expectedPaths);
        sort($manifestPaths, SORT_STRING);
        if ($actualPaths !== $manifestPaths) {
            throw new RuntimeException('The extracted package contains files outside the attested manifest inventory.');
        }

        $manifestPublic = $manifest['public_files'] ?? null;
        $manifestRuntime = $manifest['runtime_files'] ?? null;
        if (!is_array($manifestPublic) || !is_array($manifestRuntime)
            || !array_is_list($manifestPublic) || !array_is_list($manifestRuntime)) {
            throw new RuntimeException('The release manifest public/runtime file lists are invalid.');
        }
        sort($expectedPublic, SORT_STRING);
        sort($expectedRuntime, SORT_STRING);
        $listedPublic = $manifestPublic;
        $listedRuntime = $manifestRuntime;
        sort($listedPublic, SORT_STRING);
        sort($listedRuntime, SORT_STRING);
        $allowedRuntime = self::ALLOWED_RUNTIME_FILES;
        sort($allowedRuntime, SORT_STRING);
        if ($listedPublic !== $expectedPublic
            || $listedRuntime !== $expectedRuntime
            || $expectedRuntime !== $allowedRuntime) {
            throw new RuntimeException('The release manifest file allowlist does not match the approved package layout.');
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
        if ($this->httpJsonRunner !== null) {
            $result = ($this->httpJsonRunner)($url);
            if (!is_array($result)) {
                throw new RuntimeException('GitHub API test runner returned an invalid response.');
            }
            return $result;
        }
        if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL is required for update checks.');
        $parts = parse_url($url);
        if (($parts['scheme'] ?? '') !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'api.github.com'
            || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && (int)$parts['port'] !== 443)
            || isset($parts['fragment'])) {
            throw new RuntimeException('Update API request is outside the approved GitHub API origin.');
        }

        $body = '';
        $ch = curl_init($url);
        if ($ch === false) throw new RuntimeException('Unable to initialize the GitHub update API request.');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2026-03-10', 'User-Agent: SentryIQ-Updater/1.0'],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > self::MAX_API_BYTES) return 0;
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        if ($ok !== true || $status < 200 || $status >= 300 || $body === '') {
            throw new RuntimeException('github_http_status:' . $status . ($error !== '' ? ' ' . $error : ''));
        }
        try {
            $data = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('GitHub returned invalid release JSON.', 0, $exception);
        }
        if (!is_array($data)) throw new RuntimeException('GitHub returned an invalid release response.');
        return $data;
    }

    private function download(string $url, string $target): void
    {
        ReleaseDownloadPolicy::assertAllowedUrl($url);
        if (strtolower((string)(parse_url($url, PHP_URL_HOST) ?? '')) !== 'github.com') {
            throw new RuntimeException('Initial update download URL must use github.com.');
        }
        if (file_exists($target) || is_link($target)) {
            throw new RuntimeException('Update download target already exists or is unsafe.');
        }

        if ($this->downloadRunner !== null) {
            $ok = ($this->downloadRunner)($url, $target);
            if ($ok !== true || !is_file($target) || is_link($target)) {
                @unlink($target);
                throw new RuntimeException('SentryIQ update download failed.');
            }
        } else {
            if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL is required for application updates.');
            $fp = @fopen($target, 'xb');
            if ($fp === false) throw new RuntimeException('Unable to create the update download.');
            $ch = curl_init($url);
            if ($ch === false) {
                fclose($fp);
                @unlink($target);
                throw new RuntimeException('Unable to initialize the SentryIQ update download.');
            }
            $downloaded = 0;
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_TIMEOUT => 120,
                CURLOPT_CONNECTTIMEOUT => 15,
                CURLOPT_HTTPHEADER => ['User-Agent: SentryIQ-Updater/1.0'],
                CURLOPT_FAILONERROR => true,
                CURLOPT_MAXFILESIZE => self::MAX_DOWNLOAD_BYTES,
                CURLOPT_HEADERFUNCTION => static function ($handle, string $header): int {
                    if (stripos($header, 'Location:') === 0) {
                        $location = trim(substr($header, strlen('Location:')));
                        if (!ReleaseDownloadPolicy::isAllowedUrl($location)) return 0;
                    }
                    return strlen($header);
                },
                CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use ($fp, &$downloaded): int {
                    $length = strlen($chunk);
                    if ($downloaded + $length > self::MAX_DOWNLOAD_BYTES) return 0;
                    $written = fwrite($fp, $chunk);
                    if (!is_int($written) || $written !== $length) return 0;
                    $downloaded += $written;
                    return $written;
                },
            ]);
            $ok = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $effectiveUrl = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
            $error = curl_error($ch);
            curl_close($ch);
            $flushed = fflush($fp);
            fclose($fp);
            if ($ok !== true || $status < 200 || $status >= 300
                || !ReleaseDownloadPolicy::isAllowedUrl($effectiveUrl) || !$flushed) {
                @unlink($target);
                throw new RuntimeException('SentryIQ update download failed.' . ($error !== '' ? ' ' . $error : ''));
            }
        }

        $size = @filesize($target);
        if ($size === false || $size <= 0 || $size > self::MAX_DOWNLOAD_BYTES) {
            @unlink($target);
            throw new RuntimeException('The downloaded update is too large or empty.');
        }
    }

    private function download(string $url, string $target): void
    {
        if (!preg_match('#^https://github\.com/#i', $url)) throw new RuntimeException('Update download source is not trusted.');
        if ($this->downloadRunner !== null) {
            $ok = ($this->downloadRunner)($url, $target);
            if ($ok !== true) {
                @unlink($target);
                throw new RuntimeException('SentryIQ update download failed.');
            }
        } else {
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

    /**
     * Restore targets after replacement has started.
     *
     * Existing targets are restored only from a successfully completed backup.
     * A missing backup is an error, never evidence that the target was new.
     * Targets absent in the pre-update snapshot may be removed.
     *
     * @return list<string> Rollback errors; all targets are attempted.
     */
    private function rollbackTargets(
        array $files,
        array $originallyExisted,
        array $backedUp,
        string $targetRoot,
        string $backupRoot,
        int $mode
    ): array {
        $errors = [];
        foreach ($files as $relative) {
            $target = $targetRoot . '/' . $relative;
            if (($originallyExisted[$relative] ?? false) === true) {
                if (!isset($backedUp[$relative])) {
                    $errors[] = 'Missing completed backup for existing file ' . $relative;
                    continue;
                }
                try {
                    $this->replaceFile($backupRoot . '/' . $relative, $target, $mode);
                } catch (\Throwable $exception) {
                    $errors[] = 'Unable to restore ' . $relative . ': ' . $exception->getMessage();
                }
                continue;
            }

            if (is_link($target)) {
                $errors[] = 'Refusing to remove symbolic link created during update: ' . $relative;
                continue;
            }
            if (is_file($target) && !@unlink($target)) {
                $errors[] = 'Unable to remove newly created file ' . $relative;
            } elseif (file_exists($target) && !is_file($target)) {
                $errors[] = 'Refusing to remove non-file target created during update: ' . $relative;
            }
        }
        return $errors;
    }

    private function copyAndVerifyBackup(string $source, string $destination): bool
    {
        if (is_link($source) || !is_file($source) || file_exists($destination) || is_link($destination)) {
            return false;
        }
        if (!@copy($source, $destination)) {
            @unlink($destination);
            return false;
        }
        $sourceHash = @hash_file('sha256', $source);
        $backupHash = @hash_file('sha256', $destination);
        $sourceSize = @filesize($source);
        $backupSize = @filesize($destination);
        if (!is_string($sourceHash) || !is_string($backupHash)
            || !is_int($sourceSize) || !is_int($backupSize)
            || $sourceSize !== $backupSize || !hash_equals($sourceHash, $backupHash)) {
            @unlink($destination);
            return false;
        }
        if (!@chmod($destination, 0600)) {
            @unlink($destination);
            return false;
        }
        $permissions = @fileperms($destination);
        if (!is_int($permissions) || ($permissions & 0777) !== 0600) {
            @unlink($destination);
            return false;
        }
        return true;
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
