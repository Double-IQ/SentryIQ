<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TrustedRoot;
use K2gl\Tuf\HttpFetcher;
use K2gl\Tuf\Updater;
use RuntimeException;
use Throwable;

/**
 * Verifies a release ZIP using the native PHP Sigstore verifier and Sigstore
 * TUF trust metadata. No shell, exec, proc_open, or GitHub CLI is used.
 */
final class NativeSigstoreReleaseVerifier
{
    private const API_BASE = 'https://api.github.com';
    private const TUF_METADATA_URL = 'https://tuf-repo-cdn.sigstore.dev';
    private const TUF_TARGETS_URL = 'https://tuf-repo-cdn.sigstore.dev/targets';
    private const MAX_API_BYTES = 2_000_000;
    private const MAX_BUNDLE_BYTES = 8_000_000;
    private const SIGSTORE_VERIFY_VERSION = '1.6.1';
    private const TUF_VERSION = '1.2.1';

    private readonly TufRootStore $rootStore;

    public function __construct(string $vendorAutoloadPath, string $privateDataDirectory)
    {
        if ($vendorAutoloadPath === '' || !str_starts_with($vendorAutoloadPath, '/')
            || is_link($vendorAutoloadPath) || !is_file($vendorAutoloadPath) || !is_readable($vendorAutoloadPath)) {
            throw new RuntimeException('A readable private Sigstore Composer autoload.php path is required.');
        }
        if (!is_dir($privateDataDirectory) || is_link($privateDataDirectory)) {
            throw new RuntimeException('The private SentryIQ data directory is unavailable.');
        }

        require_once $vendorAutoloadPath;
        foreach ([Bundle::class, SigstoreVerifier::class, TrustedRoot::class, Updater::class] as $class) {
            if (!class_exists($class)) {
                throw new RuntimeException('The configured private vendor directory is missing a required Sigstore/TUF class.');
            }
        }
        if (!class_exists(\Composer\InstalledVersions::class)
            || \Composer\InstalledVersions::getPrettyVersion('k2gl/sigstore-verify') !== self::SIGSTORE_VERIFY_VERSION
            || \Composer\InstalledVersions::getPrettyVersion('k2gl/tuf') !== self::TUF_VERSION) {
            throw new RuntimeException('Private Sigstore dependencies do not match the pinned verifier and patched TUF versions.');
        }

        $storeDirectory = rtrim($privateDataDirectory, '/') . '/sigstore-tuf';
        if (!is_dir($storeDirectory) && !@mkdir($storeDirectory, 0700)) {
            throw new RuntimeException('Unable to create the private Sigstore TUF root directory.');
        }
        if (is_link($storeDirectory) || !is_dir($storeDirectory) || !is_writable($storeDirectory)) {
            throw new RuntimeException('The private Sigstore TUF root directory is unsafe or not writable.');
        }
        @chmod($storeDirectory, 0700);
        $this->rootStore = new TufRootStore($storeDirectory);
    }

    /**
     * @return array<string, mixed> authenticated and policy-ready claims
     */
    public function verifyRelease(string $zipPath, string $version): array
    {
        if (!is_file($zipPath) || is_link($zipPath) || !is_readable($zipPath)) {
            throw new RuntimeException('The downloaded release ZIP is unavailable.');
        }
        $digest = hash_file('sha256', $zipPath);
        if (!is_string($digest) || preg_match('/^[a-f0-9]{64}$/', $digest) !== 1) {
            throw new RuntimeException('Unable to calculate the release ZIP SHA-256 digest.');
        }

        $tagCommit = $this->resolveTagCommit($version);
        $attestations = $this->fetchAttestations($digest);
        $trustedRoot = $this->refreshTrustedRoot();

        $identity = IdentityPolicy::githubActions(
            SigstoreProvenance::REPOSITORY,
            SigstoreProvenance::WORKFLOW_PATH,
            'refs/tags/v' . $version,
        );
        $verifier = new SigstoreVerifier();
        $lastFailure = null;

        foreach ($attestations as $entry) {
            if (!is_array($entry) || (string)($entry['repository_id'] ?? '') !== SigstoreProvenance::REPOSITORY_ID) {
                continue;
            }
            $bundleUrl = $entry['bundle_url'] ?? null;
            if (!is_string($bundleUrl) || $bundleUrl === '') {
                continue;
            }

            try {
                $bundleJson = $this->httpsGet($bundleUrl, self::MAX_BUNDLE_BYTES, 'blob');
                $bundle = Bundle::fromJson($bundleJson);
                $envelope = $verifier->verify($bundle, $trustedRoot, $identity);
                $claims = SigstoreProvenance::claims($envelope, $version, $digest);
                if (!hash_equals($tagCommit, $claims['source_commit'])) {
                    throw new RuntimeException('Attested source commit does not match the current immutable Git tag resolution.');
                }
                return $claims;
            } catch (Throwable $exception) {
                $lastFailure = $exception;
            }
        }

        throw new RuntimeException(
            'No GitHub attestation for this repository passed native Sigstore and SLSA provenance verification.'
            . ($lastFailure !== null ? ' ' . $lastFailure->getMessage() : ''),
            0,
            $lastFailure,
        );
    }

    private function refreshTrustedRoot(): TrustedRoot
    {
        $root = $this->rootStore->load();
        if ($root === null) {
            $bootstrap = dirname((new ReflectionClass(TrustedRoot::class))->getFileName()) . '/../resources/sigstore-tuf-root.json';
            $bootstrap = realpath($bootstrap) ?: '';
            if ($bootstrap === '' || !is_file($bootstrap) || is_link($bootstrap) || !is_readable($bootstrap)) {
                throw new RuntimeException('The pinned Sigstore TUF bootstrap root is missing from the private vendor package.');
            }
            $root = file_get_contents($bootstrap);
            if (!is_string($root) || $root === '') {
                throw new RuntimeException('Unable to read the pinned Sigstore TUF bootstrap root.');
            }
        }

        $updater = new Updater(
            $root,
            self::TUF_METADATA_URL,
            self::TUF_TARGETS_URL,
            new HttpFetcher(20),
        );
        // fromTuf() completes TUF refresh and verifies trusted_root.json target
        // hashes before it returns. Persist only after that complete operation.
        $trustedRoot = TrustedRoot::fromTuf($updater);
        $verifiedRootBytes = $updater->getTrustedRootBytes();
        if (!is_string($verifiedRootBytes) || $verifiedRootBytes === '') {
            throw new RuntimeException('TUF updater did not expose verified root metadata bytes.');
        }
        $this->rootStore->storeVerifiedRoot($verifiedRootBytes);
        return $trustedRoot;
    }

    private function resolveTagCommit(string $version): string
    {
        $data = $this->githubApi('/repos/' . SigstoreProvenance::REPOSITORY . '/commits/v' . rawurlencode($version));
        $sha = strtolower((string)($data['sha'] ?? ''));
        if (preg_match('/^[a-f0-9]{40}$/', $sha) !== 1) {
            throw new RuntimeException('GitHub did not resolve the release tag to a full commit SHA.');
        }
        return $sha;
    }

    /** @return list<array<string, mixed>> */
    private function fetchAttestations(string $digest): array
    {
        $data = $this->githubApi(
            '/repos/' . SigstoreProvenance::REPOSITORY . '/attestations/sha256:' . $digest . '?per_page=100'
        );
        $entries = $data['attestations'] ?? null;
        if (!is_array($entries) || !array_is_list($entries) || $entries === []) {
            throw new RuntimeException('GitHub returned no attestations for the release ZIP digest.');
        }
        return $entries;
    }

    /** @return array<string, mixed> */
    private function githubApi(string $path): array
    {
        $body = $this->httpsGet(self::API_BASE . $path, self::MAX_API_BYTES, 'api');
        try {
            $data = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('GitHub API returned invalid JSON.', 0, $exception);
        }
        if (!is_array($data)) {
            throw new RuntimeException('GitHub API response is not a JSON object.');
        }
        return $data;
    }

    private function httpsGet(string $url, int $maximumBytes, string $hostType): string
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required for native release attestation verification.');
        }
        $parts = parse_url($url);
        $host = strtolower((string)($parts['host'] ?? ''));
        $validHost = $hostType === 'api'
            ? $host === 'api.github.com'
            : ($hostType === 'blob' && str_ends_with($host, '.blob.core.windows.net'));
        if (($parts['scheme'] ?? '') !== 'https' || !$validHost
            || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && (int)$parts['port'] !== 443)
            || isset($parts['fragment'])) {
            throw new RuntimeException('Attestation download URL is outside the approved HTTPS hosts.');
        }

        $body = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 12,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => $hostType === 'api'
                ? ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28', 'User-Agent: SentryIQ-Updater/1.0']
                : ['Accept: application/json', 'User-Agent: SentryIQ-Updater/1.0'],
            CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, $maximumBytes): int {
                if (strlen($body) + strlen($chunk) > $maximumBytes) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($ok !== true || $status < 200 || $status >= 300 || $body === '') {
            throw new RuntimeException('HTTPS attestation request failed (HTTP ' . $status . ').' . ($error !== '' ? ' ' . $error : ''));
        }
        return $body;
    }
}
