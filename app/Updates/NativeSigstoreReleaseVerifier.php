<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

require_once __DIR__ . '/TufRootStore.php';
require_once __DIR__ . '/FulcioCertificateClaims.php';
require_once __DIR__ . '/SnappyBlockDecoder.php';
require_once __DIR__ . '/SigstoreProvenance.php';
require_once __DIR__ . '/ReleaseArtifactVerifier.php';

use K2gl\Sigstore\Bundle;
use K2gl\Sigstore\IdentityPolicy;
use K2gl\Sigstore\SigstoreVerifier;
use K2gl\Sigstore\TrustedRoot;
use K2gl\Tuf\Exception\NotFoundException;
use K2gl\Tuf\HttpFetcher;
use K2gl\Tuf\Updater;
use RuntimeException;
use Throwable;

/**
 * Verifies a release ZIP using the native PHP Sigstore verifier and Sigstore
 * TUF trust metadata. No shell, exec, proc_open, or GitHub CLI is used.
 */
final class NativeSigstoreReleaseVerifier implements ReleaseArtifactVerifier
{
    private const API_BASE = 'https://api.github.com';
    private const TUF_METADATA_URL = 'https://tuf-repo-cdn.sigstore.dev';
    private const TUF_TARGETS_URL = 'https://tuf-repo-cdn.sigstore.dev/targets';
    private const MAX_API_BYTES = 2_000_000;
    private const MAX_BUNDLE_BYTES = 8_000_000;
    private const SIGSTORE_VERIFY_VERSION = '1.6.1';
    private const TUF_VERSION = '1.2.1';

    private readonly TufRootStore $rootStore;
    private ?string $githubApiToken = null;

    public function __construct(string $vendorAutoloadPath, string $privateDataDirectory, ?string $githubApiToken = null)
    {
        if ($githubApiToken !== null && preg_match('/^[A-Za-z0-9_-]{20,255}$/', $githubApiToken) !== 1) {
            throw new RuntimeException('Optional GitHub API token has an invalid format.');
        }
        $this->githubApiToken = $githubApiToken;
        if ($vendorAutoloadPath === '' || !str_starts_with($vendorAutoloadPath, '/')
            || is_link($vendorAutoloadPath) || !is_file($vendorAutoloadPath) || !is_readable($vendorAutoloadPath)) {
            throw new RuntimeException('A readable private Sigstore Composer autoload.php path is required.');
        }
        if (!is_dir($privateDataDirectory) || is_link($privateDataDirectory)) {
            throw new RuntimeException('The private SentryIQ data directory is unavailable.');
        }
        $realDataDirectory = realpath($privateDataDirectory);
        $realAutoloadPath = realpath($vendorAutoloadPath);
        if (!is_string($realDataDirectory) || $realDataDirectory === ''
            || rtrim($realDataDirectory, '/') !== rtrim($privateDataDirectory, '/')
            || !is_string($realAutoloadPath) || $realAutoloadPath !== $vendorAutoloadPath
            || !str_starts_with($realAutoloadPath, rtrim($realDataDirectory, '/') . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Sigstore dependencies must resolve canonically inside the private SentryIQ data directory.');
        }
        $documentRoot = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
        if ($documentRoot === '' && PHP_SAPI !== 'cli') {
            throw new RuntimeException('Unable to establish the public web root for native Sigstore verification.');
        }
        if ($documentRoot !== '') {
            $realDocumentRoot = realpath($documentRoot);
            if (!is_string($realDocumentRoot) || !is_dir($realDocumentRoot)) {
                throw new RuntimeException('The public web root cannot be verified for native Sigstore verification.');
            }
            $publicPrefix = rtrim($realDocumentRoot, '/') . DIRECTORY_SEPARATOR;
            if ($realDataDirectory === rtrim($realDocumentRoot, '/')
                || str_starts_with($realDataDirectory . DIRECTORY_SEPARATOR, $publicPrefix)) {
                throw new RuntimeException('Native Sigstore dependencies must be outside the public web root.');
            }
        }

        require_once $vendorAutoloadPath;
        foreach ([Bundle::class, SigstoreVerifier::class, TrustedRoot::class, Updater::class, HttpFetcher::class, NotFoundException::class] as $class) {
            if (!class_exists($class)) {
                throw new RuntimeException('The configured private vendor directory is missing a required Sigstore/TUF class.');
            }
        }

        $installedVersionsClass = 'Composer' . chr(92) . 'InstalledVersions';
        if (!class_exists($installedVersionsClass)
            || call_user_func([$installedVersionsClass, 'getPrettyVersion'], 'k2gl/sigstore-verify') !== self::SIGSTORE_VERIFY_VERSION
            || call_user_func([$installedVersionsClass, 'getPrettyVersion'], 'k2gl/tuf') !== self::TUF_VERSION) {
            throw new RuntimeException('Private Sigstore dependencies do not match the pinned verifier and patched TUF versions.');
        }

        $storeDirectory = rtrim($realDataDirectory, '/') . '/sigstore-tuf';
        if (!is_dir($storeDirectory) && !@mkdir($storeDirectory, 0700)) {
            throw new RuntimeException('Unable to create the private Sigstore TUF root directory.');
        }
        if (is_link($storeDirectory) || !is_dir($storeDirectory) || !is_writable($storeDirectory)
            || !@chmod($storeDirectory, 0700)) {
            throw new RuntimeException('The private Sigstore TUF root directory is unsafe or not writable.');
        }
        $storeRealPath = realpath($storeDirectory);
        if (!is_string($storeRealPath) || $storeRealPath !== $storeDirectory) {
            throw new RuntimeException('The private Sigstore TUF root directory is not canonical.');
        }
        $this->rootStore = new TufRootStore($storeDirectory);
    }

    /**
     * @return array<string, mixed> authenticated and policy-ready claims
     */
    public function verifyRelease(string $zipPath, string $version): array
    {
        $normalizedVersion = trim($version);
        if (str_starts_with($normalizedVersion, 'v')) $normalizedVersion = substr($normalizedVersion, 1);
        return $this->verifyArtifact($zipPath, $normalizedVersion, 'sentryiq-' . $normalizedVersion . '.zip');
    }

    /**
     * Verify one canonical release artifact (manifest or ZIP) independently.
     *
     * @return array<string,mixed> authenticated and policy-ready claims
     */
    public function verifyArtifact(string $artifactPath, string $version, string $expectedSubjectName): array
    {
        if (!is_file($artifactPath) || is_link($artifactPath) || !is_readable($artifactPath)) {
            throw new RuntimeException('The downloaded release artifact is unavailable.');
        }
        $version = trim($version);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)) {
            throw new RuntimeException('Release artifact version must use MAJOR.MINOR.PATCH format.');
        }
        if ($expectedSubjectName !== 'release-manifest.json'
            && $expectedSubjectName !== 'sentryiq-' . $version . '.zip') {
            throw new RuntimeException('Expected release subject is outside the canonical manifest/ZIP set.');
        }

        $digest = hash_file('sha256', $artifactPath);
        if (!is_string($digest) || preg_match('/^[a-f0-9]{64}$/', $digest) !== 1) {
            throw new RuntimeException('Unable to calculate the release artifact SHA-256 digest.');
        }

        $tagCommit = $this->resolveTagCommit($version);
        $attestations = $this->fetchAttestations($digest);
        $trustedRoot = $this->refreshTrustedRoot();

        $identity = IdentityPolicy::githubActions(
            SigstoreProvenance::REPOSITORY,
            basename(SigstoreProvenance::WORKFLOW_PATH),
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
                $compressedBundle = $this->httpsGet($bundleUrl, self::MAX_BUNDLE_BYTES, 'blob');
                $bundleJson = SnappyBlockDecoder::decode($compressedBundle, self::MAX_BUNDLE_BYTES);
                $bundle = Bundle::fromJson($bundleJson);
                $envelope = $verifier->verify($bundle, $trustedRoot, $identity);

                // Use the exact leaf certificate authenticated by verify().
                // Fulcio OID .1.19 is Build Config Digest (GitHub workflow_sha).
                $workflowCommit = FulcioCertificateClaims::workflowCommit($bundle->leafCertificate);
                $claims = SigstoreProvenance::claims(
                    $envelope,
                    $workflowCommit,
                    $version,
                    $digest,
                    $expectedSubjectName
                );
                if (!hash_equals($tagCommit, $claims['source_commit'])) {
                    throw new RuntimeException("Attested source commit does not match GitHub's current resolution of the release tag.");
                }
                return $claims;
            } catch (Throwable $exception) {
                $lastFailure = $exception;
            }
        }

        throw new RuntimeException(
            'No GitHub attestation for this repository passed native Sigstore and SLSA provenance verification.',
            0,
            $lastFailure,
        );
    }

    private function refreshTrustedRoot(): TrustedRoot
    {
        $root = $this->rootStore->load();
        if ($root === null) {
            $bootstrap = dirname((new \ReflectionClass(TrustedRoot::class))->getFileName()) . '/../resources/sigstore-tuf-root.json';
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
        if ($ch === false) throw new RuntimeException('Unable to initialize HTTPS attestation request.');
        $headers = $hostType === 'api'
            ? ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2026-03-10', 'User-Agent: SentryIQ-Updater/1.0']
            : ['Accept: application/json', 'User-Agent: SentryIQ-Updater/1.0'];
        if ($hostType === 'api' && $this->githubApiToken !== null) {
            $headers[] = 'Authorization: Bearer ' . $this->githubApiToken;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CONNECTTIMEOUT => 12,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => $headers,
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
            $remoteCode = '';
            if (preg_match('/<Code>([^<]{1,80})<\\/Code>/', $body, $matches) === 1) {
                $remoteCode = ' ' . $matches[1];
            }
            throw new RuntimeException(
                'HTTPS attestation request failed for ' . $host . ' (HTTP ' . $status . ').' . $remoteCode
            );
        }
        return $body;
    }
}
