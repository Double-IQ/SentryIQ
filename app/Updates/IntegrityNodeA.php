<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

require_once __DIR__ . '/IntegrityNodeAlertedException.php';
require_once __DIR__ . '/IntegrityPublicAssetPolicy.php';

/**
 * Node A's read-only public-origin verifier.
 *
 * Both the external manifest and exact release ZIP must pass the maintained
 * GitHub/Sigstore verifier before the manifest is used as expected state.
 * Only signed static public assets are fetched; dynamic PHP responses and
 * private runtime files are not treated as byte-verifiable HTTP assets.
 */
final class IntegrityNodeA
{
    /** @var callable(string,string,string,string):void */
    private $verifyAttestation;

    /** @var callable(string):string */
    private $fetch;

    /** @var callable(string,string,array<string,mixed>):void|null */
    private $notifyFailure;

    /** @var callable(string):array{approved:bool,mismatches:list<string>} */
    private $verifyOriginHeaders;

    /** @var callable(string,string,string,string,string,array,string):array{approved:bool,mismatches:list<array<string,mixed>>} */
    private $verifyPrivateHost;

    /**
     * @param callable(string,string,string,string):void $verifyAttestation
     *        Arguments: artifact path, release version, source commit, installed version.
     * @param callable(string):string|null $fetch Test seam; production uses HTTPS cURL.
     * @param callable(string,string,array<string,mixed>):void $notifyFailure (required; null is rejected) Independent direct owner-alert transport; never routes through Node 4.
     */
    public function __construct(
        private readonly IntegrityReportSigner $signer,
        callable $verifyAttestation,
        ?callable $fetch = null,
        ?callable $notifyFailure = null,
        ?callable $verifyOriginHeaders = null,
        ?callable $verifyPrivateHost = null
    ) {
        if ($this->signer->nodeId() !== 'integrity-a') {
            throw new RuntimeException('Integrity Node A requires its own integrity-a signing identity.');
        }
        if ($notifyFailure === null) {
            throw new RuntimeException('Integrity Node A requires an independent direct owner-alert transport.');
        }
        if ($verifyOriginHeaders === null) {
            throw new RuntimeException('Integrity Node A requires an origin security-header verifier.');
        }
        if ($verifyPrivateHost === null) {
            throw new RuntimeException('Integrity Node A requires independent private-host deployment attestation.');
        }
        $this->verifyAttestation = $verifyAttestation;
        $this->fetch = $fetch ?? fn(string $url): string => $this->fetchHttps($url);
        $this->notifyFailure = $notifyFailure;
        $this->verifyOriginHeaders = $verifyOriginHeaders;
        $this->verifyPrivateHost = $verifyPrivateHost;
    }

    /**
     * @param list<string> $publicPaths Optional subset of signed static assets; empty selects every manifest public_http_files entry.
     * @param string $nonce Fresh 32-byte event-plane challenge as 64 hexadecimal characters.
     * @return array{approved:bool,report:string,checked_paths:list<string>,mismatches:list<array{path:string,reason:string}>,manifest_sha256:string,artifact_sha256:string}
     */
    public function verify(
        string $manifestPath,
        string $artifactPath,
        string $releaseVersion,
        string $commit,
        string $installedVersion,
        string $origin,
        array $publicPaths,
        string $nonce
    ): array {
        $manifestReal = $this->regularFile($manifestPath);
        $artifactReal = $this->regularFile($artifactPath);
        $version = $this->normalizeVersion($releaseVersion);
        $commit = strtolower(trim($commit));
        $nonce = strtolower(trim($nonce));
        if (!preg_match('/^[a-f0-9]{64}$/', $nonce)) {
            throw new RuntimeException('A fresh 32-byte event-plane nonce is required.');
        }

        if (!preg_match('/^[a-f0-9]{40}$/', $commit)) {
            throw new RuntimeException('Release commit must be a full Git SHA.');
        }

        $base = parse_url($origin);
        if (!is_array($base) || ($base['scheme'] ?? '') !== 'https'
            || empty($base['host']) || isset($base['user']) || isset($base['pass'])
            || isset($base['query']) || isset($base['fragment'])) {
            throw new RuntimeException('Integrity Node origin must be a clean HTTPS base URL.');
        }
        $origin = rtrim($origin, '/') . '/';

        // Verify both independently attested subjects before trusting manifest contents.
        try {
            ($this->verifyAttestation)($manifestReal, $version, $commit, $installedVersion);
            ($this->verifyAttestation)($artifactReal, $version, $commit, $installedVersion);
        } catch (\Throwable $exception) {
            $this->alertFailure('release_attestation_rejected', ['release_version' => $version]);
            throw new IntegrityNodeAlertedException(
                'Release attestation rejected after direct owner alert delivery.',
                0,
                $exception
            );
        }

        $manifestBytes = file_get_contents($manifestReal);
        if (!is_string($manifestBytes) || strlen($manifestBytes) > 5_000_000) {
            throw new RuntimeException('Release manifest is unreadable or exceeds the size limit.');
        }
        try {
            $manifest = json_decode($manifestBytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Attested release manifest is not valid JSON.', 0, $exception);
        }
        if (!is_array($manifest) || ($manifest['format'] ?? null) !== 2
            || ($manifest['repository'] ?? null) !== 'Double-IQ/SentryIQ'
            || (string)($manifest['repository_id'] ?? '') !== '1345956206'
            || ($manifest['version'] ?? null) !== $version
            || strtolower((string)($manifest['commit'] ?? '')) !== $commit
            || ($manifest['workflow_path'] ?? null) !== '.github/workflows/release.yml'
            || !is_array($manifest['files'] ?? null)) {
            throw new RuntimeException('Attested manifest identity or schema does not match the requested release.');
        }

        $entries = [];
        foreach ($manifest['files'] as $entry) {
            if (!is_array($entry) || !is_string($entry['path'] ?? null)
                || !is_int($entry['size'] ?? null) || $entry['size'] < 0
                || !is_string($entry['sha256'] ?? null)
                || !preg_match('/^[a-f0-9]{64}$/', $entry['sha256'])) {
                throw new RuntimeException('Release manifest contains a malformed file entry.');
            }
            $path = $entry['path'];
            if ($path === '' || str_starts_with($path, '/') || str_contains($path, '\\')
                || preg_match('~(^|/)\.\.?(/|$)~', $path) || isset($entries[$path])) {
                throw new RuntimeException('Release manifest contains an unsafe or duplicate path.');
            }
            $entries[$path] = $entry;
        }

        $pathsToCheck = IntegrityPublicAssetPolicy::resolve($manifest, $entries, $publicPaths);

        $checked = [];
        $mismatches = [];
        foreach ($pathsToCheck as $path) {
            $url = $origin . implode('/', array_map('rawurlencode', explode('/', $path)));
            try {
                $body = ($this->fetch)($url);
            } catch (\Throwable $exception) {
                $mismatches[] = ['path' => $path, 'reason' => 'fetch_failed'];
                continue;
            }
            if (!is_string($body)) {
                $mismatches[] = ['path' => $path, 'reason' => 'fetch_failed'];
                continue;
            }
            $actual = hash('sha256', $body);
            $checked[] = $path;
            if (!hash_equals($entries[$path]['sha256'], $actual)
                || strlen($body) !== $entries[$path]['size']) {
                $mismatches[] = ['path' => $path, 'reason' => 'content_mismatch'];
            }
        }

        $headerResult = ($this->verifyOriginHeaders)($origin);
        if (!is_array($headerResult) || !is_bool($headerResult['approved'] ?? null)
            || !is_array($headerResult['mismatches'] ?? null) || !array_is_list($headerResult['mismatches'])
            || count($headerResult['mismatches']) > 32
            || ($headerResult['approved'] !== ($headerResult['mismatches'] === []))) {
            throw new RuntimeException('Origin security-header verifier returned an invalid result.');
        }
        foreach ($headerResult['mismatches'] as $headerMismatch) {
            if (!is_string($headerMismatch) || $headerMismatch === '' || strlen($headerMismatch) > 128
                || preg_match('/[\\x00-\\x1f]/', $headerMismatch)) {
                throw new RuntimeException('Origin security-header verifier returned an unsafe mismatch value.');
            }
        }
        $checked[] = '@origin-headers';
        $headerMismatchNames = $headerResult['mismatches'];
        if ($headerResult['approved'] !== true) {
            $mismatches[] = ['path' => '@origin-headers', 'reason' => 'security_header_mismatch'];
        }

        $originMismatches = $mismatches;
        $artifactDigest = hash_file('sha256', $artifactReal);
        $manifestDigest = hash('sha256', $manifestBytes);
        if (!is_string($artifactDigest)) {
            throw new RuntimeException('Unable to calculate release artifact digest.');
        }

        try {
            $privateHost = ($this->verifyPrivateHost)(
                $version,
                $commit,
                $manifestDigest,
                $artifactDigest,
                $nonce,
                $manifest,
                rtrim($origin, '/')
            );
            if (!is_array($privateHost) || !is_bool($privateHost['approved'] ?? null)
                || !is_array($privateHost['mismatches'] ?? null) || !array_is_list($privateHost['mismatches'])
                || count($privateHost['mismatches']) > 100
                || ($privateHost['approved'] !== ($privateHost['mismatches'] === []))) {
                throw new RuntimeException('Private-host attestation verifier returned an invalid result.');
            }
        } catch (\Throwable $exception) {
            $this->alertFailure('private_host_attestation_unavailable', [
                'release_version' => $version,
                'phase' => 'private_host_attestation',
            ]);
            throw new IntegrityNodeAlertedException(
                'Private-host deployment attestation failed after independent owner alert delivery.',
                0,
                $exception
            );
        }
        $checked[] = '@private-host-attestation';
        if ($privateHost['approved'] !== true) {
            $mismatches[] = ['path' => '@private-host-attestation', 'reason' => 'private_host_attestation_failed'];
            $this->alertFailure('private_host_attestation_rejected', [
                'release_version' => $version,
                'mismatch_count' => count($privateHost['mismatches']),
            ]);
        }

        $approved = $mismatches === [];
        if ($originMismatches !== []) {
            $this->alertFailure('origin_integrity_mismatch', [
                'target_origin' => rtrim($origin, '/'),
                'mismatch_count' => count($originMismatches),
                'header_mismatches' => $headerMismatchNames,
            ]);
        }
        $report = $this->signer->createReport(
            $version,
            $commit,
            $artifactDigest,
            $nonce,
            $approved ? 'approve' : 'reject',
            [
                'target_origin' => rtrim($origin, '/'),
                'manifest_sha256' => $manifestDigest,
                'checked_paths' => $checked,
                'mismatches' => $mismatches,
            ]
        );


        return [
            'approved' => $approved,
            'report' => $report,
            'checked_paths' => $checked,
            'mismatches' => $mismatches,
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
        ];
    }

    /** Deliver directly to the node owner's separately configured alert destination. */
    private function alertFailure(string $reason, array $context = []): void
    {
        if ($this->notifyFailure === null) {
            return;
        }
        try {
            ($this->notifyFailure)($this->signer->nodeId(), $reason, $context);
        } catch (\Throwable $exception) {
            throw new RuntimeException('Independent integrity-node owner alert delivery failed.', 0, $exception);
        }
    }

    private function regularFile(string $path): string
    {
        $real = realpath($path);
        if ($real === false || !is_file($real) || is_link($path) || !is_readable($real)) {
            throw new RuntimeException('Integrity Node input must be a readable regular file.');
        }
        return $real;
    }

    private function fetchHttps(string $url): string
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required by Integrity Node A.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize HTTPS request.');
        }
        $body = '';
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HTTPHEADER => ['Cache-Control: no-cache, no-store, no-transform', 'Pragma: no-cache'],
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 25,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'SentryIQ-Integrity-Node-A/1.0',
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body): int {
                if (strlen($body) + strlen($chunk) > 10_000_000) {
                    return 0;
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        if ($ok !== true || $status !== 200) {
            throw new RuntimeException('Public-origin request failed or returned a non-200 response.');
        }
        return $body;
    }

    private function normalizeVersion(string $version): string
    {
        $version = trim($version);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)) {
            throw new RuntimeException('Release version must use stable MAJOR.MINOR.PATCH format.');
        }
        return $version;
    }
}
