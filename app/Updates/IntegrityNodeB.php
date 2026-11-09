<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Node B's read-only public-origin verifier.
 *
 * Both the external manifest and exact release ZIP must pass the maintained
 * GitHub/Sigstore verifier before the manifest is used as expected state.
 * Only explicitly configured public paths are fetched; private PHP/runtime
 * files are not inferred to be HTTP-verifiable.
 */
final class IntegrityNodeB
{
    /** @var callable(string,string,string,string):void */
    private $verifyAttestation;

    /** @var callable(string):string */
    private $fetch;

    /**
     * @param callable(string,string,string,string):void $verifyAttestation
     *        Arguments: artifact path, release version, source commit, installed version.
     * @param callable(string):string|null $fetch Test seam; production uses HTTPS cURL.
     */
    public function __construct(
        private readonly IntegrityReportSigner $signer,
        callable $verifyAttestation,
        ?callable $fetch = null
    ) {
        $this->verifyAttestation = $verifyAttestation;
        $this->fetch = $fetch ?? fn(string $url): string => $this->fetchHttps($url);
    }

    /**
     * @param list<string> $publicPaths Explicit relative URLs to check, e.g. ["index.php","assets/app.js"].
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
        ($this->verifyAttestation)($manifestReal, $version, $commit, $installedVersion);
        ($this->verifyAttestation)($artifactReal, $version, $commit, $installedVersion);

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

        if ($publicPaths === [] || !array_is_list($publicPaths)) {
            throw new RuntimeException('At least one explicit public-origin path must be configured.');
        }

        $checked = [];
        $mismatches = [];
        foreach (array_values(array_unique($publicPaths)) as $path) {
            if (!is_string($path) || $path === '' || str_starts_with($path, '/')
                || str_contains($path, '\\') || preg_match('~(^|/)\.\.?(/|$)~', $path)
                || preg_match('/[?#]/', $path)) {
                throw new RuntimeException('Configured public-origin path is unsafe.');
            }
            if (!isset($entries[$path])) {
                throw new RuntimeException('Configured public-origin path is absent from the attested manifest: ' . $path);
            }

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

        $artifactDigest = hash_file('sha256', $artifactReal);
        $manifestDigest = hash('sha256', $manifestBytes);
        if (!is_string($artifactDigest)) {
            throw new RuntimeException('Unable to calculate release artifact digest.');
        }

        $approved = $mismatches === [];
        $report = $this->signer->createReport(
            $version,
            $commit,
            $artifactDigest,
            $nonce,
            $approved ? 'approve' : 'reject'
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
            throw new RuntimeException('PHP cURL is required by Integrity Node B.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize HTTPS request.');
        }
        $body = '';
        curl_setopt_array($handle, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 25,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'SentryIQ-Integrity-Node-B/1.0',
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
