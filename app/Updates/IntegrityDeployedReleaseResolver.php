<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Resolves the deployed release from the live VERSION file, then resolves the
 * corresponding immutable source commit from the canonical GitHub repository.
 */
final class IntegrityDeployedReleaseResolver
{
    /** @var callable(string,int):array{status:int,body:string} */
    private $get;
    private ?string $githubApiToken = null;

    public function __construct(
        private readonly string $targetOrigin = 'https://sentryiq.bichet.co.za',
        ?callable $get = null,
        ?string $githubApiToken = null
    ) {
        $parts = parse_url($targetOrigin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || (isset($parts['port']) && $parts['port'] !== 443)
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || ($parts['path'] ?? '') !== '') {
            throw new RuntimeException('Deployed release resolver must use the canonical SentryIQ HTTPS origin.');
        }
        if ($githubApiToken !== null && preg_match('/^[A-Za-z0-9_-]{20,255}$/', $githubApiToken) !== 1) {
            throw new RuntimeException('Optional GitHub API token has an invalid format.');
        }
        $this->githubApiToken = $githubApiToken;
        $this->get = $get ?? fn(string $url, int $maxBytes): array => $this->curlGet($url, $maxBytes);
    }

    /** @return array{version:string,commit:string} */
    public function __invoke(): array
    {
        $originResponse = ($this->get)(rtrim($this->targetOrigin, '/') . '/VERSION', 128);
        if (!is_array($originResponse) || ($originResponse['status'] ?? null) !== 200
            || !is_string($originResponse['body'] ?? null) || strlen($originResponse['body']) > 128) {
            throw new RuntimeException('Live SentryIQ VERSION endpoint is unavailable or invalid.');
        }

        $version = trim($originResponse['body']);
        if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)) {
            throw new RuntimeException('Live SentryIQ VERSION file must contain one stable MAJOR.MINOR.PATCH release.');
        }

        $apiUrl = 'https://api.github.com/repos/Double-IQ/SentryIQ/commits/v' . $version;
        $commitResponse = ($this->get)($apiUrl, 1_000_000);
        if (!is_array($commitResponse) || ($commitResponse['status'] ?? null) !== 200
            || !is_string($commitResponse['body'] ?? null) || strlen($commitResponse['body']) > 1_000_000) {
            throw new RuntimeException('Canonical GitHub release tag could not be resolved to a commit.');
        }
        try {
            $commitPayload = json_decode($commitResponse['body'], true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('GitHub release tag response is not valid JSON.', 0, $exception);
        }
        $commit = is_array($commitPayload) ? strtolower((string)($commitPayload['sha'] ?? '')) : '';
        if (!preg_match('/^[a-f0-9]{40}$/', $commit)) {
            throw new RuntimeException('Canonical GitHub release tag did not resolve to a full commit SHA.');
        }

        return ['version' => $version, 'commit' => $commit];
    }

    /** @return array{status:int,body:string} */
    private function curlGet(string $url, int $maxBytes): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required to resolve the deployed SentryIQ release.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize deployed release HTTPS request.');
        }
        $body = '';
        $headers = ['Accept: */*', 'Cache-Control: no-cache, no-store, no-transform', 'Pragma: no-cache'];
        if (str_starts_with($url, 'https://api.github.com/')) {
            $headers[0] = 'Accept: application/vnd.github+json';
            $headers[] = 'User-Agent: SentryIQ-Integrity-Node/1.0';
            if ($this->githubApiToken !== null) $headers[] = 'Authorization: Bearer ' . $this->githubApiToken;
        }
        curl_setopt_array($handle, [
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 20,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$body, $maxBytes): int {
                if (strlen($body) + strlen($chunk) > $maxBytes) return 0;
                $body .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        if ($ok !== true) {
            throw new RuntimeException('Deployed release HTTPS request failed or exceeded its response limit.');
        }
        return ['status' => $status, 'body' => $body];
    }
}
