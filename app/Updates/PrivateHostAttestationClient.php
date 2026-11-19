<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Authenticated A/B transport to the production-host attestation service.
 * The remote adapter must forward this bounded request to the isolated
 * collector process; this client never accepts caller-supplied file paths.
 */
final class PrivateHostAttestationClient
{
    /** @var callable(string,array<string,string>,string,int):array{status:int,body:string} */
    private $post;

    public function __construct(
        private readonly string $nodeId,
        private readonly string $bearerToken,
        string $endpoint = 'https://sentryiq.bichet.co.za/private-host-attestation',
        ?callable $post = null
    ) {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b'], true)
            || !preg_match('/^[A-Za-z0-9_-]{40,128}$/', $bearerToken)) {
            throw new RuntimeException('Private host transport requires a known A/B identity and unique strong bearer token.');
        }
        $parts = parse_url($endpoint);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || (isset($parts['port']) && $parts['port'] !== 443)
            || ($parts['path'] ?? '') !== '/private-host-attestation'
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('Private host transport endpoint must use the pinned SentryIQ HTTPS route.');
        }
        $this->endpoint = $endpoint;
        $this->post = $post ?? fn(string $url, array $headers, string $body, int $maxBytes): array =>
            $this->curlPost($url, $headers, $body, $maxBytes);
    }

    private string $endpoint;

    /** Return the fixed node identity without exposing its bearer credential. */
    public function nodeId(): string
    {
        return $this->nodeId;
    }

    /** Stable comparison value for auditing that A and B use distinct bearer credentials. */
    public function credentialFingerprint(): string
    {
        return hash('sha256', $this->bearerToken);
    }

    /**
     * Returns the original JSON envelope bytes for the pinned verifier.
     */
    public function request(
        string $nonce,
        string $releaseVersion,
        string $commit,
        string $manifestDigest,
        string $artifactDigest
    ): string {
        $nonce = strtolower(trim($nonce));
        $version = trim($releaseVersion);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        $commit = strtolower(trim($commit));
        $manifestDigest = strtolower(trim($manifestDigest));
        $artifactDigest = strtolower(trim($artifactDigest));
        if (!preg_match('/^[a-f0-9]{64}$/', $nonce)
            || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)
            || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
            || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
            throw new RuntimeException('Private host request context is invalid.');
        }

        $body = json_encode([
            'schema_version' => 1,
            'node_id' => $this->nodeId,
            'nonce' => $nonce,
            'release_version' => $version,
            'commit' => $commit,
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $response = ($this->post)(
            $this->endpoint,
            [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer ' . $this->bearerToken,
                'Cache-Control' => 'no-store',
            ],
            $body,
            1_048_576
        );
        if (!is_array($response) || ($response['status'] ?? null) !== 200
            || !is_string($response['body'] ?? null) || $response['body'] === ''
            || strlen($response['body']) > 1_048_576) {
            throw new RuntimeException('Private host attestation service is unavailable or returned an invalid response.');
        }
        try {
            $envelope = json_decode($response['body'], true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Private host attestation service returned invalid JSON.', 0, $exception);
        }
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['signature'] ?? null)) {
            throw new RuntimeException('Private host attestation response envelope is invalid.');
        }
        $payload = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        if (!is_string($payload) || $payload === '' || strlen($payload) > 786_432
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('Private host attestation response exceeds bounds or has invalid encoding.');
        }
        return $response['body'];
    }

    /** @return array{status:int,body:string} */
    private function curlPost(string $url, array $headers, string $body, int $maxBytes): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('PHP cURL is required for private host attestation transport.');
        }
        $handle = curl_init($url);
        if ($handle === false) throw new RuntimeException('Unable to initialize private host attestation request.');
        $headerLines = [];
        foreach ($headers as $name => $value) $headerLines[] = $name . ': ' . $value;
        $responseBody = '';
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$responseBody, $maxBytes): int {
                if (strlen($responseBody) + strlen($chunk) > $maxBytes) return 0;
                $responseBody .= $chunk;
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);
        if ($ok !== true) throw new RuntimeException('Private host HTTPS request failed or exceeded its response limit.');
        return ['status' => $status, 'body' => $responseBody];
    }
}
