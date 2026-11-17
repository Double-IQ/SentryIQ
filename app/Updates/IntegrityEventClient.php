<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * HTTPS client used by independent Integrity Nodes A/B to exchange challenges
 * and signed reports with BTM-SA Node 4.
 */
final class IntegrityEventClient
{
    /** @var callable(string,array<string,string>,string):array{status:int,body:string} */
    private $transport;

    public function __construct(
        private readonly string $endpoint,
        private readonly string $nodeId,
        private readonly string $bearerToken,
        ?callable $transport = null
    ) {
        $parts = parse_url($endpoint);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || !in_array($nodeId, ['integrity-a', 'integrity-b'], true)
            || !preg_match('/^[A-Za-z0-9_-]{40,128}$/', $bearerToken)) {
            throw new RuntimeException('Node 4 client endpoint or node credentials are invalid.');
        }
        $this->transport = $transport ?? fn(string $url, array $headers, string $body): array => $this->curlPost($url, $headers, $body);
    }

    /** @return array{nonce:string,expires_at:int,node_id:string} */
    public function requestChallenge(
        string $targetOrigin,
        string $releaseVersion,
        string $commit,
        string $artifactSha256,
        string $manifestSha256
    ): array {
        $response = $this->request([
            'action' => 'challenge',
            'node_id' => $this->nodeId,
            'target_origin' => $targetOrigin,
            'release_version' => $releaseVersion,
            'commit' => $commit,
            'artifact_sha256' => $artifactSha256,
            'manifest_sha256' => $manifestSha256,
        ], 201);
        if (($response['node_id'] ?? null) !== $this->nodeId
            || !is_string($response['nonce'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $response['nonce'])
            || !is_int($response['expires_at'] ?? null)
            || $response['expires_at'] <= time()
            || $response['expires_at'] > time() + 330) {
            throw new RuntimeException('Node 4 returned an invalid or expired challenge.');
        }
        return [
            'nonce' => $response['nonce'],
            'expires_at' => $response['expires_at'],
            'node_id' => $this->nodeId,
        ];
    }

    /** @return array<string,mixed> */
    public function submitReport(string $signedEnvelope): array
    {
        if ($signedEnvelope === '' || strlen($signedEnvelope) > 16384) {
            throw new RuntimeException('Signed integrity report is empty or too large.');
        }
        return $this->request([
            'action' => 'report',
            'envelope' => $signedEnvelope,
        ], 202);
    }

    /** @param array<string,mixed> $request @return array<string,mixed> */
    private function request(array $request, int $expectedStatus): array
    {
        try {
            $body = json_encode($request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Unable to encode Node 4 request.', 0, $exception);
        }
        $headers = [
            'Authorization' => 'Bearer ' . $this->bearerToken,
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
        ];
        $result = ($this->transport)($this->endpoint, $headers, $body);
        if (!is_array($result) || ($result['status'] ?? null) !== $expectedStatus
            || !is_string($result['body'] ?? null) || strlen($result['body']) > 16384) {
            throw new RuntimeException('Node 4 returned an unexpected HTTP response.');
        }
        try {
            $decoded = json_decode($result['body'], true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Node 4 response is not valid JSON.', 0, $exception);
        }
        if (!is_array($decoded) || ($decoded['status'] ?? null) !== ($expectedStatus === 201 ? 'ok' : 'accepted')) {
            throw new RuntimeException('Node 4 rejected the integrity event request.');
        }
        return $decoded;
    }

    /**
     * @param array<string,string> $headers
     * @return array{status:int,body:string}
     */
    private function curlPost(string $url, array $headers, string $body): array
    {
        if (!function_exists('curl_init')) {
            throw new RuntimeException('cURL is required for the Node 4 HTTPS client.');
        }
        $curlHeaders = [];
        foreach ($headers as $name => $value) {
            $curlHeaders[] = $name . ': ' . $value;
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Unable to initialize Node 4 HTTPS request.');
        }
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $body,
            CURLOPT_HTTPHEADER => $curlHeaders,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
        ]);
        $response = curl_exec($handle);
        $status = (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);
        if (!is_string($response) || strlen($response) > 16384) {
            throw new RuntimeException('Node 4 HTTPS request failed or response exceeded the size limit: ' . $error);
        }
        return ['status' => $status, 'body' => $response];
    }
}
