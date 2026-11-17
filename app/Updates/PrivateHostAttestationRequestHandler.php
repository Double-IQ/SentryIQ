<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Framework-neutral authenticated request handler for an isolated host service.
 * The actual HTTP listener/reverse proxy is deliberately host-specific.
 */
final class PrivateHostAttestationRequestHandler
{
    /** @var array<string,string> */
    private array $nodeTokens;

    /** @var callable(string,string,int):bool */
    private $consumeNonce;

    /**
     * @param array<string,string> $nodeTokens Exactly integrity-a and integrity-b, distinct URL-safe bearer tokens.
     * @param callable(string,string,int):bool $consumeNonce Durable single-use nonce store:
     *        node ID, nonce, expiry timestamp => true only when atomically recorded as new.
     */
    public function __construct(
        private readonly PrivateHostAttestationCollector $collector,
        array $nodeTokens,
        callable $consumeNonce
    ) {
        if (array_keys($nodeTokens) !== ['integrity-a', 'integrity-b']
            || !is_string($nodeTokens['integrity-a'] ?? null)
            || !is_string($nodeTokens['integrity-b'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{40,128}$/', $nodeTokens['integrity-a'])
            || !preg_match('/^[A-Za-z0-9_-]{40,128}$/', $nodeTokens['integrity-b'])
            || hash_equals($nodeTokens['integrity-a'], $nodeTokens['integrity-b'])) {
            throw new RuntimeException('Host attestation service requires distinct strong A/B credentials in fixed order.');
        }
        $this->nodeTokens = $nodeTokens;
        $this->consumeNonce = $consumeNonce;
    }

    /** @param array<string,string> $headers @return array{status:int,body:string} */
    public function handle(string $method, array $headers, string $body): array
    {
        if ($method !== 'POST' || strlen($body) < 1 || strlen($body) > 4096) {
            return $this->error(400);
        }
        $authorization = null;
        foreach ($headers as $name => $value) {
            if (is_string($name) && strtolower($name) === 'authorization' && is_string($value)) {
                $authorization = $value;
                break;
            }
        }
        if (!is_string($authorization) || !str_starts_with($authorization, 'Bearer ')) {
            return $this->error(401);
        }
        $token = substr($authorization, 7);
        $nodeId = null;
        foreach ($this->nodeTokens as $candidate => $expected) {
            if (hash_equals($expected, $token)) {
                $nodeId = $candidate;
                break;
            }
        }
        if ($nodeId === null) return $this->error(401);

        try {
            $request = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error(400);
        }
        $required = ['schema_version', 'node_id', 'nonce', 'release_version', 'commit', 'manifest_sha256', 'artifact_sha256'];
        if (!is_array($request) || array_diff(array_keys($request), $required) !== []
            || array_diff($required, array_keys($request)) !== []
            || ($request['schema_version'] ?? null) !== 1
            || ($request['node_id'] ?? null) !== $nodeId
            || !is_string($request['nonce'] ?? null)
            || !is_string($request['release_version'] ?? null)
            || !is_string($request['commit'] ?? null)
            || !is_string($request['manifest_sha256'] ?? null)
            || !is_string($request['artifact_sha256'] ?? null)) {
            return $this->error(400);
        }

        $nonce = strtolower(trim($request['nonce']));
        $version = trim($request['release_version']);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        $commit = strtolower(trim($request['commit']));
        $manifest = strtolower(trim($request['manifest_sha256']));
        $artifact = strtolower(trim($request['artifact_sha256']));
        if (!preg_match('/^[a-f0-9]{64}$/', $nonce)
            || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)
            || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $manifest)
            || !preg_match('/^[a-f0-9]{64}$/', $artifact)) {
            return $this->error(400);
        }

        $now = time();
        try {
            if (!(($this->consumeNonce)($nodeId, $nonce, $now + 120))) {
                return $this->error(409);
            }
            $envelope = $this->collector->collect($nonce, $version, $commit, $manifest, $artifact);
            return [
                'status' => 200,
                'body' => json_encode($envelope, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            ];
        } catch (\Throwable) {
            return $this->error(503);
        }
    }

    /** @return array{status:int,body:string} */
    private function error(int $status): array
    {
        return [
            'status' => $status,
            'body' => json_encode(['error' => 'private_host_attestation_unavailable'], JSON_THROW_ON_ERROR),
        ];
    }
}
