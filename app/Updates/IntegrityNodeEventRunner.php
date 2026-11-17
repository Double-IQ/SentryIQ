<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Orchestrates a node's local verification with the remote Node 4 challenge
 * and report exchange. A/B verifier classes remain read-only and reusable.
 */
final class IntegrityNodeEventRunner
{
    public function __construct(private readonly IntegrityEventClient $client)
    {
    }

    /**
     * @param callable(string):array<string,mixed> $verifyWithNonce
     * @return array<string,mixed> Local verification result plus Node 4 acknowledgement.
     */
    public function run(
        callable $verifyWithNonce,
        string $manifestPath,
        string $artifactPath,
        string $releaseVersion,
        string $commit,
        string $targetOrigin
    ): array {
        $manifest = $this->regularFile($manifestPath);
        $artifact = $this->regularFile($artifactPath);
        $manifestDigest = hash_file('sha256', $manifest);
        $artifactDigest = hash_file('sha256', $artifact);
        if (!is_string($manifestDigest) || !is_string($artifactDigest)) {
            throw new RuntimeException('Unable to bind Node 4 challenge to local release files.');
        }
        $releaseVersion = trim($releaseVersion);
        $version = str_starts_with($releaseVersion, 'v') ? substr($releaseVersion, 1) : $releaseVersion;
        $targetOrigin = rtrim($targetOrigin, '/');
        $challenge = $this->client->requestChallenge(
            $targetOrigin,
            $version,
            strtolower($commit),
            $artifactDigest,
            $manifestDigest
        );

        $result = $verifyWithNonce($challenge['nonce']);
        if (!is_array($result) || !is_string($result['report'] ?? null)
            || !is_string($result['manifest_sha256'] ?? null)
            || !is_string($result['artifact_sha256'] ?? null)
            || !hash_equals($manifestDigest, $result['manifest_sha256'])
            || !hash_equals($artifactDigest, $result['artifact_sha256'])) {
            throw new RuntimeException('Local verification inputs changed after the Node 4 challenge was issued.');
        }

        $acknowledgement = $this->client->submitReport($result['report']);
        return $result + [
            'challenge_expires_at' => $challenge['expires_at'],
            'event_acknowledgement' => $acknowledgement,
        ];
    }

    private function regularFile(string $path): string
    {
        $real = realpath($path);
        if ($real === false || !is_file($real) || is_link($path) || !is_readable($real)) {
            throw new RuntimeException('Node 4 runner inputs must be readable regular files.');
        }
        return $real;
    }
}
