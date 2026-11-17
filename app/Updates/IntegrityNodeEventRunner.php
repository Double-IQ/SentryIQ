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
    /** @var callable(string,string,array<string,mixed>):void */
    private $notifyFailure;

    /**
     * A direct owner-alert callback is mandatory because Node 4 shares the
     * SentryIQ host and cannot be the sole route for reporting its own outage.
     *
     * @param callable(string,string,array<string,mixed>):void $notifyFailure
     */
    public function __construct(
        private readonly IntegrityEventClient $client,
        callable $notifyFailure
    ) {
        $this->notifyFailure = $notifyFailure;
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
            $this->alertFailure('local_evidence_unreadable', ['phase' => 'prepare']);
            throw new RuntimeException('Unable to bind Node 4 challenge to local release files.');
        }
        $releaseVersion = trim($releaseVersion);
        $version = str_starts_with($releaseVersion, 'v') ? substr($releaseVersion, 1) : $releaseVersion;
        $targetOrigin = rtrim($targetOrigin, '/');
        try {
            $challenge = $this->client->requestChallenge(
                $targetOrigin,
                $version,
                strtolower($commit),
                $artifactDigest,
                $manifestDigest
            );
        } catch (\Throwable $exception) {
            $this->alertFailure('node4_challenge_unavailable', ['phase' => 'challenge']);
            throw new RuntimeException('Node 4 challenge request failed; independent owner alert was attempted.', 0, $exception);
        }

        try {
            $result = $verifyWithNonce($challenge['nonce']);
            if (!is_array($result) || !is_string($result['report'] ?? null)
                || !is_string($result['manifest_sha256'] ?? null)
                || !is_string($result['artifact_sha256'] ?? null)
                || !hash_equals($manifestDigest, $result['manifest_sha256'])
                || !hash_equals($artifactDigest, $result['artifact_sha256'])) {
                throw new RuntimeException('Local verification inputs changed after the Node 4 challenge was issued.');
            }
        } catch (\\Throwable $exception) {
            $this->alertFailure('local_verification_failed', [
                'phase' => 'verification',
                'release_version' => $version,
                'exception' => get_class($exception),
            ]);
            throw new RuntimeException('Local integrity verification failed; independent owner alert was attempted.', 0, $exception);
        }

        try {
            $acknowledgement = $this->client->submitReport($result['report']);
        } catch (\Throwable $exception) {
            $this->alertFailure('node4_report_delivery_failed', ['phase' => 'report']);
            throw new RuntimeException('Node 4 report delivery failed; independent owner alert was attempted.', 0, $exception);
        }
        return $result + [
            'challenge_expires_at' => $challenge['expires_at'],
            'event_acknowledgement' => $acknowledgement,
        ];
    }


    private function alertFailure(string $reason, array $context): void
    {
        try {
            ($this->notifyFailure)($this->client->nodeId(), $reason, $context);
        } catch (\Throwable $exception) {
            throw new RuntimeException('Independent integrity-node owner alert delivery failed.', 0, $exception);
        }
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
