<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Binds one node's authenticated collector transport to its independently
 * pinned signature verifier and immutable expected inventory.
 *
 * Use this object as the private-host verification dependency for Node A or B.
 * It deliberately exposes no setter for credentials, key pins, or policy maps.
 */
final class PrivateHostAttestationGate
{
    public function __construct(
        private readonly string $nodeId,
        private readonly PrivateHostAttestationClient $client,
        private readonly PrivateHostAttestationVerifier $verifier,
        private readonly array $expectedFiles,
        private readonly array $expectedPrivateConfig
    ) {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b'], true)
            || $client->nodeId() !== $nodeId
            || $expectedFiles === []
            || count($expectedFiles) > 5000
            || count($expectedPrivateConfig) > 100) {
            throw new RuntimeException('Private-host gate identity or pinned inventory is invalid.');
        }
        // Force validation of all policy entries at construction time, before a scheduled run.
        foreach ($expectedFiles as $path => $digest) {
            if (!is_string($path) || $path === '' || !is_string($digest)
                || !preg_match('/^[a-f0-9]{64}$/', $digest)) {
                throw new RuntimeException('Private-host gate contains an invalid deployed-file pin.');
            }
        }
        foreach ($expectedPrivateConfig as $policyId => $digest) {
            if (!is_string($policyId) || !preg_match('/^[a-z0-9][a-z0-9._-]{1,95}$/', $policyId)
                || !is_string($digest) || !preg_match('/^[a-f0-9]{64}$/', $digest)) {
                throw new RuntimeException('Private-host gate contains an invalid private-config pin.');
            }
        }
    }

    public function nodeId(): string
    {
        return $this->nodeId;
    }

    public function credentialFingerprint(): string
    {
        return $this->client->credentialFingerprint();
    }

    public function collectorKeyFingerprint(): string
    {
        return $this->verifier->collectorKeyFingerprint();
    }

    /**
     * Callable contract consumed by IntegrityNodeA and IntegrityNodeB.
     *
     * @return array{approved:bool,mismatches:list<array<string,mixed>>}
     */
    public function __invoke(
        string $version,
        string $commit,
        string $manifestDigest,
        string $artifactDigest,
        string $nonce,
        array $manifest,
        string $origin
    ): array {
        if ($origin !== 'https://sentryiq.bichet.co.za') {
            throw new RuntimeException('Private-host gate refuses an unexpected SentryIQ origin.');
        }
        $envelope = $this->client->request(
            $nonce,
            $version,
            $commit,
            $manifestDigest,
            $artifactDigest
        );
        $result = $this->verifier->assertAttested(
            $envelope,
            $nonce,
            $version,
            $commit,
            $manifestDigest,
            $artifactDigest,
            $this->expectedFiles,
            $this->expectedPrivateConfig
        );
        return [
            'approved' => $result['approved'],
            'mismatches' => $result['mismatches'],
        ];
    }
}
