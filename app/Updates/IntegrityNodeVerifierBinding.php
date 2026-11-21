<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

require_once __DIR__ . '/IntegrityNodeA.php';
require_once __DIR__ . '/IntegrityNodeB.php';
require_once __DIR__ . '/IntegrityNodeC.php';

/**
 * Sealed binding from a scheduled identity to its concrete final verifier.
 * Arbitrary callables cannot replace the node's verification policy.
 */
final class IntegrityNodeVerifierBinding
{
    public function __construct(
        private readonly string $nodeId,
        private readonly IntegrityNodeA|IntegrityNodeB|IntegrityNodeC $node
    ) {
        $classIdentity = match (true) {
            $node instanceof IntegrityNodeA => 'integrity-a',
            $node instanceof IntegrityNodeB => 'integrity-b',
            $node instanceof IntegrityNodeC => 'integrity-c',
        };
        if (!in_array($nodeId, ['integrity-a', 'integrity-b', 'integrity-c'], true)
            || $classIdentity !== $nodeId) {
            throw new RuntimeException('Scheduled verifier binding must use the concrete node class for its exact identity.');
        }
    }

    public function nodeId(): string
    {
        return $this->nodeId;
    }

    /**
     * @param list<string> $publicPaths
     * @return array<string,mixed>
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
        return $this->node->verify(
            $manifestPath,
            $artifactPath,
            $releaseVersion,
            $commit,
            $installedVersion,
            $origin,
            $publicPaths,
            $nonce
        );
    }
}
