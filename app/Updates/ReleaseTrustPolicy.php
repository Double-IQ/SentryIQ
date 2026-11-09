<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use InvalidArgumentException;
use RuntimeException;

/**
 * Evaluates normalized claims only after a maintained Sigstore/GitHub verifier
 * has cryptographically verified the attestation bundle.
 *
 * This class is a policy gate, not a cryptographic signature verifier.
 */
final class ReleaseTrustPolicy
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';

    /**
     * @param array<string, mixed> $verifiedClaims Claims emitted by a trusted,
     *        independently successful attestation-verification adapter.
     */
    public function assertTrustedRelease(
        array $verifiedClaims,
        string $version,
        string $expectedCommit,
        string $artifactSha256,
        string $installedVersion
    ): void {
        $version = $this->normalizeVersion($version);
        $installedVersion = $this->normalizeVersion($installedVersion);
        $expectedCommit = strtolower(trim($expectedCommit));
        $artifactSha256 = strtolower(trim($artifactSha256));

        if (!preg_match('/^[a-f0-9]{40}$/', $expectedCommit)) {
            throw new InvalidArgumentException('Expected release commit must be a full Git SHA.');
        }
        if (!preg_match('/^[a-f0-9]{64}$/', $artifactSha256)) {
            throw new InvalidArgumentException('Artifact digest must be a SHA-256 hex digest.');
        }

        if (($verifiedClaims['cryptographically_verified'] ?? false) !== true) {
            throw new RuntimeException('Release attestation has not been cryptographically verified.');
        }

        if ((string)($verifiedClaims['repository_id'] ?? '') !== self::REPOSITORY_ID
            || (string)($verifiedClaims['repository'] ?? '') !== self::REPOSITORY) {
            throw new RuntimeException('Release attestation repository identity is not trusted.');
        }

        $tag = 'v' . $version;
        $expectedRef = 'refs/tags/' . $tag;
        $expectedWorkflowRef = self::REPOSITORY . '/' . self::WORKFLOW_PATH . '@' . $expectedRef;

        if ((string)($verifiedClaims['source_ref'] ?? '') !== $expectedRef) {
            throw new RuntimeException('Release attestation source ref does not match the requested version tag.');
        }
        if ((string)($verifiedClaims['source_commit'] ?? '') !== $expectedCommit) {
            throw new RuntimeException('Release attestation source commit does not match the approved release commit.');
        }
        if ((string)($verifiedClaims['workflow_path'] ?? '') !== self::WORKFLOW_PATH
            || (string)($verifiedClaims['workflow_ref'] ?? '') !== $expectedWorkflowRef) {
            throw new RuntimeException('Release attestation workflow identity is not approved.');
        }
        if ((string)($verifiedClaims['source_event'] ?? '') !== 'push') {
            throw new RuntimeException('Release attestation was not produced by the approved tag-push event.');
        }

        $subjectDigest = strtolower((string)($verifiedClaims['subject_sha256'] ?? ''));
        if (!hash_equals($artifactSha256, $subjectDigest)) {
            throw new RuntimeException('Release attestation subject digest does not match the downloaded package.');
        }

        if (version_compare($version, $installedVersion, '<=')) {
            throw new RuntimeException('Release version is not newer than the installed version; rollback and replay are rejected.');
        }
    }

    private function normalizeVersion(string $version): string
    {
        $version = trim($version);
        if (str_starts_with($version, 'v')) {
            $version = substr($version, 1);
        }
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new InvalidArgumentException('Release version must use the stable MAJOR.MINOR.PATCH format.');
        }
        return $version;
    }
}
