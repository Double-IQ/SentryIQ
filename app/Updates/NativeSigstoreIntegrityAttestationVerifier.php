<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

require_once __DIR__ . '/ReleaseArtifactVerifier.php';
require_once __DIR__ . '/ReleaseTrustPolicy.php';
require_once __DIR__ . '/NativeSigstoreReleaseVerifier.php';

use RuntimeException;

/**
 * Production callable adapter for Integrity Node A/B/C.
 * Each release manifest and ZIP is independently verified as a GitHub
 * attestation subject before the shared release trust policy is applied.
 */
final class NativeSigstoreIntegrityAttestationVerifier
{
    public function __construct(
        private readonly ReleaseArtifactVerifier $verifier,
        private readonly ReleaseTrustPolicy $policy
    ) {
    }

    public static function fromPrivatePaths(string $vendorAutoloadPath, string $privateDataDirectory): self
    {
        return new self(
            new NativeSigstoreReleaseVerifier($vendorAutoloadPath, $privateDataDirectory),
            new ReleaseTrustPolicy()
        );
    }

    /**
     * Matches the IntegrityNodeA/B/C verifier callable contract.
     *
     * @throws RuntimeException unless the named artifact is attested and trusted.
     */
    public function __invoke(
        string $artifactPath,
        string $version,
        string $expectedCommit,
        string $installedVersion
    ): void {
        $realPath = realpath($artifactPath);
        if (!is_string($realPath) || !is_file($realPath) || is_link($artifactPath) || !is_readable($realPath)) {
            throw new RuntimeException('Integrity Node artifact must be a readable regular file.');
        }

        $version = trim($version);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Integrity Node release version must use MAJOR.MINOR.PATCH format.');
        }

        $filename = basename($realPath);
        $expectedZip = 'sentryiq-' . $version . '.zip';
        if ($filename !== 'release-manifest.json' && $filename !== $expectedZip) {
            throw new RuntimeException('Integrity Node supplied an artifact outside the approved release subject set.');
        }

        $digest = hash_file('sha256', $realPath);
        if (!is_string($digest) || !preg_match('/^[a-f0-9]{64}$/', $digest)) {
            throw new RuntimeException('Unable to calculate Integrity Node artifact SHA-256.');
        }

        $claims = $this->verifier->verifyArtifact($realPath, $version, $filename);
        $this->policy->assertTrustedRelease(
            $claims,
            $version,
            strtolower(trim($expectedCommit)),
            $digest,
            $installedVersion,
            true
        );
    }
}
