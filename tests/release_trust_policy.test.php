<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/ReleaseTrustPolicy.php';

use SentryIQ\Updates\ReleaseTrustPolicy;

function trustCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function trustReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$policy = new ReleaseTrustPolicy();
$commit = str_repeat('a', 40);
$digest = hash('sha256', 'synthetic release archive');
$version = '1.2.3';
$claims = [
    // This flag represents a result from an external cryptographic verifier.
    // These unit tests do not perform or simulate signature verification.
    'cryptographically_verified' => true,
    'repository_id' => '1345956206',
    'repository' => 'Double-IQ/SentryIQ',
    'source_ref' => 'refs/tags/v1.2.3',
    'source_commit' => $commit,
    'workflow_path' => '.github/workflows/release.yml',
    'workflow_ref' => 'Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v1.2.3',
    'source_event' => 'push',
    'subject_sha256' => $digest,
];

$policy->assertTrustedRelease($claims, $version, $commit, $digest, '1.2.2');
trustCheck(true, 'Valid normalized release claims should pass.');

$mutations = [
    'unverified attestation' => ['cryptographically_verified' => false],
    'wrong repository id' => ['repository_id' => '999999999'],
    'wrong repository name' => ['repository' => 'attacker/SentryIQ'],
    'wrong tag' => ['source_ref' => 'refs/tags/v9.9.9'],
    'wrong source commit' => ['source_commit' => str_repeat('b', 40)],
    'wrong workflow path' => ['workflow_path' => '.github/workflows/other.yml'],
    'wrong workflow ref' => ['workflow_ref' => 'attacker/SentryIQ/.github/workflows/release.yml@refs/tags/v1.2.3'],
    'wrong triggering event' => ['source_event' => 'workflow_dispatch'],
    'wrong artifact digest' => ['subject_sha256' => hash('sha256', 'different archive')],
];

foreach ($mutations as $label => $changes) {
    $tampered = array_replace($claims, $changes);
    trustReject(
        fn() => $policy->assertTrustedRelease($tampered, $version, $commit, $digest, '1.2.2'),
        'Policy must reject ' . $label . '.'
    );
}

trustReject(
    fn() => $policy->assertTrustedRelease($claims, '1.2.3', $commit, $digest, '1.2.3'),
    'Policy must reject replay of the installed version.'
);
trustReject(
    fn() => $policy->assertTrustedRelease($claims, '1.2.2', $commit, $digest, '1.2.3'),
    'Policy must reject rollback to an older version.'
);
trustReject(
    fn() => $policy->assertTrustedRelease($claims, '1.2.3-rc.1', $commit, $digest, '1.2.2'),
    'Policy must reject non-stable release versions.'
);
trustReject(
    fn() => $policy->assertTrustedRelease($claims, $version, 'not-a-commit', $digest, '1.2.2'),
    'Policy must reject an invalid expected commit.'
);

echo "Release trust policy tests passed.\n";
