<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/ReleaseTrustPolicy.php';
require_once __DIR__ . '/../app/Updates/GitHubCliAttestationVerifier.php';

use SentryIQ\Updates\GitHubCliAttestationVerifier;
use SentryIQ\Updates\ReleaseTrustPolicy;

function cliVerifierReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$temp = tempnam(sys_get_temp_dir(), 'sentryiq-attest-');
if ($temp === false) throw new RuntimeException('Unable to create test artifact.');
file_put_contents($temp, 'synthetic test release package');
$digest = hash_file('sha256', $temp);
$commit = str_repeat('a', 40);
$version = '1.2.3';
$workflowUri = 'https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v1.2.3';

$verifiedOutput = [[
    'verificationResult' => [
        'signature' => [
            'certificate' => [
                'issuer' => 'https://token.actions.githubusercontent.com',
                'subjectAlternativeName' => ['type' => 'URI', 'value' => $workflowUri],
                'sourceRepositoryIdentifier' => '1345956206',
                'sourceRepositoryURI' => 'https://github.com/Double-IQ/SentryIQ',
                'sourceRepositoryDigest' => $commit,
                'sourceRepositoryRef' => 'refs/tags/v1.2.3',
                'buildSignerURI' => $workflowUri,
                'buildSignerDigest' => $commit,
                'buildConfigURI' => $workflowUri,
                'buildConfigDigest' => $commit,
                'buildTrigger' => 'push',
                'runnerEnvironment' => 'github-hosted',
            ],
        ],
        'verifiedTimestamps' => [['type' => 'Tlog', 'timestamp' => '2026-11-09T00:00:00Z']],
        'statement' => [
            'predicateType' => 'https://slsa.dev/provenance/v1',
            'subject' => [['name' => 'sentryiq-1.2.3.zip', 'digest' => ['sha256' => $digest]]],
        ],
    ],
]];

$capturedCommand = [];
$runner = static function (array $command) use (&$capturedCommand, $verifiedOutput): array {
    $capturedCommand = $command;
    return [0, json_encode($verifiedOutput, JSON_THROW_ON_ERROR), ''];
};
$verifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $runner);
$verifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2');

$requiredArgs = [
    'attestation', 'verify', '--repo', 'Double-IQ/SentryIQ',
    '--signer-workflow', 'Double-IQ/SentryIQ/.github/workflows/release.yml',
    '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
    '--source-ref', 'refs/tags/v1.2.3',
    '--predicate-type', 'https://slsa.dev/provenance/v1',
    '--deny-self-hosted-runners', '--format', 'json',
];
foreach ($requiredArgs as $argument) {
    if (!in_array($argument, $capturedCommand, true)) {
        throw new RuntimeException('Verifier command omitted required constraint: ' . $argument);
    }
}

$failureRunner = static fn(array $command): array => [1, '', 'verification failed'];
$failureVerifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $failureRunner);
cliVerifierReject(
    fn() => $failureVerifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2'),
    'A non-zero verifier exit must be rejected.'
);

$badOutput = $verifiedOutput;
$badOutput[0]['verificationResult']['signature']['certificate']['sourceRepositoryIdentifier'] = '999';
$badRunner = static fn(array $command): array => [0, json_encode($badOutput, JSON_THROW_ON_ERROR), ''];
$badVerifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $badRunner);
cliVerifierReject(
    fn() => $badVerifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2'),
    'A verified certificate from a different immutable repository ID must be rejected.'
);

$badDigest = $verifiedOutput;
$badDigest[0]['verificationResult']['statement']['subject'][0]['digest']['sha256'] = hash('sha256', 'wrong artifact');
$digestRunner = static fn(array $command): array => [0, json_encode($badDigest, JSON_THROW_ON_ERROR), ''];
$digestVerifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $digestRunner);
cliVerifierReject(
    fn() => $digestVerifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2'),
    'An attested subject digest that differs from the local artifact must be rejected.'
);

$missingEvidence = $verifiedOutput;
$missingEvidence[0]['verificationResult']['verifiedTimestamps'] = [];
$missingRunner = static fn(array $command): array => [0, json_encode($missingEvidence, JSON_THROW_ON_ERROR), ''];
$missingVerifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $missingRunner);
cliVerifierReject(
    fn() => $missingVerifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2'),
    'Missing verified timestamp evidence must be rejected.'
);

$certificateMutations = [
    'wrong source ref' => ['sourceRepositoryRef' => 'refs/heads/main'],
    'wrong source commit' => ['sourceRepositoryDigest' => str_repeat('b', 40)],
    'wrong signer commit' => ['buildSignerDigest' => str_repeat('b', 40)],
    'wrong workflow config commit' => ['buildConfigDigest' => str_repeat('b', 40)],
    'wrong event' => ['buildTrigger' => 'workflow_dispatch'],
    'wrong issuer' => ['issuer' => 'https://attacker.example'],
    'wrong runner' => ['runnerEnvironment' => 'self-hosted'],
    'wrong workflow signer' => ['buildSignerURI' => 'https://github.com/attacker/repo/.github/workflows/release.yml@refs/tags/v1.2.3'],
];
foreach ($certificateMutations as $label => $changes) {
    $mutated = $verifiedOutput;
    $mutated[0]['verificationResult']['signature']['certificate'] = array_replace(
        $mutated[0]['verificationResult']['signature']['certificate'],
        $changes
    );
    $mutatedRunner = static fn(array $command): array => [0, json_encode($mutated, JSON_THROW_ON_ERROR), ''];
    $mutatedVerifier = new GitHubCliAttestationVerifier(new ReleaseTrustPolicy(), 'gh', $mutatedRunner);
    cliVerifierReject(
        fn() => $mutatedVerifier->assertTrustedArtifact($temp, $version, $commit, '1.2.2'),
        'Certificate policy must reject ' . $label . '.'
    );
}

unlink($temp);
echo "GitHub CLI attestation adapter contract tests passed.\n";
