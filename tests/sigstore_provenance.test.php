<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/SigstoreProvenance.php';

use SentryIQ\Updates\SigstoreProvenance;

function provenanceAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function provenanceReject(array $statement, string $message): void
{
    try {
        SigstoreProvenance::claimsFromArray($statement, '0.1.2', str_repeat('a', 64));
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$commit = '9c639a4792cadd5421f01ed198ba2a9261c5145f';
$statement = [
    '_type' => 'https://in-toto.io/Statement/v1',
    'subject' => [[
        'name' => 'sentryiq-0.1.2.zip',
        'digest' => ['sha256' => str_repeat('a', 64)],
    ]],
    'predicateType' => SigstoreProvenance::PREDICATE_TYPE,
    'predicate' => [
        'buildDefinition' => [
            'buildType' => 'https://actions.github.io/buildtypes/workflow/v1',
            'externalParameters' => [
                'workflow' => [
                    'ref' => 'refs/tags/v0.1.2',
                    'repository' => 'https://github.com/Double-IQ/SentryIQ',
                    'path' => '.github/workflows/release.yml',
                ],
            ],
            'internalParameters' => [
                'github' => [
                    'event_name' => 'push',
                    'repository_id' => '1345956206',
                    'runner_environment' => 'github-hosted',
                ],
            ],
            'resolvedDependencies' => [[
                'uri' => 'git+https://github.com/Double-IQ/SentryIQ@refs/tags/v0.1.2',
                'digest' => ['gitCommit' => $commit],
            ]],
        ],
        'runDetails' => [
            'builder' => [
                'id' => 'https://github.com/Double-IQ/SentryIQ/.github/workflows/release.yml@refs/tags/v0.1.2',
            ],
        ],
    ],
];

$claims = SigstoreProvenance::claimsFromArray($statement, '0.1.2', str_repeat('a', 64));
provenanceAssert($claims['source_commit'] === $commit, 'Source commit must be extracted from the SLSA resolved dependency.');
provenanceAssert($claims['repository_id'] === '1345956206', 'Repository ID must be pinned.');
provenanceAssert(!array_key_exists('cryptographically_verified', $claims), 'Unverified parsed JSON must never be marked cryptographically verified.');

$mutations = [
    'wrong subject name' => static function (array &$s): void { $s['subject'][0]['name'] = 'other.zip'; },
    'wrong subject digest' => static function (array &$s): void { $s['subject'][0]['digest']['sha256'] = str_repeat('b', 64); },
    'wrong predicate type' => static function (array &$s): void { $s['predicateType'] = 'https://example.test/predicate'; },
    'wrong repository URL' => static function (array &$s): void { $s['predicate']['buildDefinition']['externalParameters']['workflow']['repository'] = 'https://github.com/attacker/SentryIQ'; },
    'wrong workflow path' => static function (array &$s): void { $s['predicate']['buildDefinition']['externalParameters']['workflow']['path'] = '.github/workflows/other.yml'; },
    'wrong tag ref' => static function (array &$s): void { $s['predicate']['buildDefinition']['externalParameters']['workflow']['ref'] = 'refs/tags/v9.9.9'; },
    'wrong repository id' => static function (array &$s): void { $s['predicate']['buildDefinition']['internalParameters']['github']['repository_id'] = '999'; },
    'wrong event' => static function (array &$s): void { $s['predicate']['buildDefinition']['internalParameters']['github']['event_name'] = 'workflow_dispatch'; },
    'wrong runner' => static function (array &$s): void { $s['predicate']['buildDefinition']['internalParameters']['github']['runner_environment'] = 'self-hosted'; },
    'wrong builder identity' => static function (array &$s): void { $s['predicate']['runDetails']['builder']['id'] = 'https://example.test/builder'; },
    'wrong source commit' => static function (array &$s): void { $s['predicate']['buildDefinition']['resolvedDependencies'][0]['digest']['gitCommit'] = str_repeat('b', 40); },
    'wrong source URI' => static function (array &$s): void { $s['predicate']['buildDefinition']['resolvedDependencies'][0]['uri'] = 'git+https://github.com/attacker/SentryIQ@refs/tags/v0.1.2'; },
    'duplicate source dependencies' => static function (array &$s): void { $s['predicate']['buildDefinition']['resolvedDependencies'][] = $s['predicate']['buildDefinition']['resolvedDependencies'][0]; },
    'multiple subjects' => static function (array &$s): void { $s['subject'][] = $s['subject'][0]; },
];

foreach ($mutations as $label => $mutate) {
    $tampered = $statement;
    $mutate($tampered);
    provenanceReject($tampered, 'Provenance parser must reject ' . $label . '.');
}

echo "SLSA provenance claim tests passed.\n";
