<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use K2gl\Dsse\Envelope;
use K2gl\InToto\Statement;
use RuntimeException;

/**
 * Reads SLSA Provenance v1 claims from an authenticated in-toto DSSE envelope.
 *
 * Call only with the Envelope returned by SigstoreVerifier::verify(). Parsing
 * this payload alone does not authenticate it.
 */
final class SigstoreProvenance
{
    public const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';
    public const REPOSITORY = 'Double-IQ/SentryIQ';
    public const REPOSITORY_ID = '1345956206';
    public const WORKFLOW_PATH = '.github/workflows/release.yml';

    /** @return array<string, mixed> */
    public static function claims(Envelope $envelope, string $expectedVersion, string $expectedDigest): array
    {
        $statement = Statement::fromEnvelope($envelope);
        return self::claimsFromArray($statement->toArray(), $expectedVersion, $expectedDigest);
    }

    /** @param array<string, mixed> $statement */
    public static function claimsFromArray(array $statement, string $expectedVersion, string $expectedDigest): array
    {
        if (($statement['predicateType'] ?? null) !== self::PREDICATE_TYPE) {
            throw new RuntimeException('Release attestation does not contain SLSA Provenance v1.');
        }

        $subjects = $statement['subject'] ?? null;
        if (!is_array($subjects) || count($subjects) !== 1 || !is_array($subjects[0] ?? null)) {
            throw new RuntimeException('Release attestation must identify exactly one artifact subject.');
        }
        $subject = $subjects[0];
        if ($subject->name !== 'sentryiq-' . $expectedVersion . '.zip'
            || strtolower((string)($subject->digest['sha256'] ?? '')) !== strtolower($expectedDigest)) {
            throw new RuntimeException('Attestation subject name or digest does not match the downloaded release ZIP.');
        }

        $predicate = $statement['predicate'] ?? null;
        if (!is_array($predicate)) {
            throw new RuntimeException('SLSA provenance predicate is missing or invalid.');
        }
        $definition = $predicate['buildDefinition'] ?? null;
        $external = is_array($definition) ? ($definition['externalParameters'] ?? null) : null;
        $workflow = is_array($external) ? ($external['workflow'] ?? null) : null;
        $internal = is_array($definition) ? ($definition['internalParameters'] ?? null) : null;
        $github = is_array($internal) ? ($internal['github'] ?? null) : null;
        $dependencies = is_array($definition) ? ($definition['resolvedDependencies'] ?? null) : null;
        $runDetails = $predicate['runDetails'] ?? null;
        $builder = is_array($runDetails) ? ($runDetails['builder'] ?? null) : null;

        if (!is_array($workflow) || !is_array($github) || !is_array($dependencies) || !is_array($builder)) {
            throw new RuntimeException('SLSA provenance is missing required build identity fields.');
        }

        $expectedRef = 'refs/tags/v' . $expectedVersion;
        if (($workflow['repository'] ?? null) !== 'https://github.com/' . self::REPOSITORY
            || ($workflow['path'] ?? null) !== self::WORKFLOW_PATH
            || ($workflow['ref'] ?? null) !== $expectedRef) {
            throw new RuntimeException('SLSA provenance workflow repository, path, or tag is not trusted.');
        }

        if ((string)($github['repository_id'] ?? '') !== self::REPOSITORY_ID
            || ($github['event_name'] ?? null) !== 'push'
            || ($github['runner_environment'] ?? null) !== 'github-hosted') {
            throw new RuntimeException('SLSA provenance GitHub repository or execution context is not trusted.');
        }

        $expectedBuilder = 'https://github.com/' . self::REPOSITORY . '/' . self::WORKFLOW_PATH . '@' . $expectedRef;
        if (($builder['id'] ?? null) !== $expectedBuilder) {
            throw new RuntimeException('SLSA provenance builder identity is not the approved release workflow.');
        }

        $sourceCommits = [];
        foreach ($dependencies as $dependency) {
            if (!is_array($dependency) || !is_array($dependency['digest'] ?? null)) {
                continue;
            }
            $uri = $dependency['uri'] ?? null;
            $commit = $dependency['digest']['gitCommit'] ?? null;
            if (is_string($uri) && is_string($commit)
                && str_starts_with($uri, 'git+https://github.com/' . self::REPOSITORY . '@' . $expectedRef)) {
                $sourceCommits[] = strtolower($commit);
            }
        }
        $sourceCommits = array_values(array_unique($sourceCommits));
        if (count($sourceCommits) !== 1 || preg_match('/^[a-f0-9]{40}$/', $sourceCommits[0]) !== 1) {
            throw new RuntimeException('SLSA provenance does not identify exactly one full source commit for this release tag.');
        }

        return [
            'cryptographically_verified' => true,
            'repository' => self::REPOSITORY,
            'repository_id' => self::REPOSITORY_ID,
            'source_ref' => $expectedRef,
            'source_commit' => $sourceCommits[0],
            'workflow_path' => self::WORKFLOW_PATH,
            'workflow_ref' => self::REPOSITORY . '/' . self::WORKFLOW_PATH . '@' . $expectedRef,
            'source_event' => 'push',
            'subject_sha256' => strtolower($expectedDigest),
        ];
    }
}
