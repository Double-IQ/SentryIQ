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
    public static function claims(Envelope $envelope, string $workflowCommit, string $expectedVersion, string $expectedDigest, ?string $expectedSubjectName = null): array
    {
        $statement = Statement::fromEnvelope($envelope);
        $claims = self::claimsFromArray($statement->toArray(), $workflowCommit, $expectedVersion, $expectedDigest, $expectedSubjectName);
        $claims['cryptographically_verified'] = true;
        return $claims;
    }

    /** @param array<string, mixed> $statement */
    public static function claimsFromArray(array $statement, string $workflowCommit, string $expectedVersion, string $expectedDigest, ?string $expectedSubjectName = null): array
    {
        if (($statement['predicateType'] ?? null) !== self::PREDICATE_TYPE) {
            throw new RuntimeException('Release attestation does not contain SLSA Provenance v1.');
        }

        $subjects = $statement['subject'] ?? null;
        $expectedZipName = 'sentryiq-' . $expectedVersion . '.zip';
        $expectedSubjectName ??= $expectedZipName;
        if (!is_array($subjects) || !array_is_list($subjects) || count($subjects) < 1 || count($subjects) > 2
            || !in_array($expectedSubjectName, ['release-manifest.json', $expectedZipName], true)) {
            throw new RuntimeException('Release attestation subject set is missing, oversized, or outside the canonical release assets.');
        }

        $seenSubjects = [];
        $matchedSubject = false;
        foreach ($subjects as $subject) {
            if (!is_array($subject) || !is_string($subject['name'] ?? null)
                || !is_array($subject['digest'] ?? null)
                || !is_string($subject['digest']['sha256'] ?? null)
                || !preg_match('/^[a-f0-9]{64}$/i', $subject['digest']['sha256'])) {
                throw new RuntimeException('Release attestation contains a malformed artifact subject.');
            }
            $name = $subject['name'];
            if (!in_array($name, ['release-manifest.json', $expectedZipName], true)
                || isset($seenSubjects[$name])) {
                throw new RuntimeException('Release attestation contains an unknown or duplicate artifact subject.');
            }
            $seenSubjects[$name] = strtolower($subject['digest']['sha256']);
            if ($name === $expectedSubjectName) {
                $matchedSubject = hash_equals(strtolower($expectedDigest), $seenSubjects[$name]);
            }
        }

        // The current release workflow attests the manifest and ZIP together.
        // Accept a single ZIP subject only for historical releases predating
        // the separately published manifest; never accept a standalone manifest.
        if (count($subjects) === 2
            && (!isset($seenSubjects['release-manifest.json']) || !isset($seenSubjects[$expectedZipName]))) {
            throw new RuntimeException('Multi-subject release provenance must bind both the canonical manifest and ZIP.');
        }
        if (count($subjects) === 1 && $expectedSubjectName === 'release-manifest.json') {
            throw new RuntimeException('A release manifest must be attested together with its corresponding ZIP.');
        }
        if (!$matchedSubject) {
            throw new RuntimeException('Attestation subject name or digest does not match the expected release artifact.');
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

        // The workflow definition digest is authenticated in Fulcio's leaf
        // certificate (Build Config Digest, OID 1.3.6.1.4.1.57264.1.19).
        // It is supplied only after SigstoreVerifier authenticates that certificate.
        $workflowCommit = strtolower($workflowCommit);
        if (preg_match('/^[a-f0-9]{40}$/', $workflowCommit) !== 1) {
            throw new RuntimeException('Authenticated Fulcio Build Config Digest is not a full workflow commit SHA.');
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
                && $uri === 'git+https://github.com/' . self::REPOSITORY . '@' . $expectedRef) {
                $sourceCommits[] = strtolower($commit);
            }
        }
        if (count($sourceCommits) !== 1 || preg_match('/^[a-f0-9]{40}$/', $sourceCommits[0]) !== 1) {
            throw new RuntimeException('SLSA provenance does not identify exactly one full source commit for this release tag.');
        }

        return [
            'repository' => self::REPOSITORY,
            'repository_id' => self::REPOSITORY_ID,
            'source_ref' => $expectedRef,
            'source_commit' => $sourceCommits[0],
            'workflow_commit' => $workflowCommit,
            'workflow_path' => self::WORKFLOW_PATH,
            'workflow_ref' => self::REPOSITORY . '/' . self::WORKFLOW_PATH . '@' . $expectedRef,
            'source_event' => 'push',
            'subject_sha256' => strtolower($expectedDigest),
        ];
    }
}
