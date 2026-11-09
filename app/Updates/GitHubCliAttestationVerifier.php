<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Runs GitHub CLI's maintained Sigstore verifier and applies SentryIQ policy
 * only to certificate and statement data returned after successful verification.
 *
 * This class does not implement cryptography. A successful "gh attestation
 * verify" exit is mandatory before JSON output is considered.
 */
final class GitHubCliAttestationVerifier
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const REPOSITORY_URI = 'https://github.com/Double-IQ/SentryIQ';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';
    private const WORKFLOW_URI_PREFIX = self::REPOSITORY_URI . '/' . self::WORKFLOW_PATH . '@';
    private const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
    private const PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';

    /** @var callable|null Test seam. Never configure this in production. */
    private $runner;

    public function __construct(
        private readonly ReleaseTrustPolicy $policy,
        private readonly string $ghBinary = 'gh',
        ?callable $runner = null
    ) {
        $this->runner = $runner;
    }

    /**
     * @throws RuntimeException when the verifier is unavailable or any trust
     *         claim does not match the expected release.
     */
    public function assertTrustedArtifact(
        string $artifactPath,
        string $version,
        string $expectedCommit,
        string $installedVersion
    ): void {
        $path = realpath($artifactPath);
        if ($path === false || !is_file($path) || is_link($artifactPath) || !is_readable($path)) {
            throw new RuntimeException('Release artifact must be a readable regular file, not a symbolic link.');
        }

        $version = trim($version);
        if (str_starts_with($version, 'v')) {
            $version = substr($version, 1);
        }
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Release version must use stable MAJOR.MINOR.PATCH format.');
        }
        $expectedCommit = strtolower(trim($expectedCommit));
        if (!preg_match('/^[a-f0-9]{40}$/', $expectedCommit)) {
            throw new RuntimeException('Expected release commit must be a full Git SHA.');
        }

        $artifactDigest = hash_file('sha256', $path);
        if (!is_string($artifactDigest) || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
            throw new RuntimeException('Unable to calculate the release artifact SHA-256 digest.');
        }

        $tagRef = 'refs/tags/v' . $version;
        $command = [
            $this->ghBinary,
            'attestation',
            'verify',
            $path,
            '--repo', self::REPOSITORY,
            '--signer-workflow', self::REPOSITORY . '/' . self::WORKFLOW_PATH,
            '--cert-oidc-issuer', self::OIDC_ISSUER,
            '--source-ref', $tagRef,
            '--predicate-type', self::PREDICATE_TYPE,
            '--deny-self-hosted-runners',
            '--format', 'json',
        ];

        [$exitCode, $stdout, $stderr] = $this->run($command);
        if ($exitCode !== 0) {
            // Do not include verifier output in the exception; it may contain
            // untrusted or sensitive diagnostic content.
            throw new RuntimeException('GitHub CLI attestation verification failed (exit ' . $exitCode . ').');
        }

        try {
            $results = json_decode($stdout, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('GitHub CLI returned invalid verification JSON.', 0, $exception);
        }
        if (!is_array($results) || $results === [] || array_is_list($results) === false) {
            throw new RuntimeException('GitHub CLI returned no verified attestation results.');
        }

        $lastFailure = null;
        foreach ($results as $result) {
            try {
                $claims = $this->claimsFromVerifiedResult($result, $artifactDigest, $tagRef);
                $this->policy->assertTrustedRelease(
                    $claims,
                    $version,
                    $expectedCommit,
                    $artifactDigest,
                    $installedVersion
                );
                return;
            } catch (\Throwable $exception) {
                $lastFailure = $exception;
            }
        }

        throw new RuntimeException(
            'No cryptographically verified attestation satisfied the SentryIQ release policy.',
            0,
            $lastFailure
        );
    }

    /**
     * Only call this with one entry from successful "gh attestation verify
     * --format json" output. Certificate extensions are signed identity claims;
     * the in-toto subject digest is additionally checked against the local file.
     *
     * @param mixed $result
     * @return array<string, mixed>
     */
    private function claimsFromVerifiedResult($result, string $artifactDigest, string $tagRef): array
    {
        if (!is_array($result)) {
            throw new RuntimeException('Malformed verified attestation result.');
        }
        $verification = $result['verificationResult'] ?? null;
        $certificate = is_array($verification) ? ($verification['signature']['certificate'] ?? null) : null;
        $statement = is_array($verification) ? ($verification['statement'] ?? null) : null;
        if (!is_array($certificate) || !is_array($statement)) {
            throw new RuntimeException('Verified attestation is missing certificate or statement evidence.');
        }

        $timestamps = $verification['verifiedTimestamps'] ?? null;
        if (!is_array($timestamps) || $timestamps === []) {
            throw new RuntimeException('Verified attestation has no independently verified timestamp evidence.');
        }

        $subjects = $statement['subject'] ?? null;
        if (!is_array($subjects) || $subjects === []) {
            throw new RuntimeException('Verified attestation has no subject entries.');
        }
        $subjectMatches = false;
        foreach ($subjects as $subject) {
            $digest = is_array($subject) ? ($subject['digest']['sha256'] ?? null) : null;
            if (is_string($digest) && hash_equals($artifactDigest, strtolower($digest))) {
                $subjectMatches = true;
                break;
            }
        }
        if (!$subjectMatches) {
            throw new RuntimeException('Attested subject digest does not match the downloaded artifact.');
        }
        if (($statement['predicateType'] ?? '') !== self::PREDICATE_TYPE) {
            throw new RuntimeException('Attestation predicate type is not approved.');
        }

        $buildSignerUri = (string)($certificate['buildSignerURI'] ?? '');
        $buildConfigUri = (string)($certificate['buildConfigURI'] ?? '');
        $expectedWorkflowUri = self::WORKFLOW_URI_PREFIX . $tagRef;
        if ($buildSignerUri !== $expectedWorkflowUri || $buildConfigUri !== $expectedWorkflowUri) {
            throw new RuntimeException('Certificate workflow identity does not match the approved release workflow.');
        }
        // GitHub CLI emits subjectAlternativeName as a plain URI string.
        // Do not assume the object shape used by our earlier synthetic fixture.
        $san = $certificate['subjectAlternativeName'] ?? '';
        if (!is_string($san) || $san !== $expectedWorkflowUri) {
            throw new RuntimeException('Certificate subject alternative name does not match the approved workflow.');
        }

        if (($certificate['issuer'] ?? '') !== self::OIDC_ISSUER) {
            throw new RuntimeException('Certificate OIDC issuer is not GitHub Actions.');
        }
        if (($certificate['runnerEnvironment'] ?? '') !== 'github-hosted') {
            throw new RuntimeException('Release attestation was not produced on a GitHub-hosted runner.');
        }

        $sourceCommit = strtolower((string)($certificate['sourceRepositoryDigest'] ?? ''));
        $signerCommit = strtolower((string)($certificate['buildSignerDigest'] ?? ''));
        $configCommit = strtolower((string)($certificate['buildConfigDigest'] ?? ''));
        if ($sourceCommit === '' || $signerCommit !== $sourceCommit || $configCommit !== $sourceCommit) {
            throw new RuntimeException('Source, signer, and workflow configuration commits do not agree.');
        }

        return [
            // This flag is created only after the real verifier exited successfully.
            'cryptographically_verified' => true,
            'repository_id' => (string)($certificate['sourceRepositoryIdentifier'] ?? ''),
            'repository' => $this->repositoryName((string)($certificate['sourceRepositoryURI'] ?? '')),
            'source_ref' => (string)($certificate['sourceRepositoryRef'] ?? ''),
            'source_commit' => $sourceCommit,
            'workflow_commit' => $signerCommit,
            'workflow_path' => self::WORKFLOW_PATH,
            'workflow_ref' => self::REPOSITORY . '/' . self::WORKFLOW_PATH . '@' . (string)($certificate['sourceRepositoryRef'] ?? ''),
            'source_event' => (string)($certificate['buildTrigger'] ?? ''),
            'subject_sha256' => $artifactDigest,
        ];
    }

    private function repositoryName(string $repositoryUri): string
    {
        if ($repositoryUri !== self::REPOSITORY_URI) {
            return '';
        }
        return self::REPOSITORY;
    }

    /**
     * @param string[] $command
     * @return array{0:int,1:string,2:string}
     */
    private function run(array $command): array
    {
        if ($this->runner !== null) {
            $result = ($this->runner)($command);
            if (!is_array($result) || count($result) !== 3) {
                throw new RuntimeException('Attestation verifier runner returned an invalid result.');
            }
            return [(int)$result[0], (string)$result[1], (string)$result[2]];
        }

        if ($this->ghBinary === '' || !str_starts_with($this->ghBinary, '/')) {
            throw new RuntimeException('Configure GitHub CLI using an administrator-controlled absolute binary path.');
        }
        if (!is_file($this->ghBinary) || !is_executable($this->ghBinary) || is_link($this->ghBinary)) {
            throw new RuntimeException('Configured GitHub CLI binary is missing, non-executable, or a symbolic link.');
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = @proc_open($command, $descriptors, $pipes, null, null, ['bypass_shell' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start GitHub CLI. Install and configure a supported gh version.');
        }

        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = '';
        $stderr = '';
        $exitCode = -1;
        $deadline = microtime(true) + 60.0;
        $maxBytes = 1048576;

        while (true) {
            $read = [];
            if (!feof($pipes[1])) $read[] = $pipes[1];
            if (!feof($pipes[2])) $read[] = $pipes[2];
            if ($read !== []) {
                $write = null;
                $except = null;
                @stream_select($read, $write, $except, 0, 200000);
                foreach ($read as $stream) {
                    $chunk = fread($stream, 8192);
                    if (!is_string($chunk) || $chunk === '') continue;
                    if ($stream === $pipes[1]) $stdout .= $chunk;
                    else $stderr .= $chunk;
                    if (strlen($stdout) + strlen($stderr) > $maxBytes) {
                        proc_terminate($process, 9);
                        fclose($pipes[1]);
                        fclose($pipes[2]);
                        proc_close($process);
                        throw new RuntimeException('GitHub CLI verification output exceeded the configured limit.');
                    }
                }
            } else {
                usleep(100000);
            }

            $status = proc_get_status($process);
            if (!$status['running']) {
                $exitCode = (int)$status['exitcode'];
                $stdout .= (string)stream_get_contents($pipes[1]);
                $stderr .= (string)stream_get_contents($pipes[2]);
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($process, 9);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                throw new RuntimeException('GitHub CLI attestation verification timed out.');
            }
        }

        fclose($pipes[1]);
        fclose($pipes[2]);
        $closeCode = proc_close($process);
        if ($exitCode < 0) $exitCode = $closeCode;
        if (strlen($stdout) + strlen($stderr) > $maxBytes) {
            throw new RuntimeException('GitHub CLI verification output exceeded the configured limit.');
        }
        return [$exitCode, $stdout, $stderr];
    }
}
