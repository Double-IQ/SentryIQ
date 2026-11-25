<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use Throwable;

require_once __DIR__ . '/IntegrityNodeAlertedException.php';
require_once __DIR__ . '/IntegrityNodeReleaseStateStore.php';
require_once __DIR__ . '/IntegrityNodeEvidenceStore.php';
require_once __DIR__ . '/IntegrityNodeVerifierBinding.php';

/**
 * One scheduled execution of an independently hosted Integrity Node.
 *
 * Release selection is injected because each host must obtain the deployed
 * release identity from its administrator-controlled source; GitHub's newest
 * release must never be assumed to be deployed already.
 */
final class IntegrityNodeScheduledRunner
{
    /** @var callable():array{version:string,commit:string} */
    private $resolveRelease;

    /** @var callable(string,string,array<string,mixed>):void */
    private $notifyFailure;

    public function __construct(
        private readonly string $nodeId,
        private readonly IntegrityReleaseArtifactFetcher $artifactFetcher,
        callable $resolveRelease,
        private readonly IntegrityNodeVerifierBinding $verifier,
        callable $notifyFailure,
        private readonly string $privateDataDirectory,
        private readonly string $publicWebRoot,
        private readonly string $targetOrigin,
        private readonly array $publicPaths,
        private readonly IntegrityNodeReleaseStateStore $releaseState,
        private readonly ?IntegrityNodeEventRunner $eventRunner = null,
        private readonly ?IntegrityNodeEvidenceStore $evidenceStore = null,
    ) {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b', 'integrity-c'], true)) {
            throw new RuntimeException('Scheduled runner requires a known independent Integrity Node identity.');
        }
        if ($this->verifier->nodeId() !== $nodeId) {
            throw new RuntimeException('Scheduled runner identity must match its concrete node verifier binding.');
        }
        $parts = parse_url($targetOrigin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || $targetOrigin !== 'https://sentryiq.bichet.co.za'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('Scheduled runner target must be the exact canonical SentryIQ HTTPS origin without a port or path.');
        }
        if (!array_is_list($publicPaths)) {
            throw new RuntimeException('Scheduled runner public-path selection must be a list.');
        }
        if ($nodeId !== 'integrity-c' && $eventRunner !== null && $eventRunner->nodeId() !== $nodeId) {
            throw new RuntimeException('Scheduled runner and Node 4 event client identities must match exactly.');
        }
        if ($nodeId === 'integrity-c' && ($eventRunner !== null || $evidenceStore === null)) {
            throw new RuntimeException('Node C must use private local evidence retention and remain independent of Node 4.');
        }
        if ($nodeId !== 'integrity-c' && ($eventRunner === null || $evidenceStore !== null)) {
            throw new RuntimeException('Nodes A and B require the authenticated Node 4 event exchange.');
        }
        $this->resolveRelease = $resolveRelease;
        $this->notifyFailure = $notifyFailure;
    }

    /** @return array<string,mixed> */
    public function run(): array
    {
        try {
            return $this->releaseState->runExclusive(fn(): array => $this->runLocked());
        } catch (Throwable $exception) {
            if (!$this->wasAlreadyAlerted($exception)) {
                $this->alertFailure($exception);
            }
            throw new RuntimeException('Scheduled integrity execution failed; independent owner alert was attempted.', 0, $exception);
        }
    }

    /** @return array<string,mixed> */
    private function runLocked(): array
    {
        $baseline = $this->releaseState->current();
        try {
            $release = ($this->resolveRelease)();
            if (!is_array($release)
                || !is_string($release['version'] ?? null)
                || !is_string($release['commit'] ?? null)
                || !preg_match('/^[a-f0-9]{40}$/i', $release['commit'])) {
                throw new RuntimeException('Release resolver must return the deployed stable version and its full source commit SHA.');
            }
            $version = trim($release['version']);
            if (str_starts_with($version, 'v')) {
                $version = substr($version, 1);
            }
            if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
                throw new RuntimeException('Release resolver version must use stable MAJOR.MINOR.PATCH format.');
            }
            $commit = strtolower($release['commit']);
            $this->releaseState->assertCandidateIdentity($version, $commit);
            $installedVersion = $baseline['version'];
            $staged = $this->artifactFetcher->fetch(
                $version,
                rtrim($this->privateDataDirectory, '/') . '/integrity-releases/' . $version,
                $this->publicWebRoot
            );
            $manifestDigest = hash_file('sha256', $staged['manifest_path']);
            $artifactDigest = hash_file('sha256', $staged['artifact_path']);
            if (!is_string($manifestDigest) || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
                || !is_string($artifactDigest) || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
                throw new RuntimeException('Unable to calculate staged release artifact digests.');
            }
            $this->releaseState->assertCandidate($version, $commit, $manifestDigest, $artifactDigest);
        } catch (Throwable $exception) {
            throw new RuntimeException('Release selection or artifact staging failed.', 0, $exception);
        }

        $verify = fn(string $nonce): array => $this->verifier->verify(
            $staged['manifest_path'],
            $staged['artifact_path'],
            $version,
            $commit,
            $installedVersion,
            $this->targetOrigin,
            $this->publicPaths,
            $nonce
        );

        // The A/B event runner already performs direct alerts for verification
        // and Node 4 transport failures. Do not send a duplicate alert here.
        if ($this->eventRunner !== null) {
            $result = $this->eventRunner->run(
                $verify,
                $staged['manifest_path'],
                $staged['artifact_path'],
                $version,
                $commit,
                $this->targetOrigin
            );
            $this->assertStagedDigestsUnchanged($staged, $manifestDigest, $artifactDigest);
            if (($result['approved'] ?? null) === true) {
                $this->releaseState->recordApproved($version, $commit, $manifestDigest, $artifactDigest);
            }
            return $result + ['release_version' => $version, 'release_commit' => $commit, 'release_manifest_sha256' => $manifestDigest, 'release_artifact_sha256' => $artifactDigest];
        }

        try {
            $nonce = bin2hex(random_bytes(32));
            $result = $verify($nonce);
            if (!is_array($result) || !is_bool($result['approved'] ?? null)
                || !is_string($result['report'] ?? null)
                || !is_array($result['checked_paths'] ?? null) || !array_is_list($result['checked_paths'])
                || !is_array($result['mismatches'] ?? null) || !array_is_list($result['mismatches'])
                || !is_string($result['manifest_sha256'] ?? null)
                || !hash_equals($manifestDigest, $result['manifest_sha256'])
                || !is_string($result['artifact_sha256'] ?? null)
                || !hash_equals($artifactDigest, $result['artifact_sha256'])) {
                throw new RuntimeException('Integrity Node verifier returned an invalid or unbound result.');
            }
            $this->assertStagedDigestsUnchanged($staged, $manifestDigest, $artifactDigest);
            $evidence = $this->evidenceStore->append($result['report'], $version, $commit, $manifestDigest, $artifactDigest, $result['approved'], $nonce);
            if ($result['approved'] === true) {
                $this->releaseState->recordApproved($version, $commit, $manifestDigest, $artifactDigest);
            }
            return $result + $evidence + ['release_version' => $version, 'release_commit' => $commit, 'release_manifest_sha256' => $manifestDigest, 'release_artifact_sha256' => $artifactDigest];
        } catch (Throwable $exception) {
            throw new RuntimeException('Scheduled integrity verification failed.', 0, $exception);
        }
    }

    /** @param array{manifest_path:string,artifact_path:string} $staged */
    private function assertStagedDigestsUnchanged(array $staged, string $manifestDigest, string $artifactDigest): void
    {
        $currentManifestDigest = hash_file('sha256', $staged['manifest_path']);
        $currentArtifactDigest = hash_file('sha256', $staged['artifact_path']);
        if (!is_string($currentManifestDigest) || !is_string($currentArtifactDigest)
            || !hash_equals($manifestDigest, $currentManifestDigest)
            || !hash_equals($artifactDigest, $currentArtifactDigest)) {
            throw new RuntimeException('Staged release artifacts changed during integrity verification.');
        }
    }

    private function wasAlreadyAlerted(Throwable $exception): bool
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if ($current instanceof IntegrityNodeAlertedException) {
                return true;
            }
        }
        return false;
    }

    private function alertFailure(Throwable $exception): void
    {
        try {
            ($this->notifyFailure)($this->nodeId, 'scheduled_integrity_run_failed', [
                'exception' => get_class($exception),
                'message' => substr($exception->getMessage(), 0, 300),
            ]);
        } catch (Throwable $alertException) {
            throw new RuntimeException('Scheduled integrity run and independent owner alert both failed.', 0, $alertException);
        }
    }
}
