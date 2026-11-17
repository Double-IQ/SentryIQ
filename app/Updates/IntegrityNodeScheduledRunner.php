<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use Throwable;

require_once __DIR__ . '/IntegrityNodeAlertedException.php';
require_once __DIR__ . '/IntegrityNodeReleaseStateStore.php';

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

    /** @var callable(string,string,string,string,string,string,array,string):array<string,mixed> */
    private $verify;

    /** @var callable(string,string,array<string,mixed>):void */
    private $notifyFailure;

    public function __construct(
        private readonly string $nodeId,
        private readonly IntegrityReleaseArtifactFetcher $artifactFetcher,
        callable $resolveRelease,
        callable $verify,
        callable $notifyFailure,
        private readonly string $privateDataDirectory,
        private readonly string $publicWebRoot,
        private readonly string $targetOrigin,
        private readonly array $publicPaths,
        private readonly IntegrityNodeReleaseStateStore $releaseState,
        private readonly ?IntegrityNodeEventRunner $eventRunner = null,
    ) {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b', 'integrity-c'], true)) {
            throw new RuntimeException('Scheduled runner requires a known independent Integrity Node identity.');
        }
        $parts = parse_url($targetOrigin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('Scheduled runner target must be the canonical SentryIQ HTTPS origin.');
        }
        if (!array_is_list($publicPaths)) {
            throw new RuntimeException('Scheduled runner public-path selection must be a list.');
        }
        if ($nodeId === 'integrity-c' && $eventRunner !== null) {
            throw new RuntimeException('Node C must remain independent of the Node 4 event receiver.');
        }
        if ($nodeId !== 'integrity-c' && $eventRunner === null) {
            throw new RuntimeException('Nodes A and B require the authenticated Node 4 event exchange.');
        }
        $this->resolveRelease = $resolveRelease;
        $this->verify = $verify;
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
            if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)) {
                throw new RuntimeException('Release resolver version must use stable MAJOR.MINOR.PATCH format.');
            }
            $commit = strtolower($release['commit']);
            $this->releaseState->assertCandidate($version, $commit);
            $installedVersion = $baseline['version'];
            $staged = $this->artifactFetcher->fetch(
                $version,
                rtrim($this->privateDataDirectory, '/') . '/integrity-releases/' . $version,
                $this->publicWebRoot
            );
        } catch (Throwable $exception) {
            throw new RuntimeException('Release selection or artifact staging failed.', 0, $exception);
        }

        $verify = fn(string $nonce): array => ($this->verify)(
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
            if (($result['approved'] ?? null) === true) {
                $this->releaseState->recordApproved($version, $commit);
            }
            return $result + ['release_version' => $version, 'release_commit' => $commit];
        }

        try {
            $nonce = bin2hex(random_bytes(32));
            $result = $verify($nonce);
            if (!is_array($result) || !is_bool($result['approved'] ?? null)
                || !is_string($result['report'] ?? null)) {
                throw new RuntimeException('Integrity Node verifier returned an invalid result.');
            }
            if ($result['approved'] === true) {
                $this->releaseState->recordApproved($version, $commit);
            }
            return $result + ['release_version' => $version, 'release_commit' => $commit];
        } catch (Throwable $exception) {
            throw new RuntimeException('Scheduled integrity verification failed.', 0, $exception);
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
