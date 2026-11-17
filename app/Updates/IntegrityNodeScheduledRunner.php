<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use Throwable;

/**
 * One scheduled execution of an independently hosted Integrity Node.
 *
 * Release selection is deliberately injected: each host must obtain the
 * deployed release identity from its administrator-controlled source rather
 * than silently assuming that GitHub's newest release is already deployed.
 */
final class IntegrityNodeScheduledRunner
{
    /** @var callable():array{version:string,commit:string,installed_version:string} */
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
        if ($publicPaths === [] || !array_is_list($publicPaths)) {
            throw new RuntimeException('Scheduled runner requires an explicit public-path allowlist.');
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
            $release = ($this->resolveRelease)();
            if (!is_array($release)
                || !is_string($release['version'] ?? null)
                || !is_string($release['commit'] ?? null)
                || !is_string($release['installed_version'] ?? null)
                || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', ltrim($release['version'], 'v'))
                || !preg_match('/^[a-f0-9]{40}$/i', $release['commit'])) {
                throw new RuntimeException('Release resolver must return a stable version, full commit SHA and installed version.');
            }
            $version = ltrim($release['version'], 'v');
            $commit = strtolower($release['commit']);
            $staged = $this->artifactFetcher->fetch(
                $version,
                rtrim($this->privateDataDirectory, '/') . '/integrity-releases/' . $version,
                $this->publicWebRoot
            );

            $verify = fn(string $nonce): array => ($this->verify)(
                $staged['manifest_path'],
                $staged['artifact_path'],
                $version,
                $commit,
                $release['installed_version'],
                $this->targetOrigin,
                $this->publicPaths,
                $nonce
            );

            if ($this->eventRunner !== null) {
                return $this->eventRunner->run(
                    $verify,
                    $staged['manifest_path'],
                    $staged['artifact_path'],
                    $version,
                    $commit,
                    $this->targetOrigin
                ) + ['release_version' => $version, 'release_commit' => $commit];
            }

            $nonce = bin2hex(random_bytes(32));
            $result = $verify($nonce);
            if (!is_array($result) || !is_bool($result['approved'] ?? null)
                || !is_string($result['report'] ?? null)) {
                throw new RuntimeException('Integrity Node verifier returned an invalid result.');
            }
            return $result + ['release_version' => $version, 'release_commit' => $commit];
        } catch (Throwable $exception) {
            try {
                ($this->notifyFailure)($this->nodeId, 'scheduled_integrity_run_failed', [
                    'exception' => get_class($exception),
                    'message' => substr($exception->getMessage(), 0, 300),
                ]);
            } catch (Throwable $alertException) {
                throw new RuntimeException('Scheduled integrity run and independent owner alert both failed.', 0, $alertException);
            }
            throw new RuntimeException('Scheduled integrity run failed; independent owner alert was attempted.', 0, $exception);
        }
    }
}
