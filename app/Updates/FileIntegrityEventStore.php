<?php

declare(strict_types=1);

namespace SentryIQ\\Updates;

use RuntimeException;

/**
 * Private, file-backed Node 4 challenge and evidence store.
 *
 * The state file must live outside the public web root in a directory writable
 * only by the SentryIQ application account. flock serializes the read/modify/
 * write transaction; rename publishes the complete new state atomically.
 *
 * This is a shared-host adapter, not an independent failure domain: loss or
 * compromise of the SentryIQ host affects Node 4. Nodes A/B must keep direct
 * owner alert paths.
 */
final class FileIntegrityEventStore
{
    private const STATE_VERSION = 1;
    private const MAX_STATE_BYTES = 16777216;
    private const MAX_REPORTS = 5000;

    private string $directory;
    private string $statePath;
    private string $lockPath;

    public function __construct(string $privateDirectory)
    {
        if ($privateDirectory === '' || !str_starts_with($privateDirectory, DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Node 4 storage directory must be an absolute private path.');
        }
        if (is_link($privateDirectory) || !is_dir($privateDirectory)) {
            throw new RuntimeException('Node 4 storage directory must already exist and must not be a symlink.');
        }
        $real = realpath($privateDirectory);
        if (!is_string($real) || !is_writable($real) || !is_readable($real)) {
            throw new RuntimeException('Node 4 storage directory must be readable and writable.');
        }
        $this->directory = $real;
        $this->statePath = $real . DIRECTORY_SEPARATOR . 'integrity-events.json';
        $this->lockPath = $real . DIRECTORY_SEPARATOR . 'integrity-events.lock';
        if (is_link($this->statePath) || is_link($this->lockPath)) {
            throw new RuntimeException('Node 4 storage files must not be symlinks.');
        }
    }

    /**
     * Create a single-use challenge bound to one node, target and release.
     * The returned nonce is sent to that node and later signed into its report.
     *
     * @return array{nonce:string,expires_at:int,node_id:string}
     */
    public function issueChallenge(
        string $nodeId,
        string $targetOrigin,
        string $releaseVersion,
        string $commit,
        string $artifactSha256,
        string $manifestSha256,
        ?int $now = null
    ): array {
        if (!in_array($nodeId, ['integrity-a', 'integrity-b'], true)) {
            throw new RuntimeException('Unknown integrity node identity.');
        }
        $parts = parse_url($targetOrigin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || rtrim($targetOrigin, '/') !== $targetOrigin) {
            throw new RuntimeException('Challenge target origin must be a canonical HTTPS origin.');
        }
        if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $releaseVersion)
            || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $artifactSha256)
            || !preg_match('/^[a-f0-9]{64}$/', $manifestSha256)) {
            throw new RuntimeException('Challenge release binding is malformed.');
        }
        $issuedAt = $now ?? time();
        if ($issuedAt < 1) {
            throw new RuntimeException('Challenge clock is invalid.');
        }
        $nonce = bin2hex(random_bytes(32));
        $challenge = [
            'node_id' => $nodeId,
            'target_origin' => $targetOrigin,
            'release_version' => $releaseVersion,
            'commit' => $commit,
            'artifact_sha256' => $artifactSha256,
            'manifest_sha256' => $manifestSha256,
            'issued_at' => $issuedAt,
            'expires_at' => $issuedAt + 300,
        ];

        $this->transact(function (array &$state) use ($nonce, $challenge): void {
            $key = hash('sha256', $nonce);
            if (isset($state['challenges'][$key])) {
                throw new RuntimeException('Challenge collision.');
            }
            $state['challenges'][$key] = $challenge;
        });

        return ['nonce' => $nonce, 'expires_at' => $challenge['expires_at'], 'node_id' => $nodeId];
    }

    /**
     * Callback contract for IntegrityEventReportVerifier.
     * Challenge consumption and evidence persistence happen in one locked commit.
     *
     * @param array<string,mixed> $payload
     */
    public function consumeAndStore(
        string $nodeId,
        array $payload,
        string $envelope,
        string $rawPayload
    ): string {
        return $this->transact(function (array &$state) use ($nodeId, $payload, $envelope, $rawPayload): string {
            $nonceKey = hash('sha256', (string)($payload['nonce'] ?? ''));
            $challenge = $state['challenges'][$nonceKey] ?? null;
            if (!is_array($challenge)) {
                throw new RuntimeException('Challenge is unknown, already consumed, or expired.');
            }
            $now = time();
            if (($challenge['node_id'] ?? null) !== $nodeId
                || ($challenge['expires_at'] ?? 0) <= $now
                || ($challenge['target_origin'] ?? null) !== ($payload['target_origin'] ?? null)
                || ($challenge['release_version'] ?? null) !== ($payload['release_version'] ?? null)
                || ($challenge['commit'] ?? null) !== ($payload['commit'] ?? null)
                || ($challenge['artifact_sha256'] ?? null) !== ($payload['artifact_sha256'] ?? null)
                || ($challenge['manifest_sha256'] ?? null) !== ($payload['manifest_sha256'] ?? null)
                || ($challenge['issued_at'] ?? 0) > ($payload['issued_at'] ?? 0)
                || ($payload['issued_at'] ?? 0) > ($challenge['expires_at'] ?? 0)) {
                throw new RuntimeException('Integrity report does not match its live challenge binding.');
            }
            if (count($state['reports']) >= self::MAX_REPORTS) {
                throw new RuntimeException('Node 4 evidence store is full; retention maintenance is required.');
            }
            unset($state['challenges'][$nonceKey]);
            $id = bin2hex(random_bytes(16));
            $state['reports'][$id] = [
                'accepted_at' => $now,
                'node_id' => $nodeId,
                'decision' => $payload['decision'],
                'payload_sha256' => hash('sha256', $rawPayload),
                'envelope' => base64_encode($envelope),
                'payload' => $payload,
            ];
            return $id;
        });
    }

    /** @return array<string,mixed> */
    public function snapshot(): array
    {
        return $this->transact(static fn(array &$state): array => $state, false);
    }

    /**
     * @template T
     * @param callable(array<string,mixed>&):T $operation
     * @return T
     */
    private function transact(callable $operation, bool $write = true): mixed
    {
        $lock = fopen($this->lockPath, 'c');
        if ($lock === false) {
            throw new RuntimeException('Unable to open Node 4 storage lock.');
        }
        @chmod($this->lockPath, 0600);
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Unable to lock Node 4 evidence store.');
            }
            $state = $this->readState();
            $result = $operation($state);
            if ($write) {
                $this->writeState($state);
            }
            flock($lock, LOCK_UN);
            return $result;
        } finally {
            fclose($lock);
        }
    }

    /** @return array{version:int,challenges:array<string,array<string,mixed>>,reports:array<string,array<string,mixed>>} */
    private function readState(): array
    {
        if (!file_exists($this->statePath)) {
            return ['version' => self::STATE_VERSION, 'challenges' => [], 'reports' => []];
        }
        if (is_link($this->statePath) || !is_file($this->statePath)) {
            throw new RuntimeException('Node 4 state path is not a regular file.');
        }
        $size = filesize($this->statePath);
        if (!is_int($size) || $size < 2 || $size > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Node 4 state file has an invalid size.');
        }
        $bytes = file_get_contents($this->statePath);
        if (!is_string($bytes)) {
            throw new RuntimeException('Unable to read Node 4 state.');
        }
        try {
            $state = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (\\JsonException $exception) {
            throw new RuntimeException('Node 4 state is corrupt; refusing to overwrite it.', 0, $exception);
        }
        if (!is_array($state) || ($state['version'] ?? null) !== self::STATE_VERSION
            || !is_array($state['challenges'] ?? null) || !is_array($state['reports'] ?? null)) {
            throw new RuntimeException('Node 4 state schema is invalid; refusing to overwrite it.');
        }
        return $state;
    }

    /** @param array<string,mixed> $state */
    private function writeState(array $state): void
    {
        try {
            $bytes = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\\JsonException $exception) {
            throw new RuntimeException('Unable to encode Node 4 state.', 0, $exception);
        }
        if (strlen($bytes) > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Node 4 state exceeds its configured size limit.');
        }
        $temporary = $this->directory . DIRECTORY_SEPARATOR . '.integrity-events-' . bin2hex(random_bytes(8)) . '.tmp';
        $handle = fopen($temporary, 'xb');
        if ($handle === false) {
            throw new RuntimeException('Unable to create atomic Node 4 state file.');
        }
        try {
            @chmod($temporary, 0600);
            $written = 0;
            $length = strlen($bytes);
            while ($written < $length) {
                $n = fwrite($handle, substr($bytes, $written));
                if ($n === false || $n === 0) {
                    throw new RuntimeException('Unable to write complete Node 4 state.');
                }
                $written += $n;
            }
            if (!fflush($handle)) {
                throw new RuntimeException('Unable to flush Node 4 state.');
            }
        } finally {
            fclose($handle);
        }
        if (!rename($temporary, $this->statePath)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to atomically publish Node 4 state.');
        }
        @chmod($this->statePath, 0600);
    }
}
