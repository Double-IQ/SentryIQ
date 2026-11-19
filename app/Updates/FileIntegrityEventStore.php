<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

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
    private const MAX_STATE_BYTES = 33554432;
    private const MAX_REPORTS = 5000;
    private const REPORT_RETENTION_SECONDS = 604800;
    private const ALERT_RETENTION_SECONDS = 2592000;
    private const MAX_ALERTS = 2000;

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
        if (is_string($real)) clearstatcache(true, $real);
        $directoryStat = is_string($real) ? @lstat($real) : false;
        if (!is_string($real) || !is_writable($real) || !is_readable($real)
            || !is_array($directoryStat) || (($directoryStat['mode'] ?? 0) & 0170000) !== 0040000
            || (($directoryStat['mode'] ?? 0) & 0777) !== 0700) {
            throw new RuntimeException('Node 4 storage directory must already be a real directory with exact 0700 permissions.');
        }
        $this->directory = $real;
        $this->statePath = $real . DIRECTORY_SEPARATOR . 'integrity-events.json';
        $this->lockPath = $real . DIRECTORY_SEPARATOR . 'integrity-events.lock';

        clearstatcache(true, $this->lockPath);
        $lockStat = @lstat($this->lockPath);
        if (!is_array($lockStat) || (($lockStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($lockStat['mode'] ?? 0) & 0777) !== 0600) {
            throw new RuntimeException('Node 4 lock file must be pre-provisioned as a regular file with exact 0600 permissions.');
        }
        clearstatcache(true, $this->statePath);
        $stateStat = @lstat($this->statePath);
        if (is_array($stateStat) && ((($stateStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($stateStat['mode'] ?? 0) & 0777) !== 0600)) {
            throw new RuntimeException('Existing Node 4 state must be a regular file with exact 0600 permissions.');
        }
        if ($stateStat === false && is_link($this->statePath)) {
            throw new RuntimeException('Node 4 state path must not be a symlink.');
        }
    }

    /**
     * Prune expired challenges, reports older than seven days, and delivered
     * alerts older than thirty days. Pending alerts are never discarded.
     *
     * @return array{challenges:int,reports:int,alerts:int}
     */
    public function pruneRetention(?int $now = null): array
    {
        $timestamp = $now ?? time();
        if ($timestamp < 1) throw new RuntimeException('Node 4 retention clock is invalid.');
        return $this->transact(function (array &$state) use ($timestamp): array {
            return $this->pruneState($state, $timestamp);
        });
    }

    /** @param array<string,mixed> $state @return array{challenges:int,reports:int,alerts:int} */
    private function pruneState(array &$state, int $now): array
    {
        $removed = ['challenges' => 0, 'reports' => 0, 'alerts' => 0];
        foreach ($state['challenges'] as $id => $challenge) {
            if (!is_array($challenge) || (int)($challenge['expires_at'] ?? 0) <= $now) {
                unset($state['challenges'][$id]);
                $removed['challenges']++;
            }
        }
        $reportCutoff = $now - self::REPORT_RETENTION_SECONDS;
        foreach ($state['reports'] as $id => $report) {
            if (!is_array($report) || (int)($report['accepted_at'] ?? 0) < $reportCutoff) {
                unset($state['reports'][$id]);
                $removed['reports']++;
            }
        }
        $alertCutoff = $now - self::ALERT_RETENTION_SECONDS;
        foreach ($state['alerts'] as $id => $alert) {
            if (is_array($alert) && ($alert['status'] ?? null) === 'delivered'
                && (int)($alert['delivered_at'] ?? 0) < $alertCutoff) {
                unset($state['alerts'][$id]);
                $removed['alerts']++;
            }
        }
        return $removed;
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
            || isset($parts['path']) || rtrim($targetOrigin, '/') !== $targetOrigin) {
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
            'expires_at' => $issuedAt + 600,
        ];

        $this->transact(function (array &$state) use ($nonce, $challenge, $issuedAt): void {
            $this->pruneState($state, $issuedAt);
            if (count($state['challenges']) >= 1000) {
                throw new RuntimeException('Node 4 active challenge capacity has been reached.');
            }
            $nodeActiveChallenges = 0;
            foreach ($state['challenges'] as $existingKey => $existingChallenge) {
                if (!is_array($existingChallenge) || ($existingChallenge['expires_at'] ?? 0) <= $issuedAt) {
                    unset($state['challenges'][$existingKey]);
                    continue;
                }
                if (($existingChallenge['node_id'] ?? null) === $nodeId) $nodeActiveChallenges++;
            }
            if ($nodeActiveChallenges >= 5) {
                throw new RuntimeException('Node 4 per-node active challenge capacity has been reached.');
            }
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
            $this->pruneState($state, time());
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

    /**
     * Persist an incident notification in the durable outbox, deduplicated by fingerprint.
     * @param array<string,mixed> $incident
     * @return array{id:string,created:bool}
     */
    public function queueAlert(array $incident): array
    {
        if (!is_string($incident['code'] ?? null) || !is_string($incident['message'] ?? null)) {
            throw new RuntimeException('Incident alert requires a code and message.');
        }
        $fingerprint = hash('sha256', json_encode($incident, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        return $this->transact(function (array &$state) use ($incident, $fingerprint): array {
            $this->pruneState($state, time());
            $matchingId = null;
            $matching = null;
            foreach ($state['alerts'] as $id => $existing) {
                if (($existing['fingerprint'] ?? null) === $fingerprint
                    && ($matching === null || ($existing['created_at'] ?? 0) > ($matching['created_at'] ?? 0))) {
                    $matchingId = $id;
                    $matching = $existing;
                }
            }
            if (is_string($matchingId) && is_array($matching)) {
                $now = time();
                $pending = ($matching['status'] ?? null) === 'pending';
                $withinCooldown = ($matching['status'] ?? null) === 'delivered'
                    && $now - (int)($matching['delivered_at'] ?? 0) < 1800;
                if ($pending || $withinCooldown) {
                    $state['alerts'][$matchingId]['occurrences'] = (int)($matching['occurrences'] ?? 1) + 1;
                    $state['alerts'][$matchingId]['last_seen'] = $now;
                    return ['id' => $matchingId, 'created' => false];
                }
            }
            if (count($state['alerts']) >= self::MAX_ALERTS) {
                throw new RuntimeException('Node 4 alert outbox is full; delivery maintenance is required.');
            }
            $id = bin2hex(random_bytes(16));
            $state['alerts'][$id] = [
                'fingerprint' => $fingerprint,
                'incident' => $incident,
                'status' => 'pending',
                'created_at' => time(),
                'last_seen' => time(),
                'occurrences' => 1,
                'delivered_at' => null,
            ];
            return ['id' => $id, 'created' => true];
        });
    }

    /** @return list<array{id:string,incident:array<string,mixed>,created_at:int,occurrences:int}> */
    public function pendingAlerts(int $limit = 50): array
    {
        if ($limit < 1 || $limit > 100) {
            throw new RuntimeException('Alert outbox batch size is invalid.');
        }
        return $this->transact(static function (array &$state) use ($limit): array {
            $pending = [];
            foreach ($state['alerts'] as $id => $alert) {
                if (($alert['status'] ?? null) === 'pending') {
                    $pending[] = [
                        'id' => $id,
                        'incident' => $alert['incident'],
                        'created_at' => $alert['created_at'],
                        'occurrences' => $alert['occurrences'],
                    ];
                    if (count($pending) >= $limit) {
                        break;
                    }
                }
            }
            return $pending;
        }, false);
    }

    public function markAlertDelivered(string $id, ?int $deliveredAt = null): void
    {
        $this->transact(function (array &$state) use ($id, $deliveredAt): void {
            if (!isset($state['alerts'][$id]) || ($state['alerts'][$id]['status'] ?? null) !== 'pending') {
                throw new RuntimeException('Pending Node 4 alert was not found.');
            }
            $state['alerts'][$id]['status'] = 'delivered';
            $state['alerts'][$id]['delivered_at'] = $deliveredAt ?? time();
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
        clearstatcache(true, $this->lockPath);
        $lockStat = @lstat($this->lockPath);
        if (!is_array($lockStat) || (($lockStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($lockStat['mode'] ?? 0) & 0777) !== 0600) {
            throw new RuntimeException('Node 4 lock file changed or has unsafe type/permissions.');
        }
        $lock = @fopen($this->lockPath, 'r+b');
        $openedStat = is_resource($lock) ? fstat($lock) : false;
        if ($lock === false || !is_array($openedStat)
            || ($openedStat['dev'] ?? null) !== ($lockStat['dev'] ?? null)
            || ($openedStat['ino'] ?? null) !== ($lockStat['ino'] ?? null)
            || (($openedStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($openedStat['mode'] ?? 0) & 0777) !== 0600) {
            if (is_resource($lock)) fclose($lock);
            throw new RuntimeException('Node 4 lock inode changed during open or has unsafe permissions.');
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('Node 4 evidence store is busy; request fails closed.');
            }
            clearstatcache(true, $this->lockPath);
            $lockedPathStat = @lstat($this->lockPath);
            if (!is_array($lockedPathStat)
                || ($lockedPathStat['dev'] ?? null) !== ($openedStat['dev'] ?? null)
                || ($lockedPathStat['ino'] ?? null) !== ($openedStat['ino'] ?? null)
                || (($lockedPathStat['mode'] ?? 0) & 0170000) !== 0100000
                || (($lockedPathStat['mode'] ?? 0) & 0777) !== 0600) {
                throw new RuntimeException('Node 4 lock path changed after acquiring its inode lock.');
            }
            $state = $this->readState();
            $result = $operation($state);
            if ($write) $this->writeState($state);
            flock($lock, LOCK_UN);
            return $result;
        } finally {
            fclose($lock);
        }
    }

    /** @return array{version:int,challenges:array<string,array<string,mixed>>,reports:array<string,array<string,mixed>>} */
    private function readState(): array
    {
        clearstatcache(true, $this->statePath);
        $pathStat = @lstat($this->statePath);
        if ($pathStat === false) {
            return ['version' => self::STATE_VERSION, 'challenges' => [], 'reports' => [], 'alerts' => []];
        }
        if ((($pathStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($pathStat['mode'] ?? 0) & 0777) !== 0600
            || ($pathStat['size'] ?? 0) < 2
            || ($pathStat['size'] ?? 0) > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Node 4 state must be a regular exact-0600 file within its size limit.');
        }
        $handle = @fopen($this->statePath, 'rb');
        $openedStat = is_resource($handle) ? fstat($handle) : false;
        if ($handle === false || !is_array($openedStat)
            || ($openedStat['dev'] ?? null) !== ($pathStat['dev'] ?? null)
            || ($openedStat['ino'] ?? null) !== ($pathStat['ino'] ?? null)
            || (($openedStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($openedStat['mode'] ?? 0) & 0777) !== 0600) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Node 4 state inode changed during open or has unsafe permissions.');
        }
        try {
            $bytes = stream_get_contents($handle, self::MAX_STATE_BYTES + 1);
            $after = fstat($handle);
            clearstatcache(true, $this->statePath);
            $afterPath = @lstat($this->statePath);
            if (!is_string($bytes) || strlen($bytes) < 2 || strlen($bytes) > self::MAX_STATE_BYTES
                || !is_array($after) || !is_array($afterPath)
                || ($after['dev'] ?? null) !== ($openedStat['dev'] ?? null)
                || ($after['ino'] ?? null) !== ($openedStat['ino'] ?? null)
                || ($afterPath['dev'] ?? null) !== ($openedStat['dev'] ?? null)
                || ($afterPath['ino'] ?? null) !== ($openedStat['ino'] ?? null)
                || (($after['mode'] ?? 0) & 0777) !== 0600
                || (($afterPath['mode'] ?? 0) & 0170000) !== 0100000
                || (($afterPath['mode'] ?? 0) & 0777) !== 0600) {
                throw new RuntimeException('Node 4 state changed while being read.');
            }
        } finally {
            fclose($handle);
        }
        try {
            $state = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Node 4 state is corrupt; refusing to overwrite it.', 0, $exception);
        }
        if (!is_array($state) || ($state['version'] ?? null) !== self::STATE_VERSION
            || !is_array($state['challenges'] ?? null) || !is_array($state['reports'] ?? null)
            || !is_array($state['alerts'] ?? null)) {
            throw new RuntimeException('Node 4 state schema is invalid; refusing to overwrite it.');
        }
        return $state;
    }

    /** @param array<string,mixed> $state */
    private function writeState(array $state): void
    {
        try {
            $bytes = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Unable to encode Node 4 state.', 0, $exception);
        }
        if (strlen($bytes) > self::MAX_STATE_BYTES) {
            throw new RuntimeException('Node 4 state exceeds its configured size limit.');
        }
        $temporary = $this->directory . DIRECTORY_SEPARATOR . '.integrity-events-' . bin2hex(random_bytes(16)) . '.tmp';
        $handle = @fopen($temporary, 'x+b');
        if ($handle === false) {
            throw new RuntimeException('Unable to exclusively create atomic Node 4 state file.');
        }
        try {
            if (!@chmod($temporary, 0600)) {
                throw new RuntimeException('Unable to restrict Node 4 state temporary file permissions.');
            }
            $offset = 0;
            $length = strlen($bytes);
            while ($offset < $length) {
                $written = @fwrite($handle, substr($bytes, $offset));
                if (!is_int($written) || $written < 1) {
                    throw new RuntimeException('Unable to write complete Node 4 state.');
                }
                $offset += $written;
            }
            if (!@fflush($handle) || !@fsync($handle)) {
                throw new RuntimeException('Unable to flush Node 4 state to storage.');
            }
            $writtenStat = fstat($handle);
            clearstatcache(true, $temporary);
            $temporaryStat = @lstat($temporary);
            if (!is_array($writtenStat) || !is_array($temporaryStat)
                || (($writtenStat['mode'] ?? 0) & 0170000) !== 0100000
                || (($writtenStat['mode'] ?? 0) & 0777) !== 0600
                || ($temporaryStat['dev'] ?? null) !== ($writtenStat['dev'] ?? null)
                || ($temporaryStat['ino'] ?? null) !== ($writtenStat['ino'] ?? null)
                || (($temporaryStat['mode'] ?? 0) & 0170000) !== 0100000
                || (($temporaryStat['mode'] ?? 0) & 0777) !== 0600) {
                throw new RuntimeException('Node 4 state temporary file has unsafe or replaced metadata.');
            }
        } catch (\Throwable $exception) {
            fclose($handle);
            @unlink($temporary);
            throw $exception;
        }
        fclose($handle);
        if (!@rename($temporary, $this->statePath)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to atomically publish Node 4 state.');
        }
        clearstatcache(true, $this->statePath);
        $published = @lstat($this->statePath);
        if (!is_array($published) || ($published['dev'] ?? null) !== ($writtenStat['dev'] ?? null)
            || ($published['ino'] ?? null) !== ($writtenStat['ino'] ?? null)
            || (($published['mode'] ?? 0) & 0170000) !== 0100000
            || (($published['mode'] ?? 0) & 0777) !== 0600) {
            throw new RuntimeException('Published Node 4 state file has unsafe or replaced metadata.');
        }
    }
}
