<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use Throwable;

/**
 * Per-node monotonic release pin stored outside the public webroot.
 *
 * The baseline must be initialized explicitly from a known-good deployed
 * release. It is never silently learned from the public origin. The exclusive
 * lock covers resolution, verification, report delivery and state advancement.
 */
final class IntegrityNodeReleaseStateStore
{
    private string $directory;
    private string $statePath;
    private string $lockPath;
    private bool $runLockHeld = false;

    public function __construct(string $privateDataDirectory, string $publicWebRoot)
    {
        $private = realpath($privateDataDirectory);
        $web = realpath($publicWebRoot);
        if (!is_string($private) || !is_dir($private) || is_link($privateDataDirectory)
            || !is_string($web) || !is_dir($web) || is_link($publicWebRoot)) {
            throw new RuntimeException('Integrity release state requires real private-data and public-web directories.');
        }
        if ($private === $web || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Integrity release state must be stored outside the public webroot.');
        }
        if (!@chmod($private, 0700) || ((fileperms($private) ?: 0) & 0077) !== 0) {
            throw new RuntimeException('Integrity release state directory must have private 0700 permissions.');
        }

        $this->directory = $private;
        $this->statePath = $private . '/integrity-release-state.json';
        $this->lockPath = $private . '/integrity-release-state.lock';
    }

    /**
     * Serialize an entire scheduled check so two overlapping cron runs cannot
     * approve and publish release versions out of order.
     */
    public function runExclusive(callable $operation): mixed
    {
        if ($this->runLockHeld) {
            throw new RuntimeException('Integrity release state lock is already held by this runner.');
        }
        if (is_link($this->lockPath)) {
            throw new RuntimeException('Integrity release state lock must not be a symlink.');
        }
        $handle = @fopen($this->lockPath, 'c');
        if ($handle === false || !@chmod($this->lockPath, 0600)
            || ((fileperms($this->lockPath) ?: 0) & 0077) !== 0) {
            if (is_resource($handle)) fclose($handle);
            throw new RuntimeException('Unable to create a private integrity release state lock.');
        }
        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);
            throw new RuntimeException('Another integrity check is already running on this node.');
        }

        $this->runLockHeld = true;
        try {
            return $operation();
        } finally {
            $this->runLockHeld = false;
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * One-time administrator bootstrap. The known-good version and commit
     * must be independently established before this is called.
     */
    public function initializeBaseline(string $version, string $commit, string $manifestDigest, string $artifactDigest): void
    {
        $version = self::normalizeVersion($version);
        $commit = self::normalizeCommit($commit);
        $manifestDigest = self::normalizeDigest($manifestDigest);
        $artifactDigest = self::normalizeDigest($artifactDigest);
        $initialize = function () use ($version, $commit, $manifestDigest, $artifactDigest): void {
            if (file_exists($this->statePath) || is_link($this->statePath)) {
                throw new RuntimeException('Integrity release baseline already exists; refusing to replace it.');
            }
            $this->writeState($version, $commit, $manifestDigest, $artifactDigest);
        };

        if ($this->runLockHeld) {
            $initialize();
            return;
        }
        $this->runExclusive($initialize);
    }

    /** @return array{version:string,commit:string,manifest_sha256:string,artifact_sha256:string,approved_at:int} */
    public function current(): array
    {
        if (is_link($this->statePath) || !is_file($this->statePath)
            || (((fileperms($this->statePath) ?: 0) & 0077) !== 0)) {
            throw new RuntimeException('Integrity release baseline is missing or has unsafe permissions; initialize it explicitly.');
        }
        $bytes = @file_get_contents($this->statePath);
        if (!is_string($bytes) || $bytes === '' || strlen($bytes) > 4096) {
            throw new RuntimeException('Integrity release baseline is unreadable or invalid in size.');
        }
        try {
            $state = json_decode($bytes, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Integrity release baseline is not valid JSON.', 0, $exception);
        }
        if (!is_array($state) || ($state['format'] ?? null) !== 1
            || !is_string($state['version'] ?? null)
            || !is_string($state['commit'] ?? null)
            || !is_int($state['approved_at'] ?? null) || $state['approved_at'] < 1) {
            throw new RuntimeException('Integrity release baseline schema is invalid.');
        }
        $manifestDigest = $state['manifest_sha256'] ?? null;
        $artifactDigest = $state['artifact_sha256'] ?? null;
        if (!is_string($manifestDigest) || !is_string($artifactDigest)) {
            throw new RuntimeException('Integrity release baseline must pin both artifact digests.');
        }
        $manifestDigest = self::normalizeDigest($manifestDigest);
        $artifactDigest = self::normalizeDigest($artifactDigest);
        return [
            'version' => self::normalizeVersion($state['version']),
            'commit' => self::normalizeCommit($state['commit']),
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
            'approved_at' => $state['approved_at'],
        ];
    }

    public function assertCandidate(string $version, string $commit, string $manifestDigest, string $artifactDigest): void
    {
        $version = self::normalizeVersion($version);
        $commit = self::normalizeCommit($commit);
        $manifestDigest = self::normalizeDigest($manifestDigest);
        $artifactDigest = self::normalizeDigest($artifactDigest);
        $current = $this->current();
        $comparison = version_compare($version, $current['version']);
        if ($comparison < 0) {
            throw new RuntimeException('Integrity release rollback detected: candidate is older than the node’s pinned release.');
        }
        if ($comparison === 0 && !hash_equals($current['commit'], $commit)) {
            throw new RuntimeException('Integrity release tag was retargeted: same version now resolves to a different commit.');
        }
        if ($comparison === 0
            && (!hash_equals($current['manifest_sha256'], $manifestDigest)
                || !hash_equals($current['artifact_sha256'], $artifactDigest))) {
            throw new RuntimeException('Integrity release artifacts changed without a version and source-commit change.');
        }
    }

    /** Advance the pin only after a complete approved verification result. */
    public function recordApproved(string $version, string $commit, string $manifestDigest, string $artifactDigest): void
    {
        if (!$this->runLockHeld) {
            throw new RuntimeException('Integrity release state may advance only inside an exclusive scheduled run.');
        }
        $version = self::normalizeVersion($version);
        $commit = self::normalizeCommit($commit);
        $manifestDigest = self::normalizeDigest($manifestDigest);
        $artifactDigest = self::normalizeDigest($artifactDigest);
        $current = $this->current();
        $comparison = version_compare($version, $current['version']);
        if ($comparison < 0 || ($comparison === 0 && !hash_equals($current['commit'], $commit))) {
            throw new RuntimeException('Integrity release state cannot move backwards or change an existing tag commit.');
        }
        if ($comparison === 0
            && (!hash_equals($current['manifest_sha256'], $manifestDigest)
                || !hash_equals($current['artifact_sha256'], $artifactDigest))) {
            throw new RuntimeException('Integrity release state cannot accept changed artifacts under the same version.');
        }
        if ($comparison > 0) {
            $this->writeState($version, $commit, $manifestDigest, $artifactDigest);
        }
    }

    private function writeState(string $version, string $commit, string $manifestDigest, string $artifactDigest): void
    {
        $bytes = json_encode([
            'format' => 1,
            'version' => $version,
            'commit' => $commit,
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
            'approved_at' => time(),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
        $temporary = $this->statePath . '.tmp-' . bin2hex(random_bytes(8));
        $written = @file_put_contents($temporary, $bytes, LOCK_EX);
        if ($written !== strlen($bytes) || !@chmod($temporary, 0600)
            || !@rename($temporary, $this->statePath) || !@chmod($this->statePath, 0600)) {
            @unlink($temporary);
            throw new RuntimeException('Atomic integrity release state update failed.');
        }
    }

    private static function normalizeVersion(string $version): string
    {
        $version = trim($version);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)) {
            throw new RuntimeException('Integrity release version must use stable MAJOR.MINOR.PATCH format.');
        }
        return $version;
    }

    private static function normalizeDigest(string $digest): string
    {
        $digest = strtolower(trim($digest));
        if (!preg_match('/^[a-f0-9]{64}$/', $digest)) {
            throw new RuntimeException('Integrity release artifact digest must be a full SHA-256.');
        }
        return $digest;
    }

    private static function normalizeCommit(string $commit): string
    {
        $commit = strtolower(trim($commit));
        if (!preg_match('/^[a-f0-9]{40}$/', $commit)) {
            throw new RuntimeException('Integrity release commit must be a full Git SHA.');
        }
        return $commit;
    }
}
