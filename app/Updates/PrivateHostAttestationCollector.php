<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Read-only production-host collector core.
 *
 * It has no HTTP listener and accepts no caller-supplied inventory. The
 * administrator pins inventories and the signing key in a private config;
 * a host-specific transport may invoke collect() and return its envelope.
 */
final class PrivateHostAttestationCollector
{
    private string $publicRoot;
    private string $privateRoot;
    private string $secretKey;

    /**
     * @param array<string,string|array{sha256:string,mode?:int}> $expectedFiles Relative path => SHA-256 and optional permission bits
     * @param array<string,array{path:string,sha256:string}> $privateConfig
     *        policy ID => privateRoot-relative path and approved SHA-256
     */
    public function __construct(
        string $collectorId,
        string $publicWebRoot,
        string $privateDataRoot,
        string $signingKeyPath,
        private readonly array $expectedFiles,
        private readonly array $privateConfig,
        string $targetOrigin = 'https://sentryiq.bichet.co.za',
        ?callable $clock = null,
        private readonly array $monitoredDirectories = []
    ) {
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{2,63}$/', $collectorId)) {
            throw new RuntimeException('Collector identity is invalid.');
        }
        $this->collectorId = $collectorId;
        $this->clock = $clock ?? static fn(): int => time();

        $web = realpath($publicWebRoot);
        $private = realpath($privateDataRoot);
        if (!is_string($web) || !is_dir($web) || is_link($publicWebRoot)
            || !is_string($private) || !is_dir($private) || is_link($privateDataRoot)
            || $private === $web
            || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Collector requires a real private data directory outside the public webroot.');
        }
        clearstatcache(true, $private);
        $privateStat = @lstat($private);
        if (!is_array($privateStat) || (($privateStat['mode'] ?? 0) & 0170000) !== 0040000
            || (($privateStat['mode'] ?? 0) & 0777) !== 0700) {
            throw new RuntimeException('Collector private data directory must be a real directory with exact 0700 permissions.');
        }
        $this->publicRoot = $web;
        $this->privateRoot = $private;

        $origin = parse_url($targetOrigin);
        if (!is_array($origin) || ($origin['scheme'] ?? null) !== 'https'
            || strtolower((string)($origin['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || (isset($origin['port']) && $origin['port'] !== 443)
            || isset($origin['user']) || isset($origin['pass'])
            || isset($origin['query']) || isset($origin['fragment'])
            || ($origin['path'] ?? '') !== '') {
            throw new RuntimeException('Collector target origin must be the canonical SentryIQ HTTPS origin.');
        }
        $this->targetOrigin = rtrim($targetOrigin, '/');

        if ($expectedFiles === [] || count($expectedFiles) > 5000 || count($privateConfig) > 100) {
            throw new RuntimeException('Collector inventory is empty or exceeds its bounds.');
        }
        foreach ($expectedFiles as $path => $policy) {
            $digest = is_array($policy) ? ($policy['sha256'] ?? null) : $policy;
            $mode = is_array($policy) ? ($policy['mode'] ?? null) : null;
            if (!is_string($path) || !$this->safeRelativePath($path) || !is_string($digest)
                || !preg_match('/^[a-f0-9]{64}$/', $digest)
                || ($mode !== null && (!is_int($mode) || $mode < 0 || $mode > 0777))) {
                throw new RuntimeException('Collector release inventory contains an invalid path, SHA-256, or mode.');
            }
        }
        foreach ($monitoredDirectories as $directory) {
            if (!is_string($directory) || !$this->safeRelativePath($directory)) {
                throw new RuntimeException('Collector monitored directory policy contains an invalid relative path.');
            }
        }
        foreach ($privateConfig as $id => $entry) {
            if (!is_string($id) || !preg_match('/^[a-z0-9][a-z0-9._-]{1,95}$/', $id)
                || !is_array($entry) || !is_string($entry['path'] ?? null)
                || !$this->safeRelativePath($entry['path'])
                || !is_string($entry['sha256'] ?? null)
                || !preg_match('/^[a-f0-9]{64}$/', $entry['sha256'])) {
                throw new RuntimeException('Collector private configuration inventory is invalid.');
            }
        }

        $keyReal = realpath($signingKeyPath);
        if (!is_string($keyReal) || !is_file($keyReal) || is_link($signingKeyPath)
            || !str_starts_with($keyReal, rtrim($private, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Collector signing key must be a regular file inside private data storage.');
        }
        // Require a regular, owner-only key file and read it through a
        // verified descriptor rather than reopening the pathname after checks.
        clearstatcache(true, $keyReal);
        $keyStat = @lstat($keyReal);
        if (!is_array($keyStat) || ($keyStat['mode'] & 0170000) !== 0100000
            || ($keyStat['mode'] & 0777) !== 0600) {
            throw new RuntimeException('Collector signing key must be a regular file with exact 0600 permissions.');
        }
        $keyHandle = @fopen($keyReal, 'rb');
        if (!is_resource($keyHandle)) {
            throw new RuntimeException('Collector signing key cannot be opened safely.');
        }
        try {
            $openedKey = fstat($keyHandle);
            if (!is_array($openedKey) || ($openedKey['mode'] & 0170000) !== 0100000
                || ($openedKey['mode'] & 0777) !== 0600
                || ($openedKey['size'] ?? 0) < 1 || ($openedKey['size'] ?? 0) > 256
                || $openedKey['dev'] !== $keyStat['dev'] || $openedKey['ino'] !== $keyStat['ino']) {
                throw new RuntimeException('Collector signing key identity, size, or permissions changed during opening.');
            }
            $encoded = stream_get_contents($keyHandle, 257);
            $afterKey = fstat($keyHandle);
            clearstatcache(true, $keyReal);
            $pathAfterKey = @lstat($keyReal);
            if (!is_string($encoded) || $encoded === '' || strlen($encoded) > 256
                || !is_array($afterKey) || !is_array($pathAfterKey)
                || $afterKey['dev'] !== $openedKey['dev'] || $afterKey['ino'] !== $openedKey['ino']
                || $afterKey['size'] !== $openedKey['size'] || $afterKey['mtime'] !== $openedKey['mtime']
                || $afterKey['ctime'] !== $openedKey['ctime']
                || $pathAfterKey['dev'] !== $openedKey['dev'] || $pathAfterKey['ino'] !== $openedKey['ino']
                || ($pathAfterKey['mode'] & 0170000) !== 0100000
                || ($pathAfterKey['mode'] & 0777) !== 0600) {
                throw new RuntimeException('Collector signing key changed while being read.');
            }
        } finally {
            fclose($keyHandle);
        }
        $key = base64_decode(trim($encoded), true);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('Collector signing key must contain a base64 Ed25519 secret key.');
        }
        $this->secretKey = $key;
    }

    private string $collectorId;
    private string $targetOrigin;
    /** @var callable():int */
    private $clock;

    /**
     * @return array{payload:string,signature:string}
     */
    public function collect(
        string $nonce,
        string $releaseVersion,
        string $commit,
        string $manifestDigest,
        string $artifactDigest
    ): array {
        $nonce = strtolower(trim($nonce));
        $version = trim($releaseVersion);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        $commit = strtolower(trim($commit));
        $manifestDigest = strtolower(trim($manifestDigest));
        $artifactDigest = strtolower(trim($artifactDigest));
        if (!preg_match('/^[a-f0-9]{64}$/', $nonce)
            || !preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $version)
            || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
            || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
            throw new RuntimeException('Collector challenge or release identity is invalid.');
        }
        $now = ($this->clock)();
        if (!is_int($now) || $now < 1) throw new RuntimeException('Collector clock is invalid.');

        $files = [];
        $mismatches = false;
        foreach ($this->expectedFiles as $path => $policy) {
            $expected = is_array($policy) ? $policy['sha256'] : $policy;
            $mode = is_array($policy) ? ($policy['mode'] ?? null) : null;
            $entry = $this->inspect($this->publicRoot, $path, $expected, $mode);
            $files[] = ['path' => $path, 'expected_sha256' => $expected] + $entry;
            if ($entry['result'] !== 'match') $mismatches = true;
        }
        foreach ($this->findUnexpectedFiles() as $path) {
            $files[] = [
                'path' => $path,
                'expected_sha256' => null,
                'observed_sha256' => null,
                'result' => 'unexpected',
            ];
            $mismatches = true;
        }
        $config = [];
        foreach ($this->privateConfig as $id => $policy) {
            $entry = $this->inspect($this->privateRoot, $policy['path'], $policy['sha256']);
            $config[] = ['policy_id' => $id, 'expected_sha256' => $policy['sha256']] + $entry;
            if ($entry['result'] !== 'match') $mismatches = true;
        }

        $payload = [
            'schema_version' => 1,
            'collector_id' => $this->collectorId,
            'issued_at' => $now,
            'expires_at' => $now + 60,
            'nonce' => $nonce,
            'target_origin' => $this->targetOrigin,
            'repository' => 'Double-IQ/SentryIQ',
            'repository_id' => '1345956206',
            'release_version' => $version,
            'tag' => 'v' . $version,
            'commit' => $commit,
            'manifest_sha256' => $manifestDigest,
            'artifact_sha256' => $artifactDigest,
            'files' => $files,
            'private_config' => $config,
            'decision' => $mismatches ? 'reject' : 'approve',
        ];
        $bytes = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        return [
            'payload' => base64_encode($bytes),
            'signature' => base64_encode(sodium_crypto_sign_detached($bytes, $this->secretKey)),
        ];
    }

    /** @return array{result:string,observed_sha256:?string} */
    private function inspect(string $root, string $relative, string $expected, ?int $expectedMode = null): array
    {
        $rootStat = @lstat($root);
        if (!is_array($rootStat) || (($rootStat['mode'] ?? 0) & 0170000) !== 0040000) {
            return ['result' => 'unreadable', 'observed_sha256' => null];
        }
        $directories = [[
            'path' => $root,
            'dev' => $rootStat['dev'] ?? null,
            'ino' => $rootStat['ino'] ?? null,
        ]];
        $current = $root;
        $parts = explode('/', $relative);
        foreach ($parts as $index => $part) {
            $current .= DIRECTORY_SEPARATOR . $part;
            clearstatcache(true, $current);
            $stat = @lstat($current);
            if ($stat === false) return ['result' => 'missing', 'observed_sha256' => null];
            if (($stat['mode'] & 0170000) === 0120000) {
                return ['result' => 'symlink', 'observed_sha256' => null];
            }
            if ($index < count($parts) - 1) {
                if (($stat['mode'] & 0170000) !== 0040000) {
                    return ['result' => 'unreadable', 'observed_sha256' => null];
                }
                $directories[] = [
                    'path' => $current,
                    'dev' => $stat['dev'] ?? null,
                    'ino' => $stat['ino'] ?? null,
                ];
            }
        }

        // Hash the opened descriptor, not the pathname. Compare its inode to
        // lstat before and after reading so a path/symlink swap cannot silently
        // redirect the collector between inspection and hashing.
        $handle = @fopen($current, 'rb');
        if (!is_resource($handle)) return ['result' => 'unreadable', 'observed_sha256' => null];
        try {
            $opened = fstat($handle);
            clearstatcache(true, $current);
            $pathStat = @lstat($current);
            if (!is_array($opened) || !is_array($pathStat)
                || ($opened['mode'] & 0170000) !== 0100000
                || ($pathStat['mode'] & 0170000) !== 0100000
                || $opened['dev'] !== $pathStat['dev']
                || $opened['ino'] !== $pathStat['ino']
                || !$this->directoriesUnchanged($directories)) {
                return ['result' => 'symlink', 'observed_sha256' => null];
            }
            if (!is_readable($current)) return ['result' => 'unreadable', 'observed_sha256' => null];

            $context = hash_init('sha256');
            if (hash_update_stream($context, $handle) === false) {
                return ['result' => 'unreadable', 'observed_sha256' => null];
            }
            $digest = hash_final($context);
            $after = fstat($handle);
            clearstatcache(true, $current);
            $pathAfter = @lstat($current);
            if (!is_array($after) || !is_array($pathAfter)
                || $after['dev'] !== $opened['dev'] || $after['ino'] !== $opened['ino']
                || $after['size'] !== $opened['size'] || $after['mtime'] !== $opened['mtime']
                || $after['ctime'] !== $opened['ctime']
                || ($pathAfter['mode'] & 0170000) !== 0100000
                || $pathAfter['dev'] !== $opened['dev'] || $pathAfter['ino'] !== $opened['ino']
                || !$this->directoriesUnchanged($directories)) {
                return ['result' => 'unreadable', 'observed_sha256' => null];
            }
            if (!hash_equals($expected, $digest)) {
                return ['result' => 'digest_mismatch', 'observed_sha256' => $digest];
            }
            if ($expectedMode !== null && (($opened['mode'] & 0777) !== $expectedMode)) {
                return ['result' => 'permission_mismatch', 'observed_sha256' => $digest];
            }
            return ['result' => 'match', 'observed_sha256' => $digest];
        } finally {
            fclose($handle);
        }
    }


    /**
     * Revalidate every directory inode after opening and hashing a target file.
     * This catches ancestor-directory replacement/symlink swaps, not just a
     * symlink at the final filename.
     *
     * @param list<array{path:string,dev:int|string|null,ino:int|string|null}> $directories
     */
    private function directoriesUnchanged(array $directories): bool
    {
        foreach ($directories as $directory) {
            clearstatcache(true, $directory['path']);
            $current = @lstat($directory['path']);
            if (!is_array($current) || (($current['mode'] ?? 0) & 0170000) !== 0040000
                || ($current['dev'] ?? null) !== $directory['dev']
                || ($current['ino'] ?? null) !== $directory['ino']) {
                return false;
            }
        }
        return true;
    }

    /** @return list<string> */
    private function findUnexpectedFiles(): array
    {
        $unexpected = [];
        $seen = [];
        $expected = array_fill_keys(array_keys($this->expectedFiles), true);
        foreach ($this->monitoredDirectories as $directory) {
            // Validate every component, not only the leaf: an ancestor symlink
            // must never redirect a fixed monitored path outside the webroot.
            $absolute = $this->publicRoot;
            $directoryIsSafe = true;
            foreach (explode('/', $directory) as $component) {
                $absolute .= DIRECTORY_SEPARATOR . $component;
                if (is_link($absolute) || !is_dir($absolute) || !is_readable($absolute)) {
                    $directoryIsSafe = false;
                    break;
                }
            }
            if (!$directoryIsSafe) {
                $unexpected[$directory] = true;
                continue;
            }
            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator($absolute, \FilesystemIterator::SKIP_DOTS),
                    \RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($iterator as $item) {
                    $relative = $directory . '/' . str_replace(DIRECTORY_SEPARATOR, '/', substr($item->getPathname(), strlen($absolute) + 1));
                    if (isset($seen[$relative])) continue;
                    $seen[$relative] = true;
                    if ($this->safeRelativePath($relative) && isset($expected[$relative])) continue;
                    if ($item->isLink() || $item->isFile()) {
                        // Preserve detection without emitting an unsafe or secret-bearing filename.
                        $evidencePath = $this->safeRelativePath($relative)
                            ? $relative
                            : 'unexpected-item-' . hash('sha256', $relative);
                        $unexpected[$evidencePath] = true;
                    }
                    if (count($unexpected) > 5000) {
                        throw new RuntimeException('Collector discovered more unexpected files than its evidence limit.');
                    }
                }
            } catch (\Throwable $exception) {
                if ($exception instanceof RuntimeException) throw $exception;
                $unexpected[$directory] = true;
            }
        }
        return array_keys($unexpected);
    }

    private function safeRelativePath(string $path): bool
    {
        if ($path === '' || strlen($path) > 240 || str_starts_with($path, '/')
            || str_contains($path, '\\\\') || str_contains($path, "\0")) return false;
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.' || $part === '..'
                || !preg_match('/^[A-Za-z0-9._-]+$/', $part)) return false;
        }
        return true;
    }

    public function __destruct()
    {
        if (isset($this->secretKey) && $this->secretKey !== '') sodium_memzero($this->secretKey);
    }
}
