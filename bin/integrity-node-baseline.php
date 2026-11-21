<?php

declare(strict_types=1);

use SentryIQ\Updates\IntegrityNodeReleaseStateStore;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once __DIR__ . '/../app/Updates/IntegrityNodeReleaseStateStore.php';

$privateDataDirectory = getenv('SENTRYIQ_INTEGRITY_PRIVATE_DATA_DIR');
$publicWebRoot = getenv('SENTRYIQ_INTEGRITY_PUBLIC_WEB_ROOT');
$baselineConfigPath = getenv('SENTRYIQ_INTEGRITY_BASELINE_CONFIG');
$private = is_string($privateDataDirectory) ? realpath($privateDataDirectory) : false;
$web = is_string($publicWebRoot) ? realpath($publicWebRoot) : false;
$configReal = is_string($baselineConfigPath) ? realpath($baselineConfigPath) : false;
$configStat = is_string($baselineConfigPath) ? @lstat($baselineConfigPath) : false;
$privateStat = is_string($private) ? @lstat($private) : false;

if (!is_string($private) || !is_dir($private) || !is_array($privateStat)
    || (($privateStat['mode'] ?? 0) & 0170000) !== 0040000
    || (($privateStat['mode'] ?? 0) & 0777) !== 0700
    || !is_string($web) || !is_dir($web) || !is_string($publicWebRoot) || is_link($publicWebRoot)
    || $private === $web || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || !is_string($baselineConfigPath) || $baselineConfigPath === ''
    || !str_starts_with($baselineConfigPath, DIRECTORY_SEPARATOR) || is_link($baselineConfigPath)
    || !is_string($configReal) || !is_array($configStat)
    || (($configStat['mode'] ?? 0) & 0170000) !== 0100000
    || (($configStat['mode'] ?? 0) & 0777) !== 0600
    || !str_starts_with($configReal, rtrim($private, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || str_starts_with($configReal, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
    fwrite(STDERR, "A mode-0600 baseline file inside the exact-0700 private data directory is required.\n");
    exit(2);
}

try {
    $handle = @fopen($configReal, 'rb');
    $opened = is_resource($handle) ? @fstat($handle) : false;
    clearstatcache(true, $configReal);
    $current = @lstat($configReal);
    if (!is_resource($handle) || !is_array($opened) || !is_array($current)
        || ($opened['dev'] ?? null) !== ($configStat['dev'] ?? null)
        || ($opened['ino'] ?? null) !== ($configStat['ino'] ?? null)
        || ($current['dev'] ?? null) !== ($opened['dev'] ?? null)
        || ($current['ino'] ?? null) !== ($opened['ino'] ?? null)) {
        if (is_resource($handle)) fclose($handle);
        throw new RuntimeException('Private baseline configuration changed during open.');
    }
    fclose($handle);

    $baseline = require $configReal;
    $required = ['version', 'commit', 'manifest_sha256', 'artifact_sha256'];
    if (!is_array($baseline)) throw new RuntimeException('Baseline configuration must return an array.');
    $keys = array_keys($baseline);
    sort($keys);
    sort($required);
    if ($keys !== $required) throw new RuntimeException('Baseline configuration has missing or unknown fields.');
    foreach ($required as $field) {
        if (!is_string($baseline[$field])) throw new RuntimeException('Baseline field types are invalid.');
    }

    $lockPath = $private . '/integrity-release-state.lock';
    clearstatcache(true, $lockPath);
    if (is_link($lockPath)) throw new RuntimeException('Integrity release state lock must not be a symlink.');
    if (!file_exists($lockPath)) {
        $lockHandle = @fopen($lockPath, 'x+b');
        if ($lockHandle === false) throw new RuntimeException('Unable to pre-provision the integrity release state lock.');
        $lockOk = @chmod($lockPath, 0600);
        if ($lockOk) $lockOk = @fflush($lockHandle);
        if ($lockOk && function_exists('fsync')) $lockOk = @fsync($lockHandle);
        $lockStat = @fstat($lockHandle);
        fclose($lockHandle);
        clearstatcache(true, $lockPath);
        $lockPathStat = @lstat($lockPath);
        if (!$lockOk || !is_array($lockStat) || !is_array($lockPathStat)
            || (($lockStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($lockStat['mode'] ?? 0) & 0777) !== 0600
            || ($lockStat['dev'] ?? null) !== ($lockPathStat['dev'] ?? null)
            || ($lockStat['ino'] ?? null) !== ($lockPathStat['ino'] ?? null)) {
            throw new RuntimeException('Integrity release state lock could not be safely pre-provisioned.');
        }
    } else {
        $lockStat = @lstat($lockPath);
        if (!is_array($lockStat) || (($lockStat['mode'] ?? 0) & 0170000) !== 0100000
            || (($lockStat['mode'] ?? 0) & 0777) !== 0600) {
            throw new RuntimeException('Existing integrity release state lock has unsafe type or permissions.');
        }
    }

    $store = new IntegrityNodeReleaseStateStore($private, $web);
    $store->initializeBaseline(
        $baseline['version'],
        $baseline['commit'],
        $baseline['manifest_sha256'],
        $baseline['artifact_sha256']
    );
    fwrite(STDOUT, json_encode([
        'status' => 'initialized',
        'version' => ltrim($baseline['version'], 'v'),
        'commit' => strtolower($baseline['commit']),
        'baseline_file' => $private . '/integrity-release-state.json',
        'baseline_config_delete_after_use' => true,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(0);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Integrity baseline initialization failed: ' . get_class($exception) . PHP_EOL);
    exit(1);
}
