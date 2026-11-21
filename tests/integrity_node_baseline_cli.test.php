<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityNodeReleaseStateStore.php';

use SentryIQ\Updates\IntegrityNodeReleaseStateStore;

function baselineCliAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function baselineCliRun(string $config, string $private, string $web): array
{
    $env = [
        'SENTRYIQ_INTEGRITY_BASELINE_CONFIG' => $config,
        'SENTRYIQ_INTEGRITY_PRIVATE_DATA_DIR' => $private,
        'SENTRYIQ_INTEGRITY_PUBLIC_WEB_ROOT' => $web,
    ];
    $process = proc_open(
        [PHP_BINARY, __DIR__ . '/../bin/integrity-node-baseline.php'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        null,
        $env
    );
    if (!is_resource($process)) throw new RuntimeException('Unable to launch baseline initializer CLI.');
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return ['status' => proc_close($process), 'stdout' => $stdout, 'stderr' => $stderr];
}

$root = sys_get_temp_dir() . '/sentryiq-node-baseline-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/httpdocs';
mkdir($private, 0700, true);
mkdir($web, 0700, true);
$config = $private . '/baseline.php';
$baseline = [
    'version' => '1.2.3',
    'commit' => str_repeat('a', 40),
    'manifest_sha256' => str_repeat('b', 64),
    'artifact_sha256' => str_repeat('c', 64),
];
file_put_contents($config, "<?php return " . var_export($baseline, true) . ";\n");
chmod($config, 0600);

try {
    $first = baselineCliRun($config, $private, $web);
    baselineCliAssert($first['status'] === 0, 'Explicit known-good baseline initialization should succeed: ' . $first['stderr']);
    $output = json_decode($first['stdout'], true, 8, JSON_THROW_ON_ERROR);
    baselineCliAssert(($output['status'] ?? null) === 'initialized', 'Baseline CLI should return a non-secret initialization summary.');

    $statePath = $private . '/integrity-release-state.json';
    $lockPath = $private . '/integrity-release-state.lock';
    baselineCliAssert(is_file($statePath) && ((fileperms($statePath) ?: 0) & 0777) === 0600,
        'Baseline state must be a regular owner-only file.');
    baselineCliAssert(is_file($lockPath) && ((fileperms($lockPath) ?: 0) & 0777) === 0600,
        'Baseline CLI must safely pre-provision the owner-only lock file.');
    $store = new IntegrityNodeReleaseStateStore($private, $web);
    baselineCliAssert($store->current()['version'] === '1.2.3', 'Stored baseline must match the independently supplied release.');

    $second = baselineCliRun($config, $private, $web);
    baselineCliAssert($second['status'] === 1, 'Baseline CLI must never overwrite an existing baseline.');

    chmod($config, 0400);
    $unsafe = baselineCliRun($config, $private, $web);
    baselineCliAssert($unsafe['status'] === 2, 'Baseline CLI must reject a config without exact 0600 permissions.');
    chmod($config, 0600);

    $webConfig = $web . '/baseline.php';
    file_put_contents($webConfig, "<?php return [];\n");
    chmod($webConfig, 0600);
    $webRejected = baselineCliRun($webConfig, $private, $web);
    baselineCliAssert($webRejected['status'] === 2, 'Baseline CLI must reject a config inside the public webroot.');
    @unlink($webConfig);
} finally {
    @unlink($config);
    @unlink($private . '/integrity-release-state.json');
    @unlink($private . '/integrity-release-state.lock');
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}

echo "Integrity baseline CLI tests passed.\n";
