<?php

declare(strict_types=1);

function integrityCliAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-node-cli-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/httpdocs';
mkdir($private, 0700, true);
mkdir($web, 0700, true);
$config = $private . '/node-config.php';
$configBody = <<<'PHP_CONFIG'
<?php
if (!class_exists('SentryIQ' . chr(92) . 'Updates' . chr(92) . 'PrivateHostAttestationClient')
    || !class_exists('SentryIQ' . chr(92) . 'Updates' . chr(92) . 'PrivateHostAttestationVerifier')
    || !class_exists('SentryIQ' . chr(92) . 'Updates' . chr(92) . 'IntegrityNodeVerifierBinding')) {
    throw new RuntimeException('Private-host attestation classes were not preloaded.');
}
return null;
PHP_CONFIG;
file_put_contents($config, $configBody);
chmod($config, 0600);

$command = [PHP_BINARY, __DIR__ . '/../bin/integrity-node-run.php'];
$environment = [
    'SENTRYIQ_INTEGRITY_NODE_CONFIG' => $config,
    'SENTRYIQ_INTEGRITY_PRIVATE_DATA_DIR' => $private,
    'SENTRYIQ_INTEGRITY_PUBLIC_WEB_ROOT' => $web,
];
$process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $environment);
if (!is_resource($process)) throw new RuntimeException('Unable to launch integrity node CLI.');
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$status = proc_close($process);

chmod($config, 0400);
$unsafeProcess = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $unsafePipes, null, $environment);
if (!is_resource($unsafeProcess)) throw new RuntimeException('Unable to launch CLI permission regression check.');
fclose($unsafePipes[0]);
$unsafeStdout = stream_get_contents($unsafePipes[1]);
$unsafeStderr = stream_get_contents($unsafePipes[2]);
fclose($unsafePipes[1]);
fclose($unsafePipes[2]);
$unsafeStatus = proc_close($unsafeProcess);
chmod($config, 0600);

$insideWebrootConfig = $web . '/node-config.php';
file_put_contents($insideWebrootConfig, $configBody);
chmod($insideWebrootConfig, 0600);
$webEnvironment = $environment;
$webEnvironment['SENTRYIQ_INTEGRITY_NODE_CONFIG'] = $insideWebrootConfig;
$webProcess = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $webPipes, null, $webEnvironment);
if (!is_resource($webProcess)) throw new RuntimeException('Unable to launch webroot config regression check.');
fclose($webPipes[0]);
$webStdout = stream_get_contents($webPipes[1]);
$webStderr = stream_get_contents($webPipes[2]);
fclose($webPipes[1]);
fclose($webPipes[2]);
$webStatus = proc_close($webProcess);

integrityCliAssert($unsafeStatus === 2,
    'CLI must reject a read-only 0400 config rather than accepting any mode without group/world access.');
integrityCliAssert($webStatus === 2, 'CLI must reject a node config located inside the public webroot.');
integrityCliAssert($status === 1, 'CLI must reject a config that does not return a scheduled runner.');
integrityCliAssert(str_contains((string)$stderr, 'Integrity node run failed: RuntimeException'),
    'CLI config must execute after all required classes are preloaded; stderr: ' . $stderr);
integrityCliAssert(!str_contains((string)$stderr, 'Private-host attestation classes were not preloaded'),
    'CLI must preload private-host trust and concrete node-verifier binding classes before requiring private config.');

@unlink($config);
@unlink($insideWebrootConfig);
@rmdir($private);
@rmdir($web);
@rmdir($root);
echo "Integrity node CLI bootstrap tests passed.\n";
