<?php

declare(strict_types=1);

/**
 * Regression test for the production CLI's explicit class preload contract.
 * The protected config deliberately returns no runner after checking that the
 * collector client and verifier classes are available to the config file.
 */

function integrityCliAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$config = tempnam(sys_get_temp_dir(), 'sentryiq-node-cli-config-');
if (!is_string($config)) {
    throw new RuntimeException('Unable to create temporary CLI config.');
}
$configBody = <<<'PHP_CONFIG'
<?php
if (!class_exists('SentryIQ' . chr(92) . 'Updates' . chr(92) . 'PrivateHostAttestationClient')
    || !class_exists('SentryIQ' . chr(92) . 'Updates' . chr(92) . 'PrivateHostAttestationVerifier')) {
    throw new RuntimeException('Private-host attestation classes were not preloaded.');
}
return null;
PHP_CONFIG;
file_put_contents($config, $configBody);
chmod($config, 0600);

$command = [PHP_BINARY, __DIR__ . '/../bin/integrity-node-run.php'];
$process = proc_open(
    $command,
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $pipes,
    null,
    ['SENTRYIQ_INTEGRITY_NODE_CONFIG' => $config]
);
if (!is_resource($process)) {
    @unlink($config);
    throw new RuntimeException('Unable to launch integrity node CLI.');
}
fclose($pipes[0]);
$stdout = stream_get_contents($pipes[1]);
$stderr = stream_get_contents($pipes[2]);
fclose($pipes[1]);
fclose($pipes[2]);
$status = proc_close($process);
// A merely non-world-readable file is not sufficient: the bootstrap contract
// requires an exact 0600 regular config file.
chmod($config, 0400);
$unsafeProcess = proc_open(
    $command,
    [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
    $unsafePipes,
    null,
    ['SENTRYIQ_INTEGRITY_NODE_CONFIG' => $config]
);
if (!is_resource($unsafeProcess)) {
    @unlink($config);
    throw new RuntimeException('Unable to launch CLI permission regression check.');
}
fclose($unsafePipes[0]);
$unsafeStdout = stream_get_contents($unsafePipes[1]);
$unsafeStderr = stream_get_contents($unsafePipes[2]);
fclose($unsafePipes[1]);
fclose($unsafePipes[2]);
$unsafeStatus = proc_close($unsafeProcess);
chmod($config, 0600);

integrityCliAssert($unsafeStatus === 2,
    'CLI must reject a read-only 0400 config rather than accepting any mode without group/world access; stderr: ' . $unsafeStderr);
@unlink($config);

integrityCliAssert($status === 1, 'CLI must reject a config that does not return a scheduled runner.');
integrityCliAssert(str_contains((string)$stderr, 'Integrity node run failed: RuntimeException'),
    'CLI config must execute after all required classes are preloaded; stderr: ' . $stderr);
integrityCliAssert(!str_contains((string)$stderr, 'Private-host attestation classes were not preloaded'),
    'CLI must preload the private-host client and verifier before requiring private config.');
echo "Integrity node CLI bootstrap tests passed.\n";
