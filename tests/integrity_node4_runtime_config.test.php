<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityNode4RuntimeConfig.php';

use SentryIQ\Updates\IntegrityNode4RuntimeConfig;

$root = sys_get_temp_dir() . '/sentryiq-node4-config-' . bin2hex(random_bytes(6));
$public = $root . '/httpdocs';
$private = $root . '/private_data';
if (!mkdir($public, 0700, true) || !mkdir($private, 0700, true)) {
    throw new RuntimeException('Unable to create runtime-config test directories.');
}
$pointer = $public . '/sentryiq_config.php';
$privateConfig = $private . '/sentryiq_config.php';
file_put_contents($pointer, '<?php return ' . var_export([
    'data_dir' => $private,
    'base_url' => 'https://example.invalid',
], true) . ';');
file_put_contents($privateConfig, '<?php return ' . var_export([
    'data_dir' => $private,
    'integrity_event' => ['enabled' => true, 'node_tokens' => ['integrity-a' => str_repeat('a', 40)]],
], true) . ';');

try {
    $loaded = IntegrityNode4RuntimeConfig::load($pointer);
    if (($loaded['integrity_event']['enabled'] ?? false) !== true
        || ($loaded['integrity_event']['node_tokens']['integrity-a'] ?? null) !== str_repeat('a', 40)
        || ($loaded['base_url'] ?? null) !== 'https://example.invalid'
        || ($loaded['data_dir'] ?? null) !== realpath($private)) {
        throw new RuntimeException('Runtime-config loader did not merge the public pointer and private settings.');
    }

    $badPointer = $public . '/bad-pointer.php';
    file_put_contents($badPointer, '<?php return ' . var_export(['data_dir' => $public], true) . ';');
    try {
        IntegrityNode4RuntimeConfig::load($badPointer);
        throw new RuntimeException('Runtime-config loader accepted a data directory inside the webroot.');
    } catch (RuntimeException $expected) {
        if ($expected->getMessage() === 'Runtime-config loader accepted a data directory inside the webroot.') {
            throw $expected;
        }
    }

    $secretPointer = $public . '/secret-pointer.php';
    file_put_contents($secretPointer, '<?php return ' . var_export([
        'data_dir' => $private,
        'integrity_event' => ['node_tokens' => ['integrity-a' => 'should-not-be-here']],
    ], true) . ';');
    $secretRejected = false;
    try {
        IntegrityNode4RuntimeConfig::load($secretPointer);
    } catch (RuntimeException) {
        $secretRejected = true;
    }
    if (!$secretRejected) {
        throw new RuntimeException('Runtime-config loader accepted secrets in the public pointer.');
    }
} finally {
    @unlink($pointer);
    @unlink($privateConfig);
    @unlink($public . '/bad-pointer.php');
    @unlink($public . '/secret-pointer.php');
    @rmdir($public);
    @rmdir($private);
    @rmdir($root);
}

echo "Integrity Node 4 runtime config tests passed.\n";
