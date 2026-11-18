<?php

declare(strict_types=1);

// Installation diagnostics disclose filesystem paths and configuration state.
// Keep web access behind the normal SentryIQ authenticated session; when the
// application is not installed, allow this diagnostic only from the CLI.
require_once dirname(__DIR__) . '/app/Security/SecurityBootstrap.php';
require_once dirname(__DIR__) . '/app/Security/BoundedLog.php';
sentryiq_security_bootstrap();

if (PHP_SAPI !== 'cli') {
    $configPath = dirname(__DIR__) . '/sentryiq_config.php';
    if (!is_file($configPath) || is_link($configPath)) {
        http_response_code(404);
        exit('Not found.');
    }
    sentryiq_require_auth();
}

$writeDiagnosticLog = PHP_SAPI === 'cli';
if (PHP_SAPI !== 'cli') {
    $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    if ($method === 'POST') {
        sentryiq_require_csrf();
        $writeDiagnosticLog = true;
    } elseif (!in_array($method, ['GET', 'HEAD'], true)) {
        http_response_code(405);
        exit('Method not allowed.');
    }
}

header('Content-Type: application/json; charset=utf-8');

$webRoot = __DIR__;
$inferredDataDir = rtrim(dirname(dirname($webRoot)), '/') . '/private_data';
$configFile = $webRoot . '/sentryiq_config.php';
$firstRunFile = $webRoot . '/first_run.php';
$logFile = $inferredDataDir . '/install_postmortem.log';

$record = [
    'timestamp' => date('c'),
    'stage' => 'POST_INSTALL_DIAGNOSTIC',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'web_root' => $webRoot,
    'inferred_data_dir' => $inferredDataDir,
    'config_file' => $configFile,
    'config_exists' => is_file($configFile),
    'config_is_link' => is_link($configFile),
    'config_readable' => is_readable($configFile),
    'config_permissions' => is_file($configFile) ? decoct((int)(fileperms($configFile) & 0x01ff)) : null,
    'first_run_exists' => is_file($firstRunFile),
    'first_run_is_link' => is_link($firstRunFile),
];

if (is_file($configFile) && !is_link($configFile) && is_readable($configFile)) {
    try {
        $config = require $configFile;
        $record['config_valid_array'] = is_array($config);
        if (is_array($config)) {
            $configuredDataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
            $record['configured_data_dir'] = $configuredDataDir;
            $record['configured_base_url_present'] = trim((string)($config['base_url'] ?? '')) !== '';
            $record['configured_data_dir_exists'] = $configuredDataDir !== '' && is_dir($configuredDataDir);
            $record['configured_vault_engine_exists'] = $configuredDataDir !== '' && is_file($configuredDataDir . '/vault_engine.php');
            $record['configured_email_template_exists'] = $configuredDataDir !== '' && is_file($configuredDataDir . '/email_template.php');
            $record['index_runtime_guard_passes'] = $configuredDataDir !== ''
                && str_starts_with($configuredDataDir, '/')
                && is_dir($configuredDataDir)
                && is_file($configuredDataDir . '/vault_engine.php')
                && is_file($configuredDataDir . '/email_template.php');
        }
    } catch (Throwable $exception) {
        $record['config_valid_array'] = false;
        $record['config_load_error'] = $exception::class;
    }
} else {
    $record['config_valid_array'] = null;
}

$record['inferred_data_dir_exists'] = is_dir($inferredDataDir);
$record['inferred_data_dir_permissions'] = is_dir($inferredDataDir) ? decoct((int)(fileperms($inferredDataDir) & 0x01ff)) : null;
$record['inferred_vault_exists'] = is_file($inferredDataDir . '/passwords.enc');
$record['inferred_engine_exists'] = is_file($inferredDataDir . '/vault_engine.php');
$record['inferred_template_exists'] = is_file($inferredDataDir . '/email_template.php');

if ($record['config_exists'] === false && $record['first_run_exists'] === false) {
    $record['index_failure_reason'] = 'installation_unavailable_condition';
} elseif ($record['config_exists'] === true && $record['config_valid_array'] === false) {
    $record['index_failure_reason'] = 'configuration_unavailable_condition';
} elseif ($record['config_exists'] === true && ($record['index_runtime_guard_passes'] ?? false) === false) {
    $record['index_failure_reason'] = 'secure_runtime_unavailable_condition';
} else {
    $record['index_failure_reason'] = 'no_index_startup_failure_detected';
}

if ($writeDiagnosticLog && is_dir($inferredDataDir)) {
    $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) {
        \SentryIQ\Security\BoundedLog::append($logFile, $line . PHP_EOL);
        @chmod($logFile, 0600);
    }
}

echo json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
