<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Not found.');
}

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();

$firstRun = __DIR__ . '/first_run.php';
$configFile = __DIR__ . '/sentryiq_config.php';
if (!is_file($firstRun) || is_file($configFile)) {
    http_response_code(404);
    exit('Not found.');
}

$dataDir = rtrim(dirname(dirname(__DIR__)), '/') . '/private_data';
$dataFile = $dataDir . '/passwords.enc';
$engineFile = $dataDir . '/vault_engine.php';
$secureConfig = $dataDir . '/sentryiq_config.php';
$logFile = $dataDir . '/install_debug.log';

function diag_write(string $stage, array $details): void {
    global $logFile, $dataDir;
    if (!is_dir($dataDir)) return;
    $record = ['timestamp' => date('c'), 'stage' => $stage, 'php_version' => PHP_VERSION, 'sapi' => PHP_SAPI];
    foreach ($details as $k => $v) if (is_scalar($v) || $v === null) $record[$k] = $v;
    $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) { @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX); @chmod($logFile, 0600); }
}

clearstatcache(true);
$dirExists = is_dir($dataDir);
$dirLink = is_link($dataDir);
$dirReal = $dirExists ? realpath($dataDir) : false;
$dirPerms = $dirExists ? @fileperms($dataDir) : false;
$dirWritable = $dirExists && is_writable($dataDir);
$fileExists = file_exists($dataFile);
$fileIsFile = is_file($dataFile);
$fileIsLink = is_link($dataFile);
$fileReadable = is_readable($dataFile);
$fileSize = $fileIsFile ? @filesize($dataFile) : false;
$filePerms = $fileIsFile ? @fileperms($dataFile) : false;
$engineExists = is_file($engineFile);
$secureConfigExists = is_file($secureConfig);
$secureConfigDataDir = null;
if ($secureConfigExists) {
    try {
        $loaded = require $secureConfig;
        if (is_array($loaded)) $secureConfigDataDir = (string)($loaded['data_dir'] ?? '');
    } catch (Throwable) {
        $secureConfigDataDir = '[load_failed]';
    }
}
$trusted = $dirExists && !$dirLink && $dirReal !== false && rtrim($dirReal, '/') === rtrim($dataDir, '/') && $dirPerms !== false && (($dirPerms & 0x0077) === 0) && $dirWritable;

$result = [
    'data_dir_exists' => $dirExists,
    'data_dir_is_link' => $dirLink,
    'data_dir_realpath_matches' => ($dirReal !== false && rtrim($dirReal, '/') === rtrim($dataDir, '/')),
    'data_dir_permissions' => ($dirPerms === false ? null : decoct($dirPerms & 0x01ff)),
    'data_dir_writable' => $dirWritable,
    'trusted_directory_result' => $trusted,
    'data_file_exists' => $fileExists,
    'data_file_is_file' => $fileIsFile,
    'data_file_is_link' => $fileIsLink,
    'data_file_readable' => $fileReadable,
    'data_file_size' => ($fileSize === false ? null : $fileSize),
    'data_file_permissions' => ($filePerms === false ? null : decoct($filePerms & 0x01ff)),
    'engine_exists' => $engineExists,
    'secure_config_exists' => $secureConfigExists,
    'secure_config_data_dir' => $secureConfigDataDir,
    'guard_would_pass' => ($trusted && $fileIsFile && !$fileIsLink),
];

diag_write('RUNTIME_GUARD_DIAGNOSTIC', ['data_dir' => $dataDir] + $result);

header('Content-Type: application/json; charset=utf-8');
echo json_encode(['diagnostic' => 'RUNTIME_GUARD_DIAGNOSTIC', 'data_dir' => $dataDir] + $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
