<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

$configFile = dirname(__DIR__) . '/sentryiq_config.php';
$config = is_file($configFile) && !is_link($configFile) ? require $configFile : [];
$event = is_array($config) ? ($config['integrity_event'] ?? null) : null;
$dataDir = is_array($config) ? (string)($config['data_dir'] ?? '') : '';
$storageDir = is_array($event) ? (string)($event['storage_dir'] ?? '') : '';
$targetOrigin = is_array($event) ? (string)($event['target_origin'] ?? '') : '';
$sender = is_array($event) ? ($event['alert_sender'] ?? null) : null;

$realDataDir = $dataDir !== '' ? realpath($dataDir) : false;
$realStorageDir = $storageDir !== '' ? realpath($storageDir) : false;
if (!is_array($event) || ($event['enabled'] ?? false) !== true
    || !is_string($realDataDir) || !is_string($realStorageDir)
    || !str_starts_with($realStorageDir, rtrim($realDataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || !is_callable($sender) || $targetOrigin === '') {
    fwrite(STDERR, "Node 4 monitor is not fully configured.\n");
    exit(2);
}

require_once dirname(__DIR__) . '/app/Updates/FileIntegrityEventStore.php';
require_once dirname(__DIR__) . '/app/Updates/IntegrityIncidentCorrelator.php';
require_once dirname(__DIR__) . '/app/Updates/IntegrityAlertDispatcher.php';
require_once dirname(__DIR__) . '/app/Updates/IntegrityNode4Monitor.php';

try {
    $store = new SentryIQ\Updates\FileIntegrityEventStore($realStorageDir);
    $correlator = new SentryIQ\Updates\IntegrityIncidentCorrelator();
    $dispatcher = new SentryIQ\Updates\IntegrityAlertDispatcher($store, $sender);
    $monitor = new SentryIQ\Updates\IntegrityNode4Monitor($store, $correlator, $dispatcher);
    $result = $monitor->run($targetOrigin);
    fwrite(STDOUT, json_encode($result, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
    exit(($result['evaluation']['status'] ?? null) === 'healthy' ? 0 : 1);
} catch (Throwable $exception) {
    fwrite(STDERR, "Node 4 monitor execution failed.\n");
    exit(3);
}
