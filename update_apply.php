<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_fresh_auth();
sentryiq_require_csrf();

$dataDir = sentryiq_data_dir();
if ($dataDir === '' || !str_starts_with($dataDir, '/') || !is_dir($dataDir) || is_link($dataDir)
    || !sentryiq_path_is_outside_document_root($dataDir)) {
    http_response_code(503);
    exit('SentryIQ secure runtime is unavailable.');
}

$privateConfigFile = $dataDir . '/sentryiq_config.php';
if (!is_file($privateConfigFile) || is_link($privateConfigFile) || !is_readable($privateConfigFile)) {
    http_response_code(503);
    exit('SentryIQ private updater configuration is unavailable.');
}

$config = require $privateConfigFile;
if (!is_array($config) || rtrim((string)($config['data_dir'] ?? ''), '/') !== rtrim($dataDir, '/')) {
    http_response_code(503);
    exit('SentryIQ private updater configuration is invalid.');
}

$sigstoreAutoload = trim((string)($config['sigstore_vendor_autoload'] ?? ''));
$realDataDir = realpath($dataDir);
$realAutoload = $sigstoreAutoload !== '' ? realpath($sigstoreAutoload) : false;
if ($sigstoreAutoload === '' || !is_string($realDataDir) || !is_string($realAutoload)
    || is_link($sigstoreAutoload) || !is_file($realAutoload) || !is_readable($realAutoload)
    || $realAutoload !== $sigstoreAutoload
    || !str_starts_with($realAutoload, rtrim($realDataDir, '/') . DIRECTORY_SEPARATOR)) {
    http_response_code(503);
    exit('Native Sigstore verification is not configured; refusing to install an unattested release.');
}

require_once __DIR__ . '/app/Updates/TufRootStore.php';
require_once __DIR__ . '/app/Updates/ReleaseTrustPolicy.php';
require_once __DIR__ . '/app/Updates/UpdateManager.php';

try {
    $manager = new SentryIQ\Updates\UpdateManager(
        __DIR__,
        $dataDir,
        sigstoreAutoloadPath: $sigstoreAutoload
    );
    $result = $manager->applyLatest();

    if (function_exists('log_security_event') && function_exists('get_visitor_ip')) {
        log_security_event('APPLICATION_UPDATED', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown', [
            'from' => $result['from'] ?? null,
            'to' => $result['to'] ?? null,
        ]);
    }

    sentryiq_lock_vault();
    header('Location: index.php');
    exit;
} catch (Throwable $exception) {
    // Do not expose verifier diagnostics, filesystem paths, or signed bundle URLs.
    error_log('SentryIQ application update failed: ' . $exception::class);
    http_response_code(500);
    exit('SentryIQ update failed. Check the private security log or contact the administrator.');
}
