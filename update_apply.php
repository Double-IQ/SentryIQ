<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_fresh_auth();
sentryiq_require_csrf();

$configFile = __DIR__ . '/sentryiq_config.php';
$config = is_file($configFile) ? require $configFile : [];
$dataDir = is_array($config) ? rtrim((string)($config['data_dir'] ?? ''), '/') : '';
$sigstoreAutoload = is_array($config) ? trim((string)($config['sigstore_vendor_autoload'] ?? '')) : '';
if ($dataDir === '' || !str_starts_with($dataDir, '/') || !is_dir($dataDir) || is_link($dataDir)) {
    http_response_code(503);
    exit('SentryIQ secure runtime is unavailable.');
}

require_once __DIR__ . '/app/Updates/TufRootStore.php';
require_once __DIR__ . '/app/Updates/ReleaseTrustPolicy.php';
require_once __DIR__ . '/app/Updates/SigstoreProvenance.php';
require_once __DIR__ . '/app/Updates/NativeSigstoreReleaseVerifier.php';
require_once __DIR__ . '/app/Updates/UpdateManager.php';

try {
    $manager = new SentryIQ\Updates\UpdateManager(__DIR__, $dataDir);
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
    error_log('SentryIQ application update failed: ' . $exception::class . ': ' . $exception->getMessage());
    http_response_code(500);
    exit('SentryIQ update failed: ' . $exception->getMessage());
}
