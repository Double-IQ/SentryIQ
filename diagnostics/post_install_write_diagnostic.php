<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit('Not found.');
}

header('Content-Type: application/json; charset=utf-8');

$webRoot = __DIR__;
$parent = dirname($webRoot);
$configFile = $webRoot . '/sentryiq_config.php';
$record = [
    'timestamp' => date('c'),
    'stage' => 'POST_INSTALL_WRITE_DIAGNOSTIC',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'web_root' => $webRoot,
    'web_root_exists' => is_dir($webRoot),
    'web_root_permissions' => is_dir($webRoot) ? decoct((int)(fileperms($webRoot) & 0x01ff)) : null,
    'web_root_writable' => is_dir($webRoot) && is_writable($webRoot),
    'parent_directory' => $parent,
    'parent_permissions' => is_dir($parent) ? decoct((int)(fileperms($parent) & 0x01ff)) : null,
    'parent_writable' => is_dir($parent) && is_writable($parent),
    'config_exists_before' => is_file($configFile),
    'config_is_link_before' => is_link($configFile),
];

$probe = $webRoot . '/.sentryiq_write_probe_' . bin2hex(random_bytes(8));
$payload = "<?php\nreturn [];\n";
$previousError = set_error_handler(static function (int $severity, string $message): bool {
    throw new RuntimeException($message, $severity);
});
try {
    $written = file_put_contents($probe, $payload, LOCK_EX);
    $record['probe_write_ok'] = $written === strlen($payload);
    $record['probe_bytes_written'] = is_int($written) ? $written : null;
    $record['probe_permissions'] = is_file($probe) ? decoct((int)(fileperms($probe) & 0x01ff)) : null;
    $record['probe_readable'] = is_file($probe) && is_readable($probe);
    if (is_file($probe)) @unlink($probe);
} catch (Throwable $exception) {
    $record['probe_write_ok'] = false;
    $record['probe_exception'] = $exception::class;
    $record['probe_error'] = $exception->getMessage();
    @unlink($probe);
} finally {
    if ($previousError !== null) restore_error_handler(); else restore_error_handler();
}

$record['config_exists_after_probe'] = is_file($configFile);
$record['config_parent_writable'] = is_writable(dirname($configFile));

$dataDir = rtrim(dirname(dirname(__DIR__)), '/') . '/private_data';
$logFile = $dataDir . '/install_postmortem.log';
$line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if (is_dir($dataDir) && is_string($line)) {
    @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    @chmod($logFile, 0600);
}

echo json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
