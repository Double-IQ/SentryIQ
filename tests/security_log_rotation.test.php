<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/SecurityBootstrap.php';

function securityLogCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function securityLogRemoveTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) return;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) rmdir($item->getPathname());
        else unlink($item->getPathname());
    }
    rmdir($path);
}

$root = sys_get_temp_dir() . '/sentryiq-security-log-' . bin2hex(random_bytes(8));
$public = $root . '/public';
$data = $root . '/private';
foreach ([$public, $data] as $directory) {
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to prepare security log test workspace.');
    }
}
chmod($data, 0700);
try {
    $_SERVER['DOCUMENT_ROOT'] = $public;
    file_put_contents($data . '/sentryiq_config.php', '<?php return ' . var_export(['data_dir' => $data], true) . ';');
    copy(dirname(__DIR__) . '/private_data/vault_engine.php', $data . '/vault_engine.php');
    copy(dirname(__DIR__) . '/private_data/VaultKdfPolicy.php', $data . '/VaultKdfPolicy.php');
    chmod($data . '/vault_engine.php', 0600);
    chmod($data . '/VaultKdfPolicy.php', 0600);
    chmod($data . '/sentryiq_config.php', 0600);
    require_once $data . '/vault_engine.php';

    $event = [
        'timestamp' => date('c'),
        'event' => 'BASELINE_EVENT',
        'username' => 'test-user',
        'ip' => '127.0.0.1',
        'user_agent' => 'SentryIQ test',
        'context' => [],
    ];
    $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
    file_put_contents(LOG_FILE, str_repeat($line, 1200));
    chmod(LOG_FILE, 0600);
    $events = read_security_log();
    securityLogCheck(count($events) === 1000, 'Security log reader must return no more than the latest 1000 events.');

    $largeLog = str_repeat($line, 32000);
    file_put_contents(LOG_FILE, $largeLog);
    chmod(LOG_FILE, 0600);
    log_security_event('ROTATION_EVENT', '127.0.0.1', 'test-user', ['oversized' => str_repeat('x', 20000)]);
    securityLogCheck(is_file(LOG_FILE . '.1'), 'Oversized security log must be rotated.');
    securityLogCheck((int)filesize(LOG_FILE . '.1') > 5 * 1024 * 1024, 'Rotated log should preserve the previous bounded segment.');
    securityLogCheck((int)filesize(LOG_FILE) < 16384, 'Current log should contain only the new bounded event.');
    securityLogCheck(((int)fileperms(LOG_FILE) & 0077) === 0, 'Current security log permissions must be owner-only.');
    securityLogCheck(((int)fileperms(LOG_FILE . '.1') & 0077) === 0, 'Rotated security log permissions must be owner-only.');

    $events = read_security_log();
    securityLogCheck(count($events) === 1, 'Security log reader should return only the current segment after rotation.');
    securityLogCheck(($events[0]['event'] ?? '') === 'ROTATION_EVENT', 'Newest security event should be returned first.');
    securityLogCheck(($events[0]['context']['truncated'] ?? false) === true, 'Oversized event context must be truncated.');

    $outside = $root . '/outside.log';
    file_put_contents($outside, 'DO NOT MODIFY');
    rename(LOG_FILE, LOG_FILE . '.safe');
    if (!symlink($outside, LOG_FILE)) throw new RuntimeException('Unable to create log symlink fixture.');
    log_security_event('SYMLINK_ATTACK', '127.0.0.1');
    securityLogCheck(file_get_contents($outside) === 'DO NOT MODIFY', 'Log writer must not follow a symlink to an external file.');
    securityLogCheck(read_security_log() === [], 'Log reader must reject a symlinked log path.');

    echo "Security log rotation and bounded read tests passed.\\n";
} finally {
    unset($_SERVER['DOCUMENT_ROOT']);
    securityLogRemoveTree($root);
}
