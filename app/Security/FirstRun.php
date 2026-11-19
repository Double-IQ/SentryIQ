<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
require_once __DIR__ . '/FirstRunPath.php';
require_once __DIR__ . '/BoundedLog.php';
sentryiq_security_bootstrap();

$pointerConfigFile = dirname(__DIR__, 2) . '/sentryiq_config.php';
if (is_file($pointerConfigFile)) {
    http_response_code(404);
    exit('Not found.');
}

function first_run_data_dir(): string
{
    return sentryiq_first_run_configured_data_dir();
}

function first_run_base_url(): string
{
    $host = trim((string)($_SERVER['SERVER_NAME'] ?? ''));
    if ($host === '' || !preg_match('/^[A-Za-z0-9.-]+$/', $host)) return '';
    if (PHP_SAPI !== 'cli' && (($_SERVER['HTTPS'] ?? '') !== 'on' && (string)($_SERVER['SERVER_PORT'] ?? '') !== '443')) return '';
    $path = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? ''))), '/');
    return 'https://' . $host . ($path === '/' ? '' : $path);
}

function first_run_log(string $stage, array $details = []): void
{
    $dir = first_run_data_dir();
    if (!is_dir($dir)) return;
    $record = ['timestamp' => date('c'), 'stage' => $stage, 'php_version' => PHP_VERSION, 'sapi' => PHP_SAPI];
    foreach ($details as $key => $value) if (is_scalar($value) || $value === null) $record[$key] = $value;
    $path = $dir . '/install_debug.log';
    $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) { try { \SentryIQ\Security\BoundedLog::append($path, $line . PHP_EOL); } catch (Throwable) {} }
}

function first_run_prepare_dir(string $dir): bool
{
    if ($dir === '' || !str_starts_with($dir, '/') || str_contains($dir, "..")) return false;
    if (preg_match('#/(public_html|htdocs|www)(/|$)#i', $dir)) return false;
    if (!sentryiq_first_run_path_is_safe_candidate($dir)) return false;
    if (is_link($dir)) return false;
    if (!is_dir($dir) && !@mkdir($dir, 0700, false)) return false;
    if (!sentryiq_path_is_outside_document_root($dir)) return false;
    @chmod($dir, 0700);
    clearstatcache(true, $dir);
    $perms = @fileperms($dir);
    if (!is_dir($dir) || $perms === false || (($perms & 0x01ff) !== 0700)) return false;
    $probe = $dir . '/.sentryiq_probe_' . bin2hex(random_bytes(8));
    if (@file_put_contents($probe, 'ok', LOCK_EX) !== 2) { @unlink($probe); return false; }
    @unlink($probe);
    return true;
}

function first_run_write_config(string $path, string $username, string $email, string $baseUrl, string $dir): bool
{
    $config = "<?php\nreturn [\n" .
        "    'installed' => true,\n" .
        "    'username' => " . var_export($username, true) . ",\n" .
        "    'two_fa_email' => " . var_export($email, true) . ",\n" .
        "    'base_url' => " . var_export($baseUrl, true) . ",\n" .
        "    'data_dir' => " . var_export($dir, true) . ",\n" .
        "    'two_fa_token_expiry' => 300,\n];\n";
    return @file_put_contents($path, $config, LOCK_EX) !== false && @chmod($path, 0600);
}

function first_run_initialize(string $password, string $dataFile): void
{
    first_run_log('VAULT_INITIALIZATION_STARTED', ['data_file' => $dataFile, 'format_version' => SENTRYIQ_VAULT_VERSION]);
    $records = [[
        'id' => 'sys_config_node',
        'type' => 'system_config',
        'app_username' => (string)($_POST['setup_username'] ?? ''),
        '2fa_email' => (string)($_POST['setup_email'] ?? ''),
        'imap_password' => '',
    ]];
    if (!vault_initialize($password, $records)) {
        throw new RuntimeException('vault_initialization_failed');
    }
    $verified = vault_unlock($password);
    if (!is_array($verified) || !isset($verified['key']) || strlen((string)$verified['key']) !== 32) {
        throw new RuntimeException('vault_verification_failed');
    }
    $recoveryKey = vault_generate_recovery_key();
    if (!vault_add_recovery_wrapper((string)$verified['key'], $recoveryKey)) {
        throw new RuntimeException('recovery_wrapper_failed');
    }
    $recoveryEnvelope = vault_read_envelope();
    $recoveredKey = vault_unwrap_vmk_with_recovery_key($recoveryEnvelope['envelope'], $recoveryKey);
    if ($recoveredKey === false || !hash_equals((string)$verified['key'], $recoveredKey)) {
        throw new RuntimeException('recovery_wrapper_verification_failed');
    }
    $recoveredRecords = load_passwords($recoveredKey);
    if ($recoveredRecords === false) {
        throw new RuntimeException('recovery_data_verification_failed');
    }
    $_SESSION['first_run_recovery_key'] = $recoveryKey;
    first_run_log('VAULT_FILE_WRITE_COMPLETED', ['format_version' => SENTRYIQ_VAULT_VERSION, 'recovery_wrapper' => true]);
}

function first_run_direct_crypto_verify(string $password, string $dataFile): void
{
    first_run_log('DIRECT_CRYPTO_VERIFY_STARTED', ['data_file' => $dataFile]);
    clearstatcache(true, $dataFile);
    if (!is_file($dataFile) || is_link($dataFile)) throw new RuntimeException('direct_file_invalid');

    $unlocked = vault_unlock($password);
    if (!is_array($unlocked) || !isset($unlocked['key']) || strlen((string)$unlocked['key']) !== 32) {
        throw new RuntimeException('direct_vault_unlock_failed');
    }

    first_run_log('DIRECT_CRYPTO_VERIFY_COMPLETED', [
        'format_version' => SENTRYIQ_VAULT_VERSION,
        'record_count' => count($unlocked['records']),
    ]);
}

function first_run_cleanup(): bool
{
    $dir = dirname(__DIR__, 2) . '/private_data';
    if (!is_dir($dir)) return true;

    foreach (['vault_engine.php', 'email_template.php', 'vault_icon_cache.php', 'VaultKdfPolicy.php'] as $name) {
        $path = $dir . '/' . $name;
        if (is_file($path) && !@unlink($path)) return false;
    }

    $remaining = array_values(array_diff(@scandir($dir) ?: [], ['.', '..']));
    return $remaining === [] ? @rmdir($dir) : false;
}

$directory = first_run_data_dir();
$baseUrl = first_run_base_url();
$error = '';
first_run_log('FIRST_RUN_PAGE_LOADED', ['data_dir_configured' => $directory !== '', 'base_url_detected' => $baseUrl !== '']);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['complete_first_run'])) {
    sentryiq_require_csrf();
    $username = trim((string)($_POST['setup_username'] ?? ''));
    $email = trim((string)($_POST['setup_email'] ?? ''));
    $password = (string)($_POST['setup_password'] ?? '');
    $confirm = (string)($_POST['setup_password_confirm'] ?? '');

    $sourcePrivateDir = dirname(__DIR__, 2) . '/private_data';
    if ($directory === '') $error = 'SentryIQ secure storage is not configured by the hosting environment.';
    elseif (!preg_match('/^[A-Za-z0-9._-]{2,64}$/', $username)) $error = 'Please enter a valid administrator username.';
    elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) $error = 'Please enter a valid 2FA email address.';
    elseif ($baseUrl === '') $error = 'SentryIQ could not determine its HTTPS application URL.';
    elseif (!first_run_prepare_dir($directory)) $error = 'SentryIQ could not prepare secure storage.';
    elseif (strlen($password) < 12) $error = 'The master vault password must be at least 12 characters long.';
    elseif ($password !== $confirm) $error = 'The master vault passwords do not match.';
    elseif (!is_file($sourcePrivateDir . '/vault_engine.php') || !is_file($sourcePrivateDir . '/email_template.php') || !is_file($sourcePrivateDir . '/vault_icon_cache.php') || !is_file($sourcePrivateDir . '/VaultKdfPolicy.php')) $error = 'SentryIQ installation files are incomplete.';
    else {
        $engineTarget = $directory . '/vault_engine.php';
        $templateTarget = $directory . '/email_template.php';
        $iconCacheTarget = $directory . '/vault_icon_cache.php';
        $kdfPolicyTarget = $directory . '/VaultKdfPolicy.php';
        $secureConfig = $directory . '/sentryiq_config.php';
        $pointerConfig = "<?php\nreturn [\n    'data_dir' => " . var_export($directory, true) . ",\n    'base_url' => " . var_export($baseUrl, true) . ",\n];\n";
        try {
            @unlink($engineTarget); @unlink($templateTarget); @unlink($iconCacheTarget); @unlink($kdfPolicyTarget);
            if (!@copy($sourcePrivateDir . '/vault_engine.php', $engineTarget)) throw new RuntimeException('runtime_copy_failed');
            if (!@copy($sourcePrivateDir . '/email_template.php', $templateTarget)) throw new RuntimeException('template_copy_failed');
            if (!@copy($sourcePrivateDir . '/vault_icon_cache.php', $iconCacheTarget)) throw new RuntimeException('icon_cache_copy_failed');
            if (!@copy($sourcePrivateDir . '/VaultKdfPolicy.php', $kdfPolicyTarget)) throw new RuntimeException('kdf_policy_copy_failed');
            @chmod($engineTarget, 0600); @chmod($templateTarget, 0600); @chmod($iconCacheTarget, 0600); @chmod($kdfPolicyTarget, 0600);
            if (!first_run_write_config($secureConfig, $username, $email, $baseUrl, $directory)) throw new RuntimeException('secure_config_failed');

            clearstatcache(true, $engineTarget);
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($engineTarget, true);
                first_run_log('RUNTIME_OPCACHE_INVALIDATED', ['available' => true]);
            } else {
                first_run_log('RUNTIME_OPCACHE_INVALIDATE_UNAVAILABLE', ['available' => false]);
            }

            require_once $engineTarget;
            require_once $iconCacheTarget;
            first_run_initialize($password, $directory . '/passwords.enc');
            first_run_direct_crypto_verify($password, $directory . '/passwords.enc');
            $verified = vault_unlock($password);
            if ($verified === false) throw new RuntimeException('vault_verification_failed');
            first_run_log('VAULT_RUNTIME_VERIFY_COMPLETED');
            if (@file_put_contents($pointerConfigFile, $pointerConfig, LOCK_EX) === false || !@chmod($pointerConfigFile, 0600)) throw new RuntimeException('pointer_config_failed');
            first_run_log('POINTER_CONFIG_WRITTEN', [
                'exists' => is_file($pointerConfigFile),
                'permissions' => is_file($pointerConfigFile) ? decoct((int)(fileperms($pointerConfigFile) & 0x01ff)) : null,
            ]);
            $pointerConfigLoaded = false;
            if (is_file($pointerConfigFile) && !is_link($pointerConfigFile) && is_readable($pointerConfigFile)) {
                try {
                    $pointerLoaded = require $pointerConfigFile;
                    $pointerConfigLoaded = is_array($pointerLoaded)
                        && rtrim((string)($pointerLoaded['data_dir'] ?? ''), '/') === rtrim($directory, '/')
                        && trim((string)($pointerLoaded['base_url'] ?? '')) === trim($baseUrl);
                } catch (Throwable) {
                    $pointerConfigLoaded = false;
                }
            }
            first_run_log('POINTER_CONFIG_VERIFIED', ['verified' => $pointerConfigLoaded]);
            if (!$pointerConfigLoaded) throw new RuntimeException('pointer_config_verification_failed');
            if (!first_run_cleanup()) throw new RuntimeException('first_run_cleanup_failed');
            first_run_log('INSTALL_SUCCESS');
            @unlink($directory . '/install_debug.log');
            unset($_SESSION['csrf_token']);
            header('Location: index.php?setup=complete');
            exit;
        } catch (Throwable $exception) {
            first_run_log('INSTALL_FAILED', ['exception_class' => $exception::class, 'failure' => $exception->getMessage(), 'line' => $exception->getLine()]);
            @unlink($secureConfig);
            $error = 'SentryIQ could not initialize the encrypted vault. [' . $exception->getMessage() . ']';
        }
    }
}

$csrf = sentryiq_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentryIQ First-Run Setup</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
</head>
<body>
<div class="box">
    <h2>🛡️ SentryIQ Secure Setup</h2>
    <?php if ($error !== ''): ?><p class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></p><?php endif; ?>
    <form method="POST" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
        <div class="form-group"><label>Administrator Username:</label><input type="text" name="setup_username" class="input-field" required></div>
        <div class="form-group"><label>2FA Email Address:</label><input type="email" name="setup_email" class="input-field" required></div>
        <div class="form-group"><label>Master Vault Password:</label><input type="password" name="setup_password" class="input-field" autocomplete="new-password" minlength="12" required></div>
        <div class="form-group"><label>Confirm Master Vault Password:</label><input type="password" name="setup_password_confirm" class="input-field" autocomplete="new-password" minlength="12" required></div>
        <p class="first-run-note">SentryIQ securely stores its encrypted vault outside the public web root.</p>
        <button type="submit" name="complete_first_run" class="btn btn-primary">Complete Secure Installation</button>
    </form>
</div>
</body>
</html>
