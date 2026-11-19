<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();

define('SENTRYIQ_CONFIG_FILE', __DIR__ . '/sentryiq_config.php');

if (!is_file(SENTRYIQ_CONFIG_FILE)) {
    if (is_file(__DIR__ . '/first_run.php')) { require __DIR__ . '/first_run.php'; exit; }
    http_response_code(503); exit('SentryIQ installation is unavailable.');
}
$config = require SENTRYIQ_CONFIG_FILE;
if (!is_array($config)) { http_response_code(503); exit('SentryIQ configuration is unavailable.'); }
$dataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
if ($dataDir === '' || !str_starts_with($dataDir, '/') || !is_dir($dataDir) || !is_file($dataDir . '/vault_engine.php') || !is_file($dataDir . '/email_template.php')) { http_response_code(503); exit('SentryIQ secure runtime is unavailable.'); }
require_once $dataDir . '/vault_engine.php';
require_once $dataDir . '/email_template.php';
require_once __DIR__ . '/auth_flow.php';
date_default_timezone_set('Africa/Johannesburg');
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['lock_vault'])) { sentryiq_require_csrf(); log_security_event('VAULT_LOCKED', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown'); sentryiq_lock_vault(); header('Location: index.php'); exit; }
$vault_authenticated = isset($_SESSION['master_key']) && is_string($_SESSION['master_key']) && strlen($_SESSION['master_key']) === 32;
$passwords = [];
$vault_error = false;
if ($vault_authenticated) { $passwords = load_passwords(); if ($passwords === false) { log_security_event('VAULT_READ_FAILURE', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown'); sentryiq_lock_vault(); $vault_authenticated = false; $vault_error = true; } }
$systemConfig = [];
foreach (is_array($passwords) ? $passwords : [] as $entry) { if (($entry['type'] ?? '') === 'system_config') { $systemConfig = $entry; break; } }
$sys_user = trim((string)($systemConfig['app_username'] ?? $_SESSION['app_username'] ?? ''));
$sys_email = trim((string)($systemConfig['2fa_email'] ?? TWO_FA_EMAIL));
$active_pane = (string)($_GET['pane'] ?? 'view');
if (!in_array($active_pane, ['view','records','add','settings','details','edit'], true)) $active_pane = 'view';
$csrf = sentryiq_csrf_token();

$show_login_splash = !$vault_authenticated
    && $vault_error === false
    && (($_GET['recovery'] ?? '') !== '1')
    && !isset($_SESSION['pending_key']);

if (($_GET['setup'] ?? '') === 'complete' && isset($_SESSION['first_run_recovery_key']) && is_string($_SESSION['first_run_recovery_key'])) {
    if (isset($_GET['recovery_seen']) && $_GET['recovery_seen'] === '1') {
        unset($_SESSION['first_run_recovery_key']);
        header('Location: index.php');
        exit;
    }
    $recoveryKey = $_SESSION['first_run_recovery_key'];
    $recoveryDisplay = trim(chunk_split($recoveryKey, 4, ' '));
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentryIQ — Recovery Key</title>
    <link rel="stylesheet" href="assets/css/sentryiq.css">
    </head>
    <body>
    <div class="box recovery-key-page">
        <h2>🔐 Your SentryIQ Recovery Key</h2>
        <p><strong>Save this key before continuing.</strong> It is generated once for this fresh vault and is designed to recover access to the same Vault Master Key.</p>
        <div class="recovery-key-display"><?php echo htmlspecialchars($recoveryDisplay, ENT_QUOTES, 'UTF-8'); ?></div>
        <p class="recovery-key-note">Store it offline or in a trusted password manager. Do not send it by email or store it in the SentryIQ vault itself.</p>
        <p class="recovery-key-warning"><strong>Important:</strong> SentryIQ will not be able to recreate this exact recovery key if you lose it.</p>
        <a href="index.php?recovery_seen=1" class="btn btn-primary recovery-key-continue">I Have Saved My Recovery Key → Continue</a>
    </div>
    </body>
    </html>
    <?php
    exit;
}
$ogImageUrl = rtrim((string)($config['base_url'] ?? ''), '/') . '/sentryiq-og.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" sizes="32x32" href="sentryiq-icon.php?size=32">
<link rel="icon" type="image/png" sizes="16x16" href="sentryiq-icon.php?size=16">
<link rel="apple-touch-icon" sizes="180x180" href="sentryiq-icon.php?size=180">
<meta property="og:site_name" content="SentryIQ">
<meta property="og:type" content="website">
<meta property="og:title" content="SentryIQ">
<meta property="og:description" content="SentryIQ — private personal information and content platform.">
<meta property="og:image" content="<?php echo htmlspecialchars($ogImageUrl, ENT_QUOTES, 'UTF-8'); ?>">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ">
<meta name="twitter:description" content="SentryIQ — private personal information and content platform.">
<meta name="twitter:image" content="<?php echo htmlspecialchars($ogImageUrl, ENT_QUOTES, 'UTF-8'); ?>">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<meta name="description" content="SentryIQ secure password vault and credential management.">
<title>SentryIQ</title><link rel="stylesheet" href="assets/css/sentryiq.css?v=20260922-2">
<link rel="stylesheet" href="assets/css/vault_page.css">
<script src="assets/js/vault_folders.js?v=20260919-7"></script>
<script src="assets/js/vault_page.js" defer></script>
</head>
<body data-active-pane="<?php echo htmlspecialchars($active_pane, ENT_QUOTES, 'UTF-8'); ?>"<?php echo $show_login_splash ? ' class="sentryiq-login-splash-active"' : ''; ?>>
<?php if ($show_login_splash): ?>
<div class="sentryiq-login-splash" aria-hidden="true">
    <img src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
</div>
<?php endif; ?>
<div class="box">
<?php if (!$vault_authenticated): ?>
<img class="sentryiq-brand-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ" fetchpriority="high">
<?php if ($vault_error): ?><p class="error">The secure vault could not be opened. No changes have been made.</p>
<?php elseif (($_GET['recovery'] ?? '') === '1'): ?>
<h2>🛟 Recover SentryIQ Vault</h2>
<p>Enter the 64-character recovery key that was generated when this vault was created.</p>
<?php if ($recovery_failed): ?><p class="error">The recovery key could not unlock this vault.</p><?php endif; ?>
<form method="POST" autocomplete="off">
<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<div class="form-group"><label>Recovery Key:</label><input type="text" name="recovery_key" class="input-field" autocomplete="off" autocapitalize="characters" spellcheck="false" required autofocus></div>
<button type="submit" name="recovery_login" class="btn btn-primary">Recover Vault</button>
</form>
<p class="vault-login-secondary-link"><a href="index.php">← Back to Password Login</a></p>
<?php elseif (!isset($_SESSION['pending_key'])): ?>
<?php if ($decryption_failed): ?><p class="error">Unable to verify the master vault password.</p><?php endif; ?><form method="POST" autocomplete="off"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><div class="form-group"><label>Master Vault Password:</label><input type="password" name="master_password" class="input-field" autocomplete="current-password" required autofocus></div><button type="submit" name="login_step_1" class="btn btn-primary">Unlock</button></form>
<p class="vault-login-secondary-link"><a href="index.php?recovery=1">🛟 Use Recovery Key</a></p>
<?php else: ?><h2>🔐 Verification</h2><p>A temporary verification code has been sent to the configured 2FA email address.</p><?php if ($error_step_2 !== ''): ?><p class="error"><?php echo htmlspecialchars($error_step_2, ENT_QUOTES, 'UTF-8'); ?></p><?php endif; ?><form method="POST" autocomplete="off"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><div class="form-group"><label>Enter 6-Digit Code:</label><input type="text" name="verification_code" maxlength="6" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" class="input-field" required autofocus></div><button type="submit" name="login_step_2" class="btn btn-primary">Verify &amp; Unlock</button></form><?php endif; ?>
<?php else: ?>
<?php require_once __DIR__ . '/app/Vault/DashboardList.php'; ?>
<?php require_once __DIR__ . '/app/Vault/DashboardActions.php'; ?>
<?php endif; ?>
</div>
<footer class="vault-credits-footer">
    <a class="vault-credits-link" href="credits.php">Credits &amp; acknowledgements</a>
</footer>
<script src="assets/js/vault_page_init.js" defer></script>
</body></html>
