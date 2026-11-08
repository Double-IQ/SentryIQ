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
    <div class="box" style="max-width:720px;margin:40px auto;">
        <h2>🔐 Your SentryIQ Recovery Key</h2>
        <p><strong>Save this key before continuing.</strong> It is generated once for this fresh vault and is designed to recover access to the same Vault Master Key.</p>
        <div style="padding:20px;margin:20px 0;background:#f8f9fa;border:1px solid #dee2e6;border-radius:10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:18px;line-height:1.8;word-break:break-word;text-align:center;"><?php echo htmlspecialchars($recoveryDisplay, ENT_QUOTES, 'UTF-8'); ?></div>
        <p style="font-size:13px;color:#666;">Store it offline or in a trusted password manager. Do not send it by email or store it in the SentryIQ vault itself.</p>
        <p style="font-size:13px;color:#b02a37;"><strong>Important:</strong> SentryIQ will not be able to recreate this exact recovery key if you lose it.</p>
        <a href="index.php?recovery_seen=1" class="btn btn-primary" style="display:block;text-align:center;text-decoration:none;margin-top:20px;">I Have Saved My Recovery Key → Continue</a>
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
<style>
.sentryiq-login-splash{position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:var(--neo-bg,#f4f6f9);opacity:1;visibility:visible;transition:opacity .45s ease,visibility .45s ease}
.sentryiq-login-splash img{display:block;width:min(520px,82vw);height:auto}
body.sentryiq-login-ready .sentryiq-login-splash{opacity:0;visibility:hidden;pointer-events:none}
body.sentryiq-login-splash-active > .box{opacity:0;pointer-events:none}
body.sentryiq-login-ready > .box{opacity:1;transition:opacity .45s ease}
@media(prefers-reduced-motion:reduce){
 .sentryiq-login-splash{transition:none}
 body.sentryiq-login-ready > .box{transition:none}
}
#records-panel > div:first-child {
    margin: 2em 0 16px !important;
}
#records-panel > div:first-child h3 {
    order: 0 !important;
    flex: 1 1 auto !important;
    flex-basis: auto !important;
    margin: 0 !important;
    min-width: 0;
}
@media (max-width: 700px) {
    #records-panel > div:first-child {
        display: flex !important;
        flex-wrap: wrap !important;
        align-items: center !important;
        justify-content: flex-start !important;
        gap: 10px !important;
    }
    #records-panel > div:first-child > a:first-child {
        flex: 0 0 100% !important;
        width: 100% !important;
    }
    #records-panel > div:first-child > h3 {
        flex: 1 1 auto !important;
        order: 0 !important;
        flex-basis: auto !important;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    #records-panel > div:first-child > .vault-category-header-options {
        margin-left: auto !important;
    }
    #records-panel > div:first-child > button[onclick="showCreateFolderForm()"],
    #records-panel > div:first-child > .vault-add-record-button {
        display: none !important;
    }
    #records-panel > div:first-child > .vault-category-header-options {
        display: flex !important;
        position: relative !important;
        top: auto !important;
        right: auto !important;
        margin-left: auto !important;
        flex: 0 0 auto !important;
    }
    #records-panel > div:first-child > .vault-category-header-options .vault-category-options-button {
        display: inline-flex !important;
    }
}
.vault-category-grid{margin-top:8px !important;}
@media (max-width:700px){
    #view-panel{padding-top:0 !important;}
    .vault-category-grid{margin-top:0 !important;padding-top:24px !important;}
}
#view-panel a[href="index.php?pane=records"] {
    display:flex !important;
    align-items:center !important;
    justify-content:center !important;
    min-height:58px !important;
    width:100% !important;
    box-sizing:border-box !important;
    text-align:center !important;
    text-decoration:none !important;
}
</style>
<script src="assets/js/vault_folders.js?v=20260919-7"></script>
<script>
const vaultTabLabels={view:'Vault',records:'Records',add:'Add Entry',settings:'System',details:'Entry Inspection'};
function updateVaultSectionStatus(tabName){var status=document.querySelector('[data-vault-status]');if(status)status.textContent=vaultTabLabels[tabName]||'SentryIQ';}
function switchVaultTab(tabName){document.querySelectorAll('.vault-panel').forEach(panel=>panel.classList.remove('active'));document.querySelectorAll('.tab-btn').forEach(btn=>btn.classList.remove('active'));var targetPanel=document.getElementById(tabName+'-panel');if(targetPanel)targetPanel.classList.add('active');var btnElement=document.getElementById(tabName+'-btn');if(btnElement)btnElement.classList.add('active');if(tabName==='records'){var vaultBtn=document.getElementById('view-btn');if(vaultBtn)vaultBtn.classList.add('active');}var title=targetPanel&&targetPanel.getAttribute('data-vault-title');updateVaultSectionStatus(title||tabName);}
function toggleVaultMobileMenu(){var menu=document.getElementById('vault-mobile-menu');var toggle=document.querySelector('.vault-mobile-menu-toggle');if(!menu||!toggle)return;var isOpen=menu.classList.toggle('mobile-open');toggle.setAttribute('aria-expanded',isOpen?'true':'false');}
function parseVaultCsv(value){var fields=[],field='',quoted=false;for(var i=0;i<value.length;i++){var ch=value[i];if(ch==='"'){if(quoted&&value[i+1]==='"'){field+='"';i++;}else{quoted=!quoted;}}else if(ch===','&&!quoted){fields.push(field);field='';}else{field+=ch;}}fields.push(field);return fields;}
function viewRecordDetails(label,username,password,url,notes,id,category){if(Array.isArray(label)){var args=label;label=args[0]||'';username=args[1]||'';password=args[2]||'';url=args[3]||'';notes=args[4]||'';id=args[5]||'';category=args[6]||'';}if(!username&&!password&&!url&&!notes&&typeof label==='string'){var packed=parseVaultCsv(label);if(packed.length>=5&&packed.length<=7){label=packed[0]||'';username=packed[1]||'';password=packed[2]||'';url=packed[3]||'';notes=packed[4]||'';if(!id&&packed[5])id=packed[5];if(!category&&packed[6])category=packed[6];}}document.getElementById('det-label').textContent=label;var detailCategory=document.getElementById('det-category');if(detailCategory){detailCategory.textContent=category||'Uncategorized';}document.getElementById('det-username').textContent=username?username:'[None Stored]';document.getElementById('det-password').textContent=password;document.getElementById('det-notes').textContent=notes?notes:'[No Notes]';var urlLink=document.getElementById('det-url');try{var parsed=url?new URL(url,window.location.origin):null;if(parsed&&parsed.protocol==='https:'){urlLink.href=parsed.href;urlLink.textContent=parsed.href;urlLink.style.display='inline';urlLink.rel='noopener noreferrer';}else{throw new Error('Unsafe URL');}}catch(e){urlLink.textContent=url?'[Unsafe URL Blocked]':'[None Stored]';urlLink.removeAttribute('href');urlLink.style.display='inline';}var icon=document.getElementById('det-icon');if(id){icon.src='vault-icon.php?id='+encodeURIComponent(id);icon.style.display='block';icon.onerror=function(){this.style.display='none';};}else{icon.removeAttribute('src');icon.style.display='none';}document.getElementById('det-delete-id').value=id;switchVaultTab('details');}
</script>
</head>
<body<?php echo $show_login_splash ? ' class="sentryiq-login-splash-active"' : ''; ?>>
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
<p style="margin-top:15px;text-align:center;"><a href="index.php">← Back to Password Login</a></p>
<?php elseif (!isset($_SESSION['pending_key'])): ?>
<?php if ($decryption_failed): ?><p class="error">Unable to verify the master vault password.</p><?php endif; ?><form method="POST" autocomplete="off"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><div class="form-group"><label>Master Vault Password:</label><input type="password" name="master_password" class="input-field" autocomplete="current-password" required autofocus></div><button type="submit" name="login_step_1" class="btn btn-primary">Unlock</button></form>
<p style="margin-top:15px;text-align:center;"><a href="index.php?recovery=1">🛟 Use Recovery Key</a></p>
<?php else: ?><h2>🔐 Verification</h2><p>A temporary verification code has been sent to the configured 2FA email address.</p><?php if ($error_step_2 !== ''): ?><p class="error"><?php echo htmlspecialchars($error_step_2, ENT_QUOTES, 'UTF-8'); ?></p><?php endif; ?><form method="POST" autocomplete="off"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><div class="form-group"><label>Enter 6-Digit Code:</label><input type="text" name="verification_code" maxlength="6" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" class="input-field" required autofocus></div><button type="submit" name="login_step_2" class="btn btn-primary">Verify &amp; Unlock</button></form><?php endif; ?>
<?php else: ?>
<?php require_once __DIR__ . '/app/Vault/DashboardList.php'; ?>
<?php require_once __DIR__ . '/app/Vault/DashboardActions.php'; ?>
<?php endif; ?>
</div>
<footer style="max-width:820px;margin:0 auto 24px;padding:12px 18px;text-align:center;font-size:13px;color:var(--text-muted,#667085);">
    <a href="credits.php" style="color:inherit;text-decoration:underline;text-underline-offset:3px;">Credits &amp; acknowledgements</a>
</footer>
<script>
<?php if ($show_login_splash): ?>
(function(){
    var start=function(){
        window.setTimeout(function(){
            document.body.classList.remove('sentryiq-login-splash-active');
            document.body.classList.add('sentryiq-login-ready');
        },2000);
    };
    if(document.readyState === 'loading') document.addEventListener('DOMContentLoaded',start,{once:true});
    else start();
}());
<?php endif; ?>
document.addEventListener('DOMContentLoaded',function(){var csrf=document.querySelector('meta[name="csrf-token"]');var token=csrf?csrf.content:'';document.querySelectorAll('form[method="POST"]').forEach(function(form){if(!form.querySelector('input[name="csrf_token"]')&&token){var input=document.createElement('input');input.type='hidden';input.name='csrf_token';input.value=token;form.appendChild(input);}if(form.querySelector('button[name="add_entry"]')){form.action='vault_actions.php';var action=document.createElement('input');action.type='hidden';action.name='action';action.value='add';form.appendChild(action);}if(form.querySelector('button[name="save_vault_settings"]')){form.action='vault_actions.php';var action2=document.createElement('input');action2.type='hidden';action2.name='action';action2.value='save_settings';form.appendChild(action2);}if(form.querySelector('button[name="edit_entry"]')){form.action='vault_actions.php';var action3=document.createElement('input');action3.type='hidden';action3.name='action';action3.value='edit';form.appendChild(action3);}if(form.querySelector('button[name="delete_entry"]')){form.action='vault_actions.php';var action4=document.createElement('input');action4.type='hidden';action4.name='action';action4.value='delete';form.appendChild(action4);}});document.querySelectorAll('a[target="_blank"]').forEach(function(a){a.rel='noopener noreferrer';});var lock=document.querySelector('a[href="?action=logout"]');if(lock){var form=document.createElement('form');form.method='POST';form.style.display='inline';var tokenInput=document.createElement('input');tokenInput.type='hidden';tokenInput.name='csrf_token';tokenInput.value=token;var actionInput=document.createElement('input');actionInput.type='hidden';actionInput.name='lock_vault';actionInput.value='1';var button=document.createElement('button');button.type='submit';button.className=lock.className;button.style.cssText=lock.getAttribute('style')||'';button.textContent=lock.textContent;form.appendChild(tokenInput);form.appendChild(actionInput);form.appendChild(button);lock.replaceWith(form);}switchVaultTab('<?php echo htmlspecialchars($active_pane, ENT_QUOTES, 'UTF-8'); ?>');});
</script>
</body></html>
