<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$dataDir = sentryiq_data_dir();
$store = [];
if ($dataDir !== '') {
    $path = $dataDir . '/passkeys.json';
    if (is_file($path) && !is_link($path)) {
        $raw = @file_get_contents($path);
        $decoded = is_string($raw) ? json_decode($raw, true) : null;
        if (is_array($decoded)) $store = $decoded;
    }
}
$credentials = is_array($store['credentials'] ?? null) ? $store['credentials'] : [];
$csrf = sentryiq_csrf_token();
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
<meta property="og:title" content="SentryIQ — Passkeys">
<meta property="og:description" content="SentryIQ passkey management.">
<meta property="og:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ — Passkeys">
<meta name="twitter:description" content="SentryIQ passkey management.">
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<title>SentryIQ — Passkeys</title>
<link rel="stylesheet" href="assets/css/sentryiq.css?v=20260922-3">
<link rel="stylesheet" href="assets/css/passkeys.css">
</head>
<body>
<div class="box">
    <div class="sentryiq-page-header">
        <div class="sentryiq-vault-brand-wrap"><img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ"><span class="sentryiq-vault-status">Passkeys</span></div>
        <div class="sentryiq-mobile-header-actions">
            <form method="POST" class="sentryiq-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button></form>
            <div class="vault-mobile-menu-bar"><button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu"><span class="vault-mobile-menu-icon" aria-hidden="true">☰</span><span id="vault-mobile-menu-label">Menu</span></button></div>
        </div>
    </div>
    <div id="vault-mobile-menu" class="vault-tabs">
        <button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="documents.php">📄 Docs</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button>
        <button class="tab-btn active" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button>
        <form method="POST" class="vault-menu-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button></form>
    </div>
    <div class="passkeys-back"><a href="index.php?pane=settings" class="btn">← System Settings</a></div>
    <div class="passkeys-content">
        <div class="passkeys-heading"><div><h2>🔑 Passkeys</h2><p>Manage the devices that can unlock your SentryIQ vault with Face ID, Touch ID, or passkey authentication.</p></div></div>
        <div id="passkey-message" style="display:none;"></div>
        <div class="passkey-list">
            <?php if (empty($credentials)): ?><div class="passkey-empty">No passkeys are registered yet.</div>
            <?php else: ?><?php foreach ($credentials as $index => $credential): $created=(int)($credential['created_at']??0);$label='Passkey '.($index+1);$id=(string)($credential['credential_id']??''); ?><div class="passkey-row"><div class="passkey-identity"><strong><?php echo htmlspecialchars($label,ENT_QUOTES,'UTF-8'); ?></strong><div class="passkey-added">Added <?php echo $created>0?htmlspecialchars(date('j M Y, H:i',$created),ENT_QUOTES,'UTF-8'):'date unavailable'; ?></div><div class="passkey-credential">Credential: <?php echo htmlspecialchars(substr($id,0,18).(strlen($id)>18?'…':''),ENT_QUOTES,'UTF-8'); ?></div></div><button type="button" class="btn btn-primary remove-passkey" data-credential="<?php echo htmlspecialchars($id,ENT_QUOTES,'UTF-8'); ?>" <?php echo count($credentials)<=1?'disabled title="Keep at least one passkey registered"':''; ?>>Remove</button></div><?php endforeach; ?><?php endif; ?>
        </div>
        <div class="passkey-add-box"><h3>Add another device</h3><p>Register another passkey on your phone, Mac, tablet, or another trusted device. Each passkey gets its own protected copy of your existing vault key.</p><a href="passkey_setup.php?add=1" class="btn btn-primary">＋ Add Another Passkey</a></div>
        <p class="passkey-note">SentryIQ will not let you remove the last registered passkey. If you lose access to a device, use the password recovery route to regain access and register a replacement passkey.</p>
    </div>
</div>
<script src="assets/js/sentryiq_navigation.js" defer></script>
<script src="assets/js/passkeys.js" defer></script>
</body>
</html>
