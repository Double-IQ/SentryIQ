<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();

if (isset($_SESSION['master_key']) && is_string($_SESSION['master_key']) && strlen($_SESSION['master_key']) === 32) {
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?php echo htmlspecialchars(sentryiq_csrf_token(), ENT_QUOTES, 'UTF-8'); ?>">
<title>SentryIQ — Passkey</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
</head>
<body>
<div class="box">
    <img class="sentryiq-brand-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ" fetchpriority="high">
    <div style="max-width:460px;margin:20px auto;text-align:center;">
        <h2>🔐 Unlock SentryIQ</h2>
        <p>Use your passkey to unlock your secure vault.</p>
        <button type="button" id="passkey-login" class="btn btn-primary" style="width:100%;margin-top:12px;">Use Passkey / Face ID</button>
        <p id="passkey-status" class="error" style="display:none;"></p>
        <p style="margin-top:20px;font-size:13px;"><a href="index.php?password=1">Use the recovery login instead</a></p>
    </div>
</div>
<script src="assets/js/passkey_login.js" defer></script>
</body>
</html>
