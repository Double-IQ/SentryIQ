<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?php echo htmlspecialchars(sentryiq_csrf_token(), ENT_QUOTES, 'UTF-8'); ?>">
<title>SentryIQ — Set Up Passkey</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
</head>
<body>
<div class="box">
    <img class="sentryiq-brand-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ" fetchpriority="high">
    <div class="passkey-page passkey-setup-page">
        <h2>🔑 Set Up Your Passkey</h2>
        <p>Your vault is ready. Set up a passkey so future unlocks can use Face ID, Touch ID, or your device's passkey authentication instead of email codes.</p>
        <button type="button" id="passkey-register" class="btn btn-primary passkey-action-button">Set Up Passkey</button>
        <p id="passkey-status" class="error passkey-status"></p>
        <p class="passkey-setup-note">The first setup requires the current authenticated vault session. Once registered, the passkey becomes the normal unlock method.</p>
    </div>
</div>
<script src="assets/js/passkey_setup.js" defer></script>
</body>
</html>