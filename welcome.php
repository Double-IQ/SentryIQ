<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$username = trim((string)($_SESSION['app_username'] ?? ''));
if ($username === '') {
    $username = 'there';
}

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
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<meta name="description" content="SentryIQ secure vault welcome screen.">
<title>SentryIQ — Welcome Back</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<style>
html,body{min-height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;box-sizing:border-box}
.sentryiq-welcome{width:min(620px,calc(100% - 40px));text-align:center;padding:30px 24px;box-sizing:border-box}
.sentryiq-welcome-logo{display:block;width:min(320px,82%);height:auto;margin:0 auto 34px}
.sentryiq-welcome-message{opacity:0;transform:translateY(10px);animation:sentryiqWelcomeIn .65s ease-out forwards}
.sentryiq-welcome-name{margin:0;font-size:clamp(28px,5vw,42px);line-height:1.15;color:var(--neo-text,#253041);font-weight:700}
.sentryiq-welcome-subtitle{margin:12px 0 0;font-size:clamp(18px,3vw,24px);line-height:1.3;color:var(--neo-muted,#697586);font-weight:600}
@keyframes sentryiqWelcomeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.sentryiq-welcome.fade-out .sentryiq-welcome-message{animation:sentryiqWelcomeOut .7s ease-in forwards}
.sentryiq-welcome.fade-out .sentryiq-welcome-logo{animation:sentryiqWelcomeLogoOut .7s ease-in forwards}
@keyframes sentryiqWelcomeOut{from{opacity:1;transform:translateY(0)}to{opacity:0;transform:translateY(-8px)}}
@keyframes sentryiqWelcomeLogoOut{from{opacity:1}to{opacity:0}}
@media(prefers-reduced-motion:reduce){
 .sentryiq-welcome-message{opacity:1;transform:none;animation:none!important}
 .sentryiq-welcome.fade-out .sentryiq-welcome-message,.sentryiq-welcome.fade-out .sentryiq-welcome-logo{animation:none!important}
}
</style>
</head>
<body>
<main id="welcome" class="sentryiq-welcome" aria-live="polite">
    <img class="sentryiq-welcome-logo" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
    <div class="sentryiq-welcome-message">
        <h1 class="sentryiq-welcome-name">Hi, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></h1>
        <p class="sentryiq-welcome-subtitle">Welcome Back!</p>
    </div>
</main>
<script src="assets/js/welcome.js" defer></script>
</body>
</html>
