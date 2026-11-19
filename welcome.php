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
<link rel="stylesheet" href="assets/css/welcome.css">
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
