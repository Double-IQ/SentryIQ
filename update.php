<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$configFile = __DIR__ . '/sentryiq_config.php';
$config = is_file($configFile) ? require $configFile : [];
$dataDir = is_array($config) ? rtrim((string)($config['data_dir'] ?? ''), '/') : '';
if ($dataDir === '' || !str_starts_with($dataDir, '/') || !is_dir($dataDir) || is_link($dataDir)) {
    http_response_code(503);
    exit('SentryIQ secure runtime is unavailable.');
}

require_once __DIR__ . '/app/Updates/UpdateManager.php';

$manager = new SentryIQ\Updates\UpdateManager(__DIR__, $dataDir);
$current = $manager->currentVersion();
$csrf = sentryiq_csrf_token();
$error = '';
$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['check_updates'])) {
    sentryiq_require_csrf();
    try {
        $result = $manager->checkLatest(true);
    } catch (Throwable $exception) {
        $error = $exception->getMessage();
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentryIQ — System Updates</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<script src="assets/js/sentryiq_navigation.js" defer></script>
<link rel="stylesheet" href="assets/css/update.css">
</head>
<body>
<div class="box">
    <div class="sentryiq-page-header">
        <div class="sentryiq-vault-brand-wrap">
            <img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
            <span class="sentryiq-vault-status">System Updates</span>
        </div>
    </div>
    <div class="update-card">
        <h2>🔄 SentryIQ Updates</h2>
        <p class="update-meta">Installed version: <strong><?php echo htmlspecialchars($current, ENT_QUOTES, 'UTF-8'); ?></strong></p>
        <?php if ($error !== ''): ?>
            <div class="error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php elseif (is_array($result)): ?>
            <?php if (empty($result['release_available']) && !empty($result['message'])): ?>
                <div class="update-warning"><?php echo htmlspecialchars((string)$result['message'], ENT_QUOTES, 'UTF-8'); ?></div>
                <p class="update-meta">Installed version: <strong><?php echo htmlspecialchars($current, ENT_QUOTES, 'UTF-8'); ?></strong></p>
            <?php elseif (!empty($result['update_available'])): ?>
                <div class="update-warning"><strong>Update available:</strong> SentryIQ <?php echo htmlspecialchars((string)$result['latest_version'], ENT_QUOTES, 'UTF-8'); ?></div>
                <p class="update-meta"><?php echo htmlspecialchars((string)$result['name'], ENT_QUOTES, 'UTF-8'); ?> · <?php echo htmlspecialchars((string)$result['published_at'], ENT_QUOTES, 'UTF-8'); ?></p>
                <?php if ((string)($result['body'] ?? '') !== ''): ?><div class="update-notes"><?php echo htmlspecialchars((string)$result['body'], ENT_QUOTES, 'UTF-8'); ?></div><?php endif; ?>
                <form method="POST" action="update_apply.php" class="update-confirm-form" data-confirm-submit="Install this SentryIQ update now? The vault will be locked after the update and you will need to unlock it again.">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                    <button class="btn btn-primary" type="submit">Install Update</button>
                </form>
            <?php else: ?>
                <div class="update-success">SentryIQ is up to date.</div>
                <?php if (!empty($result['published_at'])): ?><p class="update-meta">Latest release: <?php echo htmlspecialchars((string)$result['latest_version'], ENT_QUOTES, 'UTF-8'); ?> · <?php echo htmlspecialchars((string)$result['published_at'], ENT_QUOTES, 'UTF-8'); ?></p><?php endif; ?>
            <?php endif; ?>
        <?php else: ?>
            <p>Check GitHub for the latest stable SentryIQ release.</p>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                <button class="btn btn-primary" type="submit" name="check_updates">Check for Updates</button>
            </form>
        <?php endif; ?>
        <p class="update-back-link"><a href="index.php?pane=settings">← System Settings</a></p>
    </div>
</div>
</body>
</html>
