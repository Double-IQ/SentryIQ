<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$dataDir = sentryiq_data_dir();
if ($dataDir === '' || !is_file($dataDir . '/vault_engine.php') || is_link($dataDir . '/vault_engine.php')) {
    http_response_code(503);
    exit('SentryIQ security log storage is unavailable.');
}

require_once $dataDir . '/vault_engine.php';

$events = read_security_log();
$csrf = sentryiq_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<title>SentryIQ — System Log</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<link rel="stylesheet" href="assets/css/security_log.css">
</head>
<body>
<div class="box">
    <img class="sentryiq-brand-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ" fetchpriority="high">
    <div class="security-log-page">
        <div class="security-log-header">
            <div>
                <h2 class="security-log-title">🔐 System Log</h2>
                <p class="security-log-description">Security and authentication events recorded by SentryIQ.</p>
            </div>
            <a href="index.php" class="btn security-log-back">Back to Vault</a>
        </div>

        <?php if (empty($events)): ?>
            <div class="form-box security-log-empty">No security events have been recorded yet.</div>
        <?php else: ?>
            <div class="security-log-table">
                <table class="security-log-events">
                    <thead>
                        <tr class="security-log-head-row">
                            <th class="security-log-heading">Date / Time</th>
                            <th class="security-log-heading">Event</th>
                            <th class="security-log-heading">User</th>
                            <th class="security-log-heading">IP Address</th>
                            <th class="security-log-heading">User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($events as $event): ?>
                        <tr class="security-log-row">
                            <td class="security-log-cell security-log-timestamp"><?php echo htmlspecialchars((string)($event['timestamp'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="security-log-cell security-log-event"><?php echo htmlspecialchars((string)($event['event'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="security-log-cell"><?php echo htmlspecialchars((string)($event['username'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="security-log-cell"><?php echo htmlspecialchars((string)($event['ip'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></td>
                            <td class="security-log-cell security-log-agent"><?php echo htmlspecialchars((string)($event['user_agent'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="security-log-list">
            <?php foreach ($events as $event): ?>
                <div class="security-log-card">
                    <div class="security-log-card-header">
                        <span class="security-log-event"><?php echo htmlspecialchars((string)($event['event'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></span>
                        <span class="security-log-time"><?php echo htmlspecialchars((string)($event['timestamp'] ?? ''), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>
                    <div class="security-log-field"><span class="security-log-label">User</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['username'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></span></div>
                    <div class="security-log-field"><span class="security-log-label">IP Address</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['ip'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></span></div>
                    <div class="security-log-field"><span class="security-log-label">User Agent</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['user_agent'] ?? 'unknown'), ENT_QUOTES, 'UTF-8'); ?></span></div>
                </div>
            <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</div>
</body>
</html>
