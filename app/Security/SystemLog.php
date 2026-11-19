<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

function sentryiq_describe_user_agent(string $userAgent): array
{
    $ua = strtolower($userAgent);
    $device = '🖥️ Desktop';

    if (str_contains($ua, 'iphone')) {
        $device = '📱 iPhone';
    } elseif (str_contains($ua, 'ipad')) {
        $device = '📱 iPad';
    } elseif (str_contains($ua, 'android')) {
        $device = '📱 Android';
    } elseif (str_contains($ua, 'macintosh') || str_contains($ua, 'mac os x')) {
        $device = '💻 Mac';
    } elseif (str_contains($ua, 'windows')) {
        $device = '🖥️ Windows';
    } elseif (str_contains($ua, 'linux')) {
        $device = '🖥️ Linux';
    }

    $browser = 'Unknown browser';
    $version = '';

    if (preg_match('/edg(?:e|a|ios)?\/([\d.]+)/i', $userAgent, $match)) {
        $browser = 'Edge';
        $version = $match[1];
    } elseif (preg_match('/(?:chrome|crios)\/([\d.]+)/i', $userAgent, $match) && !str_contains($ua, 'edg/')) {
        $browser = 'Chrome';
        $version = $match[1];
    } elseif (preg_match('/firefox\/([\d.]+)/i', $userAgent, $match)) {
        $browser = 'Firefox';
        $version = $match[1];
    } elseif (preg_match('/version\/([\d.]+).*safari\//i', $userAgent, $match)) {
        $browser = 'Safari';
        $version = $match[1];
    } elseif (preg_match('/opr\/([\d.]+)/i', $userAgent, $match)) {
        $browser = 'Opera';
        $version = $match[1];
    }

    $label = $device . ' · ' . $browser . ($version !== '' ? ' ' . $version : '');

    return [
        'label' => $label,
        'raw' => $userAgent !== '' ? $userAgent : 'Unknown',
    ];
}

$dataDir=sentryiq_data_dir();
if($dataDir!==''&&is_file($dataDir.'/vault_engine.php')&&!is_link($dataDir.'/vault_engine.php'))require_once $dataDir.'/vault_engine.php';
$events=function_exists('read_security_log')?read_security_log():[];
$csrf=sentryiq_csrf_token();
?>
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" sizes="32x32" href="sentryiq-icon.php?size=32">
<link rel="icon" type="image/png" sizes="16x16" href="sentryiq-icon.php?size=16">
<link rel="apple-touch-icon" sizes="180x180" href="sentryiq-icon.php?size=180">
<meta property="og:site_name" content="SentryIQ">
<meta property="og:type" content="website">
<meta property="og:title" content="SentryIQ — System Log">
<meta property="og:description" content="SentryIQ security system log.">
<meta property="og:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ — System Log">
<meta name="twitter:description" content="SentryIQ security system log.">
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php"><meta name="csrf-token" content="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><title>SentryIQ — System Log</title><link rel="stylesheet" href="assets/css/sentryiq.css?v=20260923-1"><link rel="stylesheet" href="assets/css/system_log.css?v=20261119-1"></head><body><div class="box">
<div class="sentryiq-page-header"><div class="sentryiq-vault-brand-wrap"><img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ"><span class="sentryiq-vault-status">System Log</span></div><div class="sentryiq-mobile-header-actions"><form method="POST" class="sentryiq-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button></form><div class="vault-mobile-menu-bar"><button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu"><span class="vault-mobile-menu-icon" aria-hidden="true">☰</span><span id="vault-mobile-menu-label">Menu</span></button></div></div></div>
<div id="vault-mobile-menu" class="vault-tabs"><button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button><button class="tab-btn" type="button" data-sentryiq-nav="documents.php">📄 Docs</button><button class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button><button class="tab-btn active" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button><form method="POST" class="vault-menu-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button></form></div>
<div class="system-log-back"><a href="index.php?pane=settings" class="btn">← System Settings</a></div><div class="system-log-container"><div><h2 class="system-log-title">🔐 System Log</h2><p class="system-log-description">Security and authentication events recorded by SentryIQ.</p></div><div class="form-box system-log-panel"><div class="system-log-panel-header"><h3 class="system-log-section-title">Security Events</h3><span class="system-log-count"><?php echo count($events); ?> events</span></div><?php if(empty($events)): ?><p class="system-log-empty">No security events have been recorded yet.</p><?php else: ?><div class="system-log-table"><table class="system-log-data-table"><thead><tr class="system-log-table-heading"><th class="system-log-cell">Date / Time</th><th class="system-log-cell">Event</th><th class="system-log-cell">User</th><th class="system-log-cell">IP Address</th><th class="system-log-cell">Device / Browser</th></tr></thead><tbody><?php foreach($events as $event): $ua=sentryiq_describe_user_agent((string)($event['user_agent']??'')); ?><tr class="system-log-table-row"><td class="system-log-cell system-log-nowrap"><?php echo htmlspecialchars((string)($event['timestamp']??'')); ?></td><td class="system-log-cell system-log-bold"><?php echo htmlspecialchars((string)($event['event']??'')); ?></td><td class="system-log-cell"><?php echo htmlspecialchars((string)($event['username']??'unknown')); ?></td><td class="system-log-cell"><?php echo htmlspecialchars((string)($event['ip']??'unknown')); ?></td><td class="system-log-cell system-log-user-agent-cell"><span class="security-device"><?php echo htmlspecialchars($ua['label']); ?></span><details class="security-user-agent"><summary>View User-Agent</summary><code><?php echo htmlspecialchars($ua['raw'],ENT_QUOTES,'UTF-8'); ?></code></details></td></tr><?php endforeach; ?></tbody></table></div><div class="system-log-list"><?php foreach($events as $event): $ua=sentryiq_describe_user_agent((string)($event['user_agent']??'')); ?><div class="security-log-card"><div class="security-log-card-header"><span class="security-log-event"><?php echo htmlspecialchars((string)($event['event']??''),ENT_QUOTES,'UTF-8') === 'SUCCESSFUL_VAULT_LOGIN_PASSKEY' ? 'VAULT_LOGIN_PASSKEY' : htmlspecialchars((string)($event['event']??''),ENT_QUOTES,'UTF-8'); ?></span><span class="security-log-time"><?php echo htmlspecialchars((string)($event['timestamp']??''),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">User:</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['username']??'unknown'),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">IP Address:</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['ip']??'unknown'),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">Device:</span><span class="security-log-value"><span class="security-device"><?php echo htmlspecialchars($ua['label'],ENT_QUOTES,'UTF-8'); ?></span><details class="security-user-agent"><summary>View User-Agent</summary><code><?php echo htmlspecialchars($ua['raw'],ENT_QUOTES,'UTF-8'); ?></code></details></span></div></div><?php endforeach; ?></div><?php endif; ?></div></div></div><script src="assets/js/sentryiq_navigation.js" defer></script></body></html>