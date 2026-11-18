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
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php"><meta name="csrf-token" content="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><title>SentryIQ — System Log</title><link rel="stylesheet" href="assets/css/sentryiq.css?v=20260923-1"><style>.system-log-table{overflow-x:auto}.system-log-list{display:none}.security-device{display:inline-flex;align-items:center;gap:6px;font-weight:600}.security-user-agent{margin-top:4px;font-size:10px;color:#888;word-break:break-word}.security-user-agent summary{cursor:pointer;color:#888}.security-user-agent code{font-family:inherit}@media(max-width:700px){.system-log-table{display:none}.system-log-list{display:flex;flex-direction:column;gap:10px}.security-log-card{border:1px solid #e9ecef;border-radius:10px;padding:12px;margin-bottom:0;background:#fff}.security-log-card-header{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;margin-bottom:10px}.security-log-event{font-weight:700;word-break:break-word}.security-log-time{font-size:11px;color:#777;text-align:right;white-space:nowrap}.security-log-field{display:flex;flex-direction:row;align-items:baseline;gap:5px;padding:7px 0;border-top:1px solid #f1f3f5}.security-log-label{width:auto;flex:0 0 auto;font-size:11px;color:#777;font-weight:700}.security-log-value{font-size:12px;word-break:break-word}.security-device{font-size:13px}.security-user-agent{font-size:10px}} .system-log-back{width:100%;margin-top:16px;margin-bottom:16px;clear:both;position:relative;z-index:1}.system-log-back .btn{display:block !important;width:100% !important;box-sizing:border-box !important;text-align:center;text-decoration:none !important}@media(max-width:700px){.system-log-back{width:100% !important;margin-top:16px !important;margin-bottom:16px !important;padding-top:16px}.system-log-back .btn{width:100% !important;min-width:0 !important}}</style></head><body><div class="box">
<div class="sentryiq-page-header"><div class="sentryiq-vault-brand-wrap"><img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ"><span class="sentryiq-vault-status">System Log</span></div><div class="sentryiq-mobile-header-actions"><form method="POST" class="sentryiq-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button></form><div class="vault-mobile-menu-bar"><button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu"><span class="vault-mobile-menu-icon" aria-hidden="true">☰</span><span id="vault-mobile-menu-label">Menu</span></button></div></div></div>
<div id="vault-mobile-menu" class="vault-tabs"><button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button><button class="tab-btn" type="button" data-sentryiq-nav="documents.php">📄 Docs</button><button class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button><button class="tab-btn active" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button><form method="POST" class="vault-menu-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button></form></div>
<div class="system-log-back"><a href="index.php?pane=settings" class="btn">← System Settings</a></div><div style="max-width:900px;margin:0 auto;"><div><h2 style="margin-bottom:6px;">🔐 System Log</h2><p style="margin-top:0;color:#666;">Security and authentication events recorded by SentryIQ.</p></div><div class="form-box" style="margin-top:20px;"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;gap:10px;flex-wrap:wrap;"><h3 style="margin:0;">Security Events</h3><span style="font-size:12px;color:#777;"><?php echo count($events); ?> events</span></div><?php if(empty($events)): ?><p style="text-align:center;padding:20px;color:#777;">No security events have been recorded yet.</p><?php else: ?><div class="system-log-table"><table style="width:100%;border-collapse:collapse;font-size:12px;"><thead><tr style="background:#e9ecef;text-align:left;"><th style="padding:9px;">Date / Time</th><th style="padding:9px;">Event</th><th style="padding:9px;">User</th><th style="padding:9px;">IP Address</th><th style="padding:9px;">Device / Browser</th></tr></thead><tbody><?php foreach($events as $event): $ua=sentryiq_describe_user_agent((string)($event['user_agent']??'')); ?><tr style="border-bottom:1px solid #eee;"><td style="padding:9px;white-space:nowrap;"><?php echo htmlspecialchars((string)($event['timestamp']??'')); ?></td><td style="padding:9px;font-weight:bold;"><?php echo htmlspecialchars((string)($event['event']??'')); ?></td><td style="padding:9px;"><?php echo htmlspecialchars((string)($event['username']??'unknown')); ?></td><td style="padding:9px;"><?php echo htmlspecialchars((string)($event['ip']??'unknown')); ?></td><td style="padding:9px;max-width:260px;"><span class="security-device"><?php echo htmlspecialchars($ua['label']); ?></span><details class="security-user-agent"><summary>View User-Agent</summary><code><?php echo htmlspecialchars($ua['raw'],ENT_QUOTES,'UTF-8'); ?></code></details></td></tr><?php endforeach; ?></tbody></table></div><div class="system-log-list"><?php foreach($events as $event): $ua=sentryiq_describe_user_agent((string)($event['user_agent']??'')); ?><div class="security-log-card"><div class="security-log-card-header"><span class="security-log-event"><?php echo htmlspecialchars((string)($event['event']??''),ENT_QUOTES,'UTF-8') === 'SUCCESSFUL_VAULT_LOGIN_PASSKEY' ? 'VAULT_LOGIN_PASSKEY' : htmlspecialchars((string)($event['event']??''),ENT_QUOTES,'UTF-8'); ?></span><span class="security-log-time"><?php echo htmlspecialchars((string)($event['timestamp']??''),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">User:</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['username']??'unknown'),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">IP Address:</span><span class="security-log-value"><?php echo htmlspecialchars((string)($event['ip']??'unknown'),ENT_QUOTES,'UTF-8'); ?></span></div><div class="security-log-field"><span class="security-log-label">Device:</span><span class="security-log-value"><span class="security-device"><?php echo htmlspecialchars($ua['label'],ENT_QUOTES,'UTF-8'); ?></span><details class="security-user-agent"><summary>View User-Agent</summary><code><?php echo htmlspecialchars($ua['raw'],ENT_QUOTES,'UTF-8'); ?></code></details></span></div></div><?php endforeach; ?></div><?php endif; ?></div></div></div><script src="assets/js/sentryiq_navigation.js" defer></script></body></html>