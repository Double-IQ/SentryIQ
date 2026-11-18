<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

define('SENTRYIQ_CONFIG_FILE', __DIR__ . '/sentryiq_config.php');

if (!is_file(SENTRYIQ_CONFIG_FILE) || is_link(SENTRYIQ_CONFIG_FILE)) {
    http_response_code(503);
    exit('SentryIQ configuration is unavailable.');
}

$config = require SENTRYIQ_CONFIG_FILE;
if (!is_array($config)) {
    http_response_code(503);
    exit('SentryIQ configuration is unavailable.');
}

function sentryiq_storage_format_bytes(int $bytes): string
{
    if ($bytes < 1024) {
        return $bytes . ' B';
    }

    $units = ['KB', 'MB', 'GB', 'TB', 'PB'];
    $value = (float)$bytes;

    foreach ($units as $unit) {
        $value /= 1024;

        if ($value < 1024 || $unit === 'PB') {
            return number_format($value, 2) . ' ' . $unit;
        }
    }

    return number_format($value, 2) . ' PB';
}

function sentryiq_storage_directory_size(string $directory, array $excludedNames = []): int
{
    if ($directory === '' || !is_dir($directory) || is_link($directory)) {
        return 0;
    }

    $size = 0;

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $directory,
                FilesystemIterator::SKIP_DOTS
            ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iterator as $file) {
            if (!$file instanceof SplFileInfo || $file->isLink()) {
                continue;
            }

            $pathname = $file->getPathname();
            $basename = $file->getBasename();

            if (in_array($basename, $excludedNames, true)) {
                continue;
            }

            if ($file->isFile()) {
                $fileSize = $file->getSize();
                if ($fileSize > 0) {
                    $size += $fileSize;
                }
            }
        }
    } catch (Throwable) {
        return $size;
    }

    return $size;
}

function sentryiq_storage_cpanel_api(string $host, string $username, string $token): ?array
{
    if (!function_exists('curl_init')) {
        return null;
    }

    $host = trim($host);
    $username = trim($username);
    $token = trim($token);

    if (
        $host === '' ||
        !preg_match('/^[A-Za-z0-9.-]+$/', $host) ||
        $username === '' ||
        !preg_match('/^[A-Za-z0-9._-]+$/', $username) ||
        $token === ''
    ) {
        return null;
    }

    $url = 'https://' . $host . ':2083/execute/Quota/get_quota_info';

    $ch = curl_init($url);
    if ($ch === false) {
        return null;
    }

    $authorization = 'cpanel ' . $username . ':' . $token;

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Authorization: ' . $authorization,
            'Accept: application/json',
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,
    ]);

    $body = curl_exec($ch);
    $httpStatus = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!is_string($body) || $body === '' || $httpStatus < 200 || $httpStatus >= 300) {
        return null;
    }

    $decoded = json_decode($body, true);
    return is_array($decoded) ? $decoded : null;
}

function sentryiq_storage_extract_quota(array $decoded): ?array
{
    $result = $decoded['result'] ?? null;

    if (is_array($result) && isset($result['data']) && is_array($result['data'])) {
        $data = $result['data'];
    } elseif (
        isset($decoded['cpanelresult']['result']['data']) &&
        is_array($decoded['cpanelresult']['result']['data'])
    ) {
        $data = $decoded['cpanelresult']['result']['data'];
    } elseif (
        isset($decoded['cpanelresult']['data']['result']) &&
        is_array($decoded['cpanelresult']['data']['result'])
    ) {
        $data = $decoded['cpanelresult']['data']['result'];
    } else {
        return null;
    }

    if (
        is_array($result) &&
        isset($result['errors']) &&
        is_array($result['errors']) &&
        $result['errors'] !== []
    ) {
        return null;
    }

    $usedBytes = isset($data['bytes_used']) && is_numeric($data['bytes_used'])
        ? max(0, (int)$data['bytes_used'])
        : null;

    $limitBytes = isset($data['byte_limit']) && is_numeric($data['byte_limit'])
        ? max(0, (int)$data['byte_limit'])
        : null;

    $remainBytes = isset($data['bytes_remain']) && is_numeric($data['bytes_remain'])
        ? max(0, (int)$data['bytes_remain'])
        : null;

    if ($usedBytes === null || $limitBytes === null) {
        $usedMb = isset($data['megabytes_used']) && is_numeric($data['megabytes_used'])
            ? (float)$data['megabytes_used']
            : null;

        $limitMb = isset($data['megabyte_limit']) && is_numeric($data['megabyte_limit'])
            ? (float)$data['megabyte_limit']
            : null;

        $remainMb = isset($data['megabytes_remain']) && is_numeric($data['megabytes_remain'])
            ? (float)$data['megabytes_remain']
            : null;

        if ($usedMb === null || $limitMb === null) {
            return null;
        }

        $usedBytes = (int)round(max(0, $usedMb) * 1024 * 1024);
        $limitBytes = $limitMb > 0
            ? (int)round($limitMb * 1024 * 1024)
            : 0;
        $remainBytes = $remainMb !== null
            ? (int)round(max(0, $remainMb) * 1024 * 1024)
            : null;
    }

    if ($limitBytes <= 0) {
        return [
            'available' => null,
            'limit' => null,
            'used' => $usedBytes,
            'unlimited' => true,
        ];
    }

    $availableBytes = $remainBytes !== null
        ? $remainBytes
        : max(0, $limitBytes - $usedBytes);

    return [
        'available' => $availableBytes,
        'limit' => $limitBytes,
        'used' => $usedBytes,
        'unlimited' => false,
    ];
}

function sentryiq_storage_read_cpanel_quota(array $config): ?array
{
    $token = '';

    $dataDir = sentryiq_data_dir();
    if ($dataDir !== '') {
        $tokenFile = rtrim($dataDir, '/') . '/cpanel_api_token.php';

        if (is_file($tokenFile) && !is_link($tokenFile)) {
            $tokenValue = require $tokenFile;

            if (is_string($tokenValue)) {
                $token = trim($tokenValue);
            }
        }
    }

    // Backward-compatible fallback for installations that already configured
    // the token in the ignored SentryIQ configuration file.
    if ($token === '') {
        $token = trim((string)($config['cpanel_api_token'] ?? ''));
    }

    if ($token === '') {
        return null;
    }

    $baseUrl = trim((string)($config['base_url'] ?? ''));
    $host = (string)(parse_url($baseUrl, PHP_URL_HOST) ?: ($_SERVER['SERVER_NAME'] ?? ''));

    $username = trim((string)(
        $config['cpanel_username']
        ?? getenv('CPANEL_USER')
        ?? getenv('USER')
        ?? getenv('LOGNAME')
        ?? get_current_user()
    ));

    $decoded = sentryiq_storage_cpanel_api($host, $username, $token);

    return is_array($decoded)
        ? sentryiq_storage_extract_quota($decoded)
        : null;
}

function sentryiq_storage_has_cpanel_token(array $config): bool
{
    $dataDir = sentryiq_data_dir();

    if ($dataDir !== '') {
        $tokenFile = rtrim($dataDir, '/') . '/cpanel_api_token.php';

        if (is_file($tokenFile) && !is_link($tokenFile)) {
            $tokenValue = require $tokenFile;
            if (is_string($tokenValue) && trim($tokenValue) !== '') {
                return true;
            }
        }
    }

    return trim((string)($config['cpanel_api_token'] ?? '')) !== '';
}


$appRoot = __DIR__;
$dataDir = sentryiq_data_dir();

$publicSize = sentryiq_storage_directory_size($appRoot, [
    'private_data',
    '.git',
]);

$privateSize = $dataDir !== ''
    ? sentryiq_storage_directory_size($dataDir)
    : 0;

$galleryPath = $dataDir !== '' ? rtrim($dataDir, '/') . '/gallery' : '';
$gallerySize = ($galleryPath !== '' && is_dir($galleryPath))
    ? sentryiq_storage_directory_size($galleryPath)
    : 0;

// Gallery storage is contained within the private data directory, so subtract
// it from the private-data total when presenting user account data.
$userAccountDataSize = max(0, $privateSize - $gallerySize);

$quota = sentryiq_storage_read_cpanel_quota($config);

$quotaPercent = null;

if (is_array($quota) && $quota['unlimited'] === false && (int)$quota['limit'] > 0) {
    $quotaPercent = min(
        100,
        max(
            0,
            ((int)$quota['used'] / (int)$quota['limit']) * 100
        )
    );
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
<meta property="og:site_name" content="SentryIQ">
<meta property="og:type" content="website">
<meta property="og:title" content="SentryIQ — Storage">
<meta property="og:description" content="SentryIQ storage usage and cPanel quota information.">
<meta property="og:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ — Storage">
<meta name="twitter:description" content="SentryIQ storage usage and cPanel quota information.">
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<title>SentryIQ — Storage</title>
<link rel="stylesheet" href="assets/css/sentryiq.css?v=20260924-1">
<style>
.storage-section{margin-top:20px}
.storage-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.storage-stat{padding:16px;border-radius:16px;background:var(--neo-surface,#e7ebf1);box-shadow:inset 4px 4px 8px var(--neo-shadow-dark,rgba(142,151,166,.35)),inset -4px -4px 8px var(--neo-shadow-light,rgba(255,255,255,.96))}
.storage-stat-label{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--neo-muted,#697586);font-weight:700;margin-bottom:5px}
.storage-stat-value{display:block;font-size:20px;font-weight:700;color:var(--neo-text,#253041);overflow-wrap:anywhere}
.storage-stat-note{display:block;font-size:12px;color:var(--neo-muted,#697586);margin-top:5px}
.storage-progress{height:14px;border-radius:999px;overflow:hidden;background:var(--neo-surface,#e7ebf1);box-shadow:inset 3px 3px 7px var(--neo-shadow-dark,rgba(142,151,166,.35)),inset -3px -3px 7px var(--neo-shadow-light,rgba(255,255,255,.96));margin-top:16px}
.storage-progress-bar{height:100%;border-radius:999px;background:#1769aa}
.storage-list{display:flex;flex-direction:column;gap:10px;margin-top:10px}
.storage-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 14px;border-radius:14px;background:var(--neo-surface,#e7ebf1);box-shadow:6px 6px 12px var(--neo-shadow-dark,rgba(142,151,166,.35)),-6px -6px 12px var(--neo-shadow-light,rgba(255,255,255,.96))}
.storage-row-name{font-weight:700;color:var(--neo-text,#253041);min-width:0;overflow-wrap:anywhere}
.storage-row-size{font-weight:700;color:var(--neo-accent,#1769aa);white-space:nowrap}
.storage-warning{margin:0;padding:14px 16px;border-radius:14px;background:#fff3cd;color:#664d03;border:1px solid #ffecb5}
.storage-muted{color:var(--neo-muted,#697586)}
@media(max-width:700px){
 .storage-grid{grid-template-columns:1fr}
 .storage-row{align-items:flex-start;flex-direction:column;gap:5px}
 .storage-row-size{white-space:normal}
}
</style>
</head>
<body>
<div class="box">
    <div class="sentryiq-page-header">
        <div class="sentryiq-vault-brand-wrap">
            <img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
            <span class="sentryiq-vault-status">Storage</span>
        </div>
        <div class="sentryiq-mobile-header-actions">
            <form method="POST" class="sentryiq-lock-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="lock_vault" value="1">
                <button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button>
            </form>
            <div class="vault-mobile-menu-bar">
                <button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu">
                    <span class="vault-mobile-menu-icon" aria-hidden="true">☰</span>
                    <span id="vault-mobile-menu-label" class="visually-hidden">Menu</span>
                </button>
            </div>
        </div>
    </div>

    <div id="vault-mobile-menu" class="vault-tabs">
        <button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="documents.php">📄 Docs</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button>
        <button class="tab-btn active" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button>
        <form method="POST" class="vault-menu-lock-form">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="lock_vault" value="1">
            <button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button>
        </form>
    </div>

    <div style="width:100%;margin:16px 0;">
        <a href="index.php?pane=settings" class="btn" style="text-decoration:none;">← System Settings</a>
    </div>

    <div class="form-box">
        <h2 style="margin-top:0;">💾 Storage</h2>
        <p style="margin-top:0;color:#697586;">Current SentryIQ storage usage together with the disk quota assigned to this cPanel account.</p>

        <section class="storage-section">
            <h3>cPanel Account Quota</h3>

            <?php if ($quota === null): ?>
                <p class="storage-warning">
                    <?php if (!sentryiq_storage_has_cpanel_token($config)): ?>
                        A cPanel API token has not been configured yet. Add one to the SentryIQ configuration to enable account quota reporting.
                    <?php else: ?>
                        SentryIQ could not retrieve the cPanel account quota through the authenticated cPanel API.
                        Check the cPanel username, API token permissions, and that secure cPanel API access on port 2083 is available.
                    <?php endif; ?>
                    The folder sizes below are still available. No filesystem capacity is being substituted for the cPanel quota.
                </p>
            <?php else: ?>
                <div class="storage-grid">
                    <div class="storage-stat">
                        <span class="storage-stat-label">Used</span>
                        <span class="storage-stat-value"><?php echo htmlspecialchars(sentryiq_storage_format_bytes((int)$quota['used']), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>

                    <div class="storage-stat">
                        <span class="storage-stat-label">Capacity</span>
                        <span class="storage-stat-value"><?php echo $quota['unlimited'] ? 'Unlimited' : htmlspecialchars(sentryiq_storage_format_bytes((int)$quota['limit']), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>

                    <div class="storage-stat">
                        <span class="storage-stat-label">Available</span>
                        <span class="storage-stat-value"><?php echo $quota['unlimited'] ? 'Unlimited' : htmlspecialchars(sentryiq_storage_format_bytes((int)$quota['available']), ENT_QUOTES, 'UTF-8'); ?></span>
                    </div>

                    <div class="storage-stat">
                        <span class="storage-stat-label">Usage</span>
                        <span class="storage-stat-value"><?php echo $quota['unlimited'] ? 'No quota limit' : htmlspecialchars(number_format((float)$quotaPercent, 1) . '%', ENT_QUOTES, 'UTF-8'); ?></span>
                        <?php if (!$quota['unlimited']): ?>
                            <span class="storage-stat-note">Reported by cPanel quota services.</span>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (!$quota['unlimited']): ?>
                    <div class="storage-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?php echo htmlspecialchars(number_format((float)$quotaPercent, 1, '.', ''), ENT_QUOTES, 'UTF-8'); ?>" aria-label="cPanel storage usage">
                        <div class="storage-progress-bar" style="width:<?php echo htmlspecialchars(number_format((float)$quotaPercent, 2, '.', ''), ENT_QUOTES, 'UTF-8'); ?>%;"></div>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </section>

        <section class="storage-section">
            <h3>SentryIQ Folder Usage</h3>
            <p class="storage-muted" style="margin-top:0;">Folder sizes are calculated from files accessible to the SentryIQ account. Private vault data remains outside the public web root.</p>

            <div class="storage-list">
                <div class="storage-row">
                    <span class="storage-row-name">Public SentryIQ Application</span>
                    <span class="storage-row-size"><?php echo htmlspecialchars(sentryiq_storage_format_bytes($publicSize), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>

                <div class="storage-row">
                    <span class="storage-row-name">User Account Data</span>
                    <span class="storage-row-size"><?php echo htmlspecialchars(sentryiq_storage_format_bytes($userAccountDataSize), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>

                <div class="storage-row">
                    <span class="storage-row-name">Gallery Storage <span class="storage-muted">(included in Private Data)</span></span>
                    <span class="storage-row-size"><?php echo htmlspecialchars(sentryiq_storage_format_bytes($gallerySize), ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
            </div>
        </section>
    </div>
</div>

<script src="assets/js/sentryiq_navigation.js" defer></script>
<script src="assets/js/storage.js" defer></script>
</body>
</html>
