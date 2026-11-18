<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/Security/SecurityBootstrap.php';
sentryiq_security_bootstrap();

$root = dirname(__DIR__);
$configFile = $root . '/sentryiq_config.php';
$installed = is_file($configFile) && !is_link($configFile);
$authenticated = isset($_SESSION['master_key']) && is_string($_SESSION['master_key']) && strlen($_SESSION['master_key']) === 32;

if ($installed && !$authenticated) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Authentication required. Unlock SentryIQ, then open this diagnostic again.');
}

header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

const SENTRYIQ_DIAGNOSTIC_BUILD = 'strict-2xx-url-source-contracts-2026-09-21';

$results = [];
function add_check(string $group, string $name, bool $ok, string $detail = ''): void
{
    global $results;
    $results[] = ['group' => $group, 'name' => $name, 'ok' => $ok, 'detail' => $detail];
}

function safe_path_state(string $path): array
{
    clearstatcache(true, $path);
    return [
        'file' => is_file($path),
        'dir' => is_dir($path),
        'link' => is_link($path),
        'readable' => is_readable($path),
        'size' => is_file($path) ? filesize($path) : null,
    ];
}

function add_required_file_check(string $group, string $label, string $relativePath): void
{
    $state = safe_path_state(dirname(__DIR__) . '/' . $relativePath);
    $ok = $state['file'] && !$state['link'] && $state['readable'];
    $detail = $state['link'] ? 'SYMLINK' : ($state['dir'] ? 'directory (expected file)' : ($state['file'] ? ('file' . ($state['size'] !== null ? ', ' . $state['size'] . ' bytes' : '')) : 'missing'));
    add_check($group, $label, $ok, $detail);
}

function add_source_reference_check(string $relativePath, string $pattern, string $label): void
{
    $path = dirname(__DIR__) . '/' . $relativePath;
    $source = is_readable($path) ? @file_get_contents($path) : false;
    $ok = is_string($source) && preg_match($pattern, $source) === 1;
    add_check('URL/source references', $label, $ok, $ok ? 'exact HTML reference found' : ($relativePath . ': expected HTML reference not found'));
}

function extract_html_asset_urls(string $source): array
{
    $urls = [];
    if (preg_match_all('/(?:href|src)=["\\\']([^"\\\']+)["\\\']/i', $source, $matches)) {
        foreach ($matches[1] as $url) {
            $urls[] = html_entity_decode((string)$url, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
    }
    return array_values(array_unique($urls));
}

function add_source_asset_check(string $relativePath, string $expectedUrl, string $label): void
{
    $path = dirname(__DIR__) . '/' . $relativePath;
    $source = is_readable($path) ? @file_get_contents($path) : false;
    $urls = is_string($source) ? extract_html_asset_urls($source) : [];
    $ok = in_array($expectedUrl, $urls, true);
    add_check('URL/source references', $label, $ok, $ok ? 'exact URL present' : ($relativePath . ': exact URL missing: ' . $expectedUrl));
}

function add_source_no_exact_asset_check(string $relativePath, string $legacyUrl, string $label): void
{
    $path = dirname(__DIR__) . '/' . $relativePath;
    $source = is_readable($path) ? @file_get_contents($path) : false;
    $urls = is_string($source) ? extract_html_asset_urls($source) : [];
    $ok = !in_array($legacyUrl, $urls, true);
    add_check('URL/source references', $label, $ok, $ok ? 'legacy URL not referenced' : ($relativePath . ': legacy URL still referenced: ' . $legacyUrl));
}

add_check('Diagnostic', 'Diagnostic build', true, SENTRYIQ_DIAGNOSTIC_BUILD);
add_check('Environment', 'PHP version', PHP_VERSION_ID >= 80300, PHP_VERSION);
$httpsOk = PHP_SAPI === 'cli' || (($_SERVER['HTTPS'] ?? '') === 'on') || (string)($_SERVER['SERVER_PORT'] ?? '') === '443';
add_check('Environment', 'HTTPS request', $httpsOk, $httpsOk ? 'HTTPS' : 'HTTP');
add_check('Environment', 'Session active', session_status() === PHP_SESSION_ACTIVE, session_status() === PHP_SESSION_ACTIVE ? 'active' : 'inactive');
add_check('Environment', 'Installed flag', $installed, $installed ? 'installed' : 'not installed');
add_check('Environment', 'Authenticated session', !$installed || $authenticated, $authenticated ? 'authenticated' : 'not authenticated');

$config = null;
$dataDir = '';
$baseUrl = '';
if ($installed && is_readable($configFile)) {
    try {
        $loaded = require $configFile;
        $config = is_array($loaded) ? $loaded : null;
    } catch (Throwable $e) {
        add_check('Runtime configuration', 'Configuration loads', false, $e::class . ': ' . $e->getMessage());
    }
}
add_check('Runtime configuration', 'Configuration array', !$installed || is_array($config));
if (is_array($config)) {
    $dataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
    $baseUrl = rtrim(trim((string)($config['base_url'] ?? '')), '/');
    add_check('Runtime configuration', 'Data directory configured', $dataDir !== '', $dataDir !== '' ? 'configured' : 'missing');
    add_check('Runtime configuration', 'HTTPS base URL configured', $baseUrl !== '' && str_starts_with($baseUrl, 'https://'), $baseUrl !== '' ? $baseUrl : 'missing');
    if ($dataDir !== '') {
        $state = safe_path_state($dataDir);
        add_check('Runtime storage', 'Runtime directory exists', $state['dir'] && !$state['link'], $state['link'] ? 'SYMLINK' : ($state['dir'] ? 'directory' : 'missing'));
        add_check('Runtime storage', 'Runtime directory is writable', $state['dir'] && !$state['link'] && is_writable($dataDir));
        foreach (['vault_engine.php' => 'Vault engine exists', 'email_template.php' => 'Email template exists', 'passwords.enc' => 'Vault encrypted file exists'] as $file => $label) {
            $fileState = safe_path_state($dataDir . '/' . $file);
            add_check('Runtime storage', $label, $fileState['file'] && !$fileState['link'] && $fileState['readable'], $fileState['link'] ? 'SYMLINK' : ($fileState['file'] ? ('file' . ($fileState['size'] !== null ? ', ' . $fileState['size'] . ' bytes' : '')) : 'missing'));
        }
    }
}

$serverHost = trim((string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? ''));
$scriptDir = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? ''))), '/');
$runtimeExpectedBaseUrl = $serverHost !== '' && $httpsOk ? 'https://' . $serverHost . ($scriptDir === '/' ? '' : $scriptDir) : '';
$baseUrlMatchesRuntime = $baseUrl === '' || ($runtimeExpectedBaseUrl !== '' && $baseUrl === rtrim($runtimeExpectedBaseUrl, '/'));
add_check('Configuration URL', 'Base URL matches current application URL', $baseUrlMatchesRuntime, $runtimeExpectedBaseUrl !== '' ? ('configured=' . ($baseUrl !== '' ? $baseUrl : 'missing') . ', current=' . rtrim($runtimeExpectedBaseUrl, '/')) : 'current application URL could not be determined');

$wideLogoPath = $root . '/assets/images/sentryiq-logo-wide.webp';
$wideLogoState = safe_path_state($wideLogoPath);
add_check('Branding', 'Wide logo file', $wideLogoState['file'] && !$wideLogoState['link'] && $wideLogoState['readable'], $wideLogoState['link'] ? 'SYMLINK' : ($wideLogoState['file'] ? ('file' . ($wideLogoState['size'] !== null ? ', ' . $wideLogoState['size'] . ' bytes' : '')) : ($wideLogoState['dir'] ? 'directory (expected file)' : 'missing')));
if ($wideLogoState['file'] && !$wideLogoState['link']) {
    $logoInfo = @getimagesize($wideLogoPath);
    $logoDimensionsOk = is_array($logoInfo) && strtolower((string)($logoInfo['mime'] ?? '')) === 'image/webp' && (int)($logoInfo[0] ?? 0) > 0 && (int)($logoInfo[1] ?? 0) > 0;
    $logoDimensionDetail = is_array($logoInfo) ? ((string)($logoInfo[0] ?? '?') . '×' . (string)($logoInfo[1] ?? '?') . ', ' . (string)($logoInfo['mime'] ?? 'unknown')) : 'unreadable image';
    add_check('Branding', 'Wide logo dimensions/type', $logoDimensionsOk, $logoDimensionDetail);
    $logoHash = @hash_file('sha256', $wideLogoPath);
    add_check('Branding', 'Wide logo SHA-256', is_string($logoHash) && preg_match('/^[a-f0-9]{64}$/', $logoHash) === 1, is_string($logoHash) ? $logoHash : 'hash unavailable');
}

$iconSourcePath = $root . '/sentryiq-icon.php';
$iconSource = is_readable($iconSourcePath) ? @file_get_contents($iconSourcePath) : false;
$iconPayloadOk = false;
$iconDecodedLength = 0;
if (is_string($iconSource) && preg_match("/const\\s+SENTRYIQ_ICON_BASE64\\s*=\\s*'([^']+)'/", $iconSource, $iconMatch) === 1) {
    $decoded = base64_decode($iconMatch[1], true);
    if (is_string($decoded)) {
        $iconDecodedLength = strlen($decoded);
        $iconPayloadOk = $iconDecodedLength >= 8 && substr($decoded, 0, 8) === "\x89PNG\r\n\x1a\n";
    }
}
add_check('Branding', 'Icon PHP payload', $iconPayloadOk, $iconPayloadOk ? ('valid PNG payload, ' . $iconDecodedLength . ' bytes') : 'embedded PNG payload could not be decoded/validated');

$logoCssPath = $root . '/assets/css/sentryiq.css';
$logoCss = is_readable($logoCssPath) ? @file_get_contents($logoCssPath) : false;
$cssLogoOk = is_string($logoCss) && str_contains($logoCss, "../images/sentryiq-logo-wide.webp");
add_check('Branding', 'CSS logo reference', $cssLogoOk, $cssLogoOk ? 'assets/css/sentryiq.css → ../images/sentryiq-logo-wide.webp' : 'expected reference missing');

foreach (['sentryiq-logo-wide.webp' => 'Legacy root logo absent', 'pm_style.css' => 'Legacy root stylesheet absent', 'vault_folders.js' => 'Legacy root Vault JS absent', 'records_view.js' => 'Legacy root Records JS absent', 'safari.js' => 'Legacy root Safari JS absent'] as $legacy => $label) {
    $legacyPath = $root . '/' . $legacy;
    add_check('Branding', $label, !is_file($legacyPath) && !is_link($legacyPath), (is_file($legacyPath) || is_link($legacyPath)) ? 'legacy root file still present' : 'not present at root');
}

$requiredFiles = [
    'Public entry points' => [
        'index.php', 'gallery.php', 'documents.php', 'first_run.php', 'sentryiq-icon.php', 'vault-icon.php',
        'auth_flow.php', 'security_bootstrap.php', 'sentryiq_diagnostic.php'
    ],
    'Application implementations' => [
        'app/Auth/PasskeySetup.php', 'app/Auth/PasskeyLogin.php', 'app/Auth/PasskeyAuth.php', 'app/Auth/Passkeys.php', 'app/Auth/AuthFlow.php',
        'app/Documents/Upload.php', 'app/Documents/Download.php', 'app/Documents/Delete.php',
        'app/Gallery/AlbumActions.php', 'app/Gallery/BulkDelete.php', 'app/Gallery/Delete.php', 'app/Gallery/Image.php', 'app/Gallery/Settings.php', 'app/Gallery/Upload.php',
        'app/Vault/Actions.php', 'app/Vault/CategoryActions.php', 'app/Vault/FolderData.php', 'app/Vault/RecordActions.php', 'app/Vault/RecordsCategoryActions.php', 'app/Vault/RecordsViewData.php',
        'app/Vault/DashboardActions.php', 'app/Vault/DashboardList.php',
        'app/Security/SecurityBootstrap.php', 'app/Security/SecurityFeatures.php', 'app/Security/SecurityLog.php', 'app/Security/SystemLog.php', 'app/Security/FirstRun.php'
    ],
    'Static assets' => ['assets/css/sentryiq.css', 'assets/js/vault_folders.js', 'assets/js/records_view.js', 'assets/js/safari.js', 'assets/images/sentryiq-logo-wide.webp', '.htaccess'],
];

foreach ($requiredFiles as $group => $paths) {
    foreach ($paths as $relative) add_required_file_check($group, $relative, $relative);
}

$sourceRefs = [
    ['index.php', 'assets/css/sentryiq.css', 'index stylesheet URL'],
    ['index.php', 'assets/images/sentryiq-logo-wide.webp', 'index wide-logo URL'],
    ['index.php', 'sentryiq-icon.php', 'index favicon/icon URL'],
    ['index.php', 'assets/js/vault_folders.js?v=20260915-2', 'index Vault JS URL'],
    ['index.php', 'assets/js/records_view.js?v=20260916-2', 'index Records JS URL'],
    ['gallery.php', 'assets/css/sentryiq.css', 'gallery stylesheet URL'],
    ['gallery.php', 'assets/images/sentryiq-logo-wide.webp', 'gallery wide-logo URL'],
    ['documents.php', 'assets/css/sentryiq.css', 'documents stylesheet URL'],
    ['documents.php', 'assets/images/sentryiq-logo-wide.webp', 'documents wide-logo URL'],
    ['app/Auth/PasskeySetup.php', 'assets/css/sentryiq.css', 'Passkey setup stylesheet URL'],
    ['app/Auth/PasskeySetup.php', 'assets/images/sentryiq-logo-wide.webp', 'Passkey setup wide-logo URL'],
    ['app/Auth/PasskeyLogin.php', 'assets/css/sentryiq.css', 'Passkey login stylesheet URL'],
    ['app/Auth/Passkeys.php', 'assets/css/sentryiq.css', 'Passkeys stylesheet URL'],
    ['app/Auth/Passkeys.php', 'assets/images/sentryiq-logo-wide.webp', 'Passkeys wide-logo URL'],
    ['app/Security/FirstRun.php', 'assets/css/sentryiq.css', 'First-run stylesheet URL'],
    ['app/Security/SecurityFeatures.php', 'assets/css/sentryiq.css', 'Security features stylesheet URL'],
    ['app/Security/SecurityLog.php', 'assets/css/sentryiq.css', 'Security log stylesheet URL'],
    ['app/Security/SecurityLog.php', 'assets/images/sentryiq-logo-wide.webp', 'Security log wide-logo URL'],
    ['app/Gallery/Settings.php', 'assets/css/sentryiq.css', 'Gallery Settings stylesheet URL'],
    ['app/Gallery/Settings.php', 'assets/images/sentryiq-logo-wide.webp', 'Gallery Settings wide-logo URL'],
    ['app/Security/SystemLog.php', 'assets/css/sentryiq.css', 'System log stylesheet URL'],
    ['app/Security/SystemLog.php', 'assets/images/sentryiq-logo-wide.webp', 'System log wide-logo URL'],
];
foreach ($sourceRefs as $ref) add_source_asset_check($ref[0], $ref[1], $ref[2]);

$sourcePageFiles = [
    'index.php', 'gallery.php', 'documents.php', 'app/Gallery/Settings.php', 'app/Auth/PasskeySetup.php', 'app/Auth/PasskeyLogin.php', 'app/Auth/Passkeys.php', 'app/Security/FirstRun.php', 'app/Security/SecurityFeatures.php',
    'app/Security/SecurityLog.php', 'app/Security/SystemLog.php'
];
foreach ($sourcePageFiles as $page) {
    add_source_no_exact_asset_check($page, 'pm_style.css', $page . ' has no exact legacy stylesheet URL');
    add_source_no_exact_asset_check($page, 'sentryiq-logo-wide.webp', $page . ' has no exact legacy root logo URL');
}

function add_legacy_attribute_reference_scan(): void
{
    $scanFiles = [];
    foreach (glob(dirname(__DIR__) . '/*.php') ?: [] as $path) {
        $scanFiles[] = $path;
    }

    $appRoot = dirname(__DIR__) . '/app';
    if (is_dir($appRoot)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($appRoot, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile() || strtolower($fileInfo->getExtension()) !== 'php') continue;
            $scanFiles[] = $fileInfo->getPathname();
        }
    }

    $legacyMap = [
        'pm_style.css' => 'legacy stylesheet URL',
        'sentryiq-logo-wide.webp' => 'legacy wide-logo URL',
        'safari.js' => 'legacy Safari JS URL',
        'vault_folders.js' => 'legacy Vault JS URL',
        'records_view.js' => 'legacy Records JS URL',
    ];

    foreach (array_values(array_unique($scanFiles)) as $path) {
        $source = @file_get_contents($path);
        if (!is_string($source)) continue;
        $relative = ltrim(str_replace(dirname(__DIR__) . '/', '', str_replace('\\', '/', $path)), '/');
        $urls = extract_html_asset_urls($source);

        foreach ($legacyMap as $legacyUrl => $description) {
            if (!in_array($legacyUrl, $urls, true)) continue;
            add_check(
                'URL/source references',
                'No ' . $description . ' in ' . $relative,
                false,
                $relative . ': legacy URL still referenced: ' . $legacyUrl
            );
        }
    }
}

add_legacy_attribute_reference_scan();


function stylesheet_rule_body(string $css, string $selector): string
{
    if ($css === '' || $selector === '') return '';
    if (!preg_match_all('/(?:^|})\s*([^{}]+)\{([^{}]*)\}/s', $css, $matches, PREG_SET_ORDER)) return '';
    $bodies = [];
    foreach ($matches as $match) {
        $selectors = preg_split('/\s*,\s*/', trim((string)$match[1])) ?: [];
        if (in_array(trim($selector), array_map('trim', $selectors), true)) $bodies[] = (string)$match[2];
    }
    return implode(';', $bodies);
}

function stylesheet_has_declaration(string $body, string $property, ?string $value = null): bool
{
    if ($body === '') return false;
    if (preg_match('/(?:^|;)\s*' . preg_quote($property, '/') . '\s*:\s*([^;]+)\s*(?:;|$)/i', $body, $match) !== 1) return false;
    return $value === null || trim((string)$match[1]) === $value;
}

function add_stylesheet_contract_checks(string $relativePath): void
{
    $path = dirname(__DIR__) . '/' . $relativePath;
    $css = is_readable($path) ? @file_get_contents($path) : false;
    if (!is_string($css) || trim($css) === '') {
        add_check('Stylesheet', 'Stylesheet source', false, $relativePath . ' is missing, unreadable, or empty');
        return;
    }

    add_check('Stylesheet', 'Stylesheet source', true, $relativePath . ', ' . strlen($css) . ' bytes');

    $contracts = [
        ['.box', 'background', null, 'Main container styling'],
        ['.box', 'box-shadow', null, 'Main container depth'],
        ['.form-box', 'border-radius', null, 'Gallery Settings panel shape'],
        ['.form-box', 'box-shadow', null, 'Gallery Settings panel depth'],
        ['.sentryiq-page-header', 'display', 'grid', 'Header layout'],
        ['.sentryiq-vault-banner', 'height', 'auto', 'Wide logo sizing'],
        ['.vault-tabs', 'display', 'flex', 'Navigation layout'],
        ['.btn', 'border-radius', null, 'Button shape'],
        ['.btn', 'box-shadow', null, 'Button depth'],
    ];

    foreach ($contracts as [$selector, $property, $value, $description]) {
        $body = stylesheet_rule_body($css, $selector);
        $ok = stylesheet_has_declaration($body, $property, $value);
        add_check('Stylesheet', $description, $ok, $ok ? ($selector . ' {' . $property . ($value !== null ? ': ' . $value : '') . '} present') : ('missing ' . $selector . ' {' . $property . ($value !== null ? ': ' . $value : '') . '}'));
    }

    $mobileOk = preg_match('/@media\s*\(\s*max-width\s*:\s*700px\s*\)\s*\{/i', $css) === 1;
    add_check('Stylesheet', 'Mobile CSS contract', $mobileOk, $mobileOk ? 'max-width:700px rules present' : 'missing max-width:700px rules');

    $logoOk = str_contains($css, "../images/sentryiq-logo-wide.webp");
    add_check('Stylesheet', 'Stylesheet logo URL', $logoOk, $logoOk ? '../images/sentryiq-logo-wide.webp' : 'expected relative logo URL missing');
}

add_stylesheet_contract_checks('assets/css/sentryiq.css');

$browserTests = [
    ['type' => 'asset', 'label' => 'CSS', 'url' => 'assets/css/sentryiq.css', 'expectedContentType' => 'text/css', 'parseCss' => true],
    ['type' => 'asset', 'label' => 'Vault folders JS', 'url' => 'assets/js/vault_folders.js?v=20260915-2', 'expectedContentType' => 'text/javascript'],
    ['type' => 'asset', 'label' => 'Records JS', 'url' => 'assets/js/records_view.js?v=20260916-2', 'expectedContentType' => 'text/javascript'],
    ['type' => 'asset', 'label' => 'Safari JS', 'url' => 'assets/js/safari.js', 'expectedContentType' => 'text/javascript'],
    ['type' => 'asset', 'label' => 'Wide logo', 'url' => 'assets/images/sentryiq-logo-wide.webp', 'expectedContentType' => 'image/webp'],
    ['type' => 'asset', 'label' => 'Favicon/icon endpoint', 'url' => 'sentryiq-icon.php', 'expectedContentType' => 'image/png', 'expectedMagic' => [137,80,78,71,13,10,26,10]],
    ['type' => 'page', 'label' => 'index.php', 'url' => 'index.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'script','prefix'=>'assets/js/vault_folders.js'],
        ['tag'=>'script','prefix'=>'assets/js/records_view.js'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
        ['tag'=>'link','value'=>'sentryiq-icon.php'],
    ]],
    ['type' => 'page', 'label' => 'documents.php', 'url' => 'documents.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'page', 'label' => 'gallery.php', 'url' => 'gallery.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'page', 'label' => 'passkey_setup.php', 'url' => 'passkey_setup.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'page', 'label' => 'passkey_login.php', 'url' => 'passkey_login.php', 'expectedFinalPath' => 'index.php', 'expectedContentType' => 'text/html'],
    ['type' => 'page', 'label' => 'passkeys.php', 'url' => 'passkeys.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'page', 'label' => 'gallery_settings.php', 'url' => 'gallery_settings.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ], 'expectedStylesheet' => 'assets/css/sentryiq.css', 'expectedCssContracts' => [
        ['selector'=>'.box','property'=>'boxShadow','not'=>'none'],
        ['selector'=>'.form-box','property'=>'borderRadius','not'=>'0px'],
        ['selector'=>'.form-box','property'=>'boxShadow','not'=>'none'],
        ['selector'=>'.sentryiq-page-header','property'=>'display','value'=>'grid'],
        ['selector'=>'.sentryiq-vault-banner','property'=>'width','not'=>'0px'],
        ['selector'=>'.sentryiq-vault-banner','property'=>'height','value'=>'auto'],
        ['selector'=>'.vault-tabs','property'=>'display','value'=>'flex'],
        ['selector'=>'.btn','property'=>'borderRadius','not'=>'0px'],
        ['selector'=>'.btn','property'=>'boxShadow','not'=>'none'],
    ]],
    ['type' => 'data', 'label' => 'records_view_data.php', 'url' => 'records_view_data.php', 'expectedContentType' => 'application/json'],
    ['type' => 'data', 'label' => 'vault_folder_data.php', 'url' => 'vault_folder_data.php', 'expectedContentType' => 'application/json'],
    ['type' => 'page', 'label' => 'security-features.php', 'url' => 'security-features.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
    ]],
    ['type' => 'page', 'label' => 'security_log.php', 'url' => 'security_log.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'page', 'label' => 'system_log.php', 'url' => 'system_log.php', 'expectedContentType' => 'text/html', 'requiredHtmlRefs' => [
        ['tag'=>'link','value'=>'assets/css/sentryiq.css'],
        ['tag'=>'img','value'=>'assets/images/sentryiq-logo-wide.webp'],
    ]],
    ['type' => 'not-tested', 'label' => 'document_upload.php', 'url' => 'document_upload.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'document_delete.php', 'url' => 'document_delete.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'gallery_album.php', 'url' => 'gallery_album.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'gallery_bulk_delete.php', 'url' => 'gallery_bulk_delete.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'gallery_delete.php', 'url' => 'gallery_delete.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'gallery_upload.php', 'url' => 'gallery_upload.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'record_actions.php', 'url' => 'record_actions.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'records_category_actions.php', 'url' => 'records_category_actions.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'vault_actions.php', 'url' => 'vault_actions.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'vault_category_actions.php', 'url' => 'vault_category_actions.php', 'reason' => 'POST-only endpoint; browser GET is not a health test'],
    ['type' => 'not-tested', 'label' => 'document_download.php', 'url' => 'document_download.php', 'reason' => 'Requires a real document id; no-id GET is intentionally not a health test'],
    ['type' => 'not-tested', 'label' => 'gallery_image.php', 'url' => 'gallery_image.php', 'reason' => 'Requires a real photo id; no-id GET is intentionally not a health test'],
];

$csrf = function_exists('sentryiq_csrf_token') ? sentryiq_csrf_token() : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['diagnostic_log']) && $dataDir !== '' && is_dir($dataDir) && !is_link($dataDir)) {
    sentryiq_require_csrf();
    $raw = (string)($_POST['diagnostic_log'] ?? '');
    if (strlen($raw) > 262144) {
        http_response_code(413);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Diagnostic report exceeds the size limit.']);
        exit;
    }
    try {
        $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Invalid diagnostic report.']);
        exit;
    }
    if (!is_array($decoded)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Invalid diagnostic report.']);
        exit;
    }
    $safe = $decoded;
    $record = [
        'timestamp' => date('c'),
        'stage' => 'SELF_TEST_BROWSER_RESULTS',
        'php_version' => PHP_VERSION,
        'browser' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 300),
        'results' => $safe,
    ];
    $log = $dataDir . '/diagnostic_self_test.log';
    $line = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (is_string($line)) {
        @file_put_contents($log, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
        @chmod($log, 0600);
    }
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => true]);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
<title>SentryIQ Self-Test</title>
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f6f8;color:#20252b;margin:0;padding:24px}.wrap{max-width:1150px;margin:auto}.card{background:#fff;border:1px solid #dfe4ea;border-radius:10px;padding:20px;margin-bottom:18px;box-shadow:0 2px 8px rgba(0,0,0,.04)}h1{margin:0 0 6px;font-size:24px}h2{font-size:17px;margin:22px 0 10px}.summary{font-size:15px;margin:12px 0}.ok{color:#137333;font-weight:600}.bad{color:#b3261e;font-weight:600}.warn{color:#8a5a00;font-weight:600}table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px 8px;border-bottom:1px solid #edf0f3;text-align:left;vertical-align:top}th{font-weight:650}pre{white-space:pre-wrap;word-break:break-word;background:#f7f8fa;border:1px solid #e5e8ec;padding:12px;border-radius:7px;max-height:420px;overflow:auto}.muted{color:#6b7280}button{border:0;border-radius:7px;padding:10px 14px;font-weight:600;cursor:pointer}#run{background:#1f6feb;color:#fff}#copy{background:#e9eef5;margin-left:8px}.danger{background:#fff4f2;border-color:#f1c7c1}.note{font-size:12px;color:#6b7280;margin-top:12px}
</style>
</head>
<body>
<div class="wrap">
<div class="card">
<h1>SentryIQ Self-Test</h1><div class="note"><strong>Diagnostic build:</strong> <?= htmlspecialchars(SENTRYIQ_DIAGNOSTIC_BUILD, ENT_QUOTES, 'UTF-8') ?></div>
<div class="summary">This diagnostic checks the deployed filesystem/configuration, validates source URL references, and then tests the real browser URLs from this session.</div>
<button id="run" type="button">Run browser checks</button><button id="copy" type="button">Copy report</button>
<p class="note">Browser health checks PASS only on a real 2xx response with the correct content type, response signature where applicable, and final URL. Any 3xx, 4xx, 5xx, or other non-2xx response is FAIL. POST-only or ID-dependent routes are NOT TESTED rather than treated as healthy.</p>
</div>
<div class="card">
<h2>Server-side checks</h2>
<table><thead><tr><th>Group</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>
<?php foreach ($results as $row): ?>
<tr><td><?= htmlspecialchars($row['group'], ENT_QUOTES, 'UTF-8') ?></td><td><?= htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') ?></td><td class="<?= $row['ok'] ? 'ok' : 'bad' ?>"><?= $row['ok'] ? 'PASS' : 'FAIL' ?></td><td><?= htmlspecialchars($row['detail'], ENT_QUOTES, 'UTF-8') ?></td></tr>
<?php endforeach; ?>
</tbody></table>
</div>
<div class="card">
<h2>Browser URL checks</h2>
<div id="browser-summary" class="muted">Not run yet.</div>
<table id="browser-table"><thead><tr><th>Type</th><th>URL</th><th>Status</th><th>HTTP</th><th>Content type</th><th>Final URL</th></tr></thead><tbody></tbody></table>
</div>
<div class="card danger">
<h2>Report</h2>
<pre id="report">Run the browser checks. The full JSON report will appear here.</pre>
</div>
</div>
<script>
const tests=<?= json_encode($browserTests, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>;
const csrf=<?= json_encode($csrf, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>;
let reportData={diagnosticBuild:<?= json_encode(SENTRYIQ_DIAGNOSTIC_BUILD, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>,serverChecks:<?= json_encode($results, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR) ?>,browserChecks:[]};
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));}
async function checkOne(test){
    const started=performance.now();
    const expectedRequestedPath=new URL(test.url,location.href).pathname;
    try{
        const r=await fetch(test.url,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'*/*'}});
        const ms=Math.round(performance.now()-started);
        const contentType=r.headers.get('content-type')||'';
        const statusOk=Number.isInteger(r.status)&&r.status>=200&&r.status<300;
        const finalUrl=new URL(r.url,location.href);
        const expectedFinalPath=test.expectedFinalPath?new URL(test.expectedFinalPath,location.href).pathname:expectedRequestedPath;
        const finalPathOk=finalUrl.pathname===expectedFinalPath;
        const contentTypeOk=!test.expectedContentType||contentType.toLowerCase().startsWith(test.expectedContentType.toLowerCase());

        let stylesheetOk=true;
        let stylesheetDetail=null;
        if(statusOk&&(test.expectedStylesheet||test.parseCss)){
            try{
                const stylesheetUrl=test.expectedStylesheet||test.url;
                const sr=await fetch(stylesheetUrl,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'text/css,*/*'}});
                const st=sr.headers.get('content-type')||'';
                const styleText=await sr.text();
                stylesheetDetail={status:sr.status,statusOk:sr.status>=200&&sr.status<300,contentType:st,contentTypeOk:st.toLowerCase().startsWith('text/css'),url:sr.url,bytes:styleText.length,parseOk:false,ruleCount:0,contracts:[]};
                stylesheetOk=stylesheetOk&&stylesheetDetail.statusOk&&stylesheetDetail.contentTypeOk&&styleText.trim().length>0;
                if(stylesheetOk){
                    const probe=document.createElement('style');
                    probe.textContent=styleText;
                    document.head.appendChild(probe);
                    const rules=probe.sheet&&probe.sheet.cssRules?Array.from(probe.sheet.cssRules):[];
                    stylesheetDetail.ruleCount=rules.length;
                    stylesheetDetail.parseOk=rules.length>0;
                    stylesheetOk=stylesheetOk&&rules.length>0;

                    for(const contract of (test.expectedCssContracts||[])){
                        const declarationProperty=contract.property.replace(/[A-Z]/g,m=>'-'+m.toLowerCase());
                        let actual='';
                        let found=false;
                        for(const rule of rules){
                            if(rule.type!==CSSRule.STYLE_RULE||typeof rule.selectorText!=='string')continue;
                            if(!rule.selectorText.split(',').map(v=>v.trim()).includes(contract.selector))continue;
                            const value=rule.style.getPropertyValue(declarationProperty).trim();
                            if(value){actual=value;found=true;}
                        }
                        const ok=contract.value!==undefined?actual===contract.value:(contract.not!==undefined?actual!==contract.not:actual!=='');
                        stylesheetDetail.contracts.push({...contract,actual,ok});
                        if(!ok)stylesheetOk=false;
                    }
                    probe.remove();
                }
            }catch(error){
                stylesheetOk=false;
                stylesheetDetail={error:String(error&&error.message||error)};
            }
        }

        let bodySignatureOk=true;
        let bodyBytes=null;
        const htmlReferenceResults=[];
        if(Array.isArray(test.expectedMagic)){
            const buffer=await r.arrayBuffer();
            bodyBytes=new Uint8Array(buffer);
            bodySignatureOk=test.expectedMagic.every((value,index)=>bodyBytes[index]===value);
        }else if(test.type!=='asset'){
            const textBody=await r.text();
            bodySignatureOk=textBody.length>0;
            if(bodySignatureOk&&Array.isArray(test.requiredHtmlRefs)){
                const doc=new DOMParser().parseFromString(textBody,'text/html');
                for(const ref of test.requiredHtmlRefs){
                    let match=null;
                    if(ref.tag==='link')match=Array.from(doc.querySelectorAll('link')).find(el=>{const v=el.getAttribute('href')||'';return ref.value?v===ref.value:(ref.prefix&&v.startsWith(ref.prefix));})||null;
                    else if(ref.tag==='script')match=Array.from(doc.querySelectorAll('script[src]')).find(el=>{const v=el.getAttribute('src')||'';return ref.value?v===ref.value:(ref.prefix&&v.startsWith(ref.prefix));})||null;
                    else if(ref.tag==='img')match=Array.from(doc.querySelectorAll('img[src]')).find(el=>{const v=el.getAttribute('src')||'';return ref.value?v===ref.value:(ref.prefix&&v.startsWith(ref.prefix));})||null;
                    const found=!!match;
                    const actualUrl=match?(match.getAttribute(ref.tag==='link'?'href':'src')||''):'';
                    const resolvedUrl=actualUrl?new URL(actualUrl,location.href).href:'';
                    let urlCheck=null;
                    if(found){
                        try{
                            const ar=await fetch(resolvedUrl,{credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'*/*'}});
                            const at=ar.headers.get('content-type')||'';
                            const expectedType=ref.tag==='link'?'text/css':(ref.tag==='script'?'text/javascript':'image/');
                            const typeOk=ref.tag==='img'?at.toLowerCase().startsWith('image/'):at.toLowerCase().startsWith(expectedType);
                            urlCheck={status:ar.status,statusOk:ar.status>=200&&ar.status<300,contentType:at,contentTypeOk:typeOk,finalUrl:ar.url};
                            if(!(urlCheck.statusOk&&urlCheck.contentTypeOk))bodySignatureOk=false;
                        }catch(error){
                            urlCheck={status:0,statusOk:false,contentType:'',contentTypeOk:false,finalUrl:'',error:String(error&&error.message||error)};
                            bodySignatureOk=false;
                        }
                    }else{
                        bodySignatureOk=false;
                    }
                    htmlReferenceResults.push({...ref,found,actualUrl,resolvedUrl,urlCheck});
                }
            }
        }

        const allOk=statusOk&&contentTypeOk&&finalPathOk&&stylesheetOk&&bodySignatureOk;
        return {...test,ok:allOk,status:r.status,statusText:r.statusText,finalUrl:r.url,timeMs:ms,contentType,stylesheetDetail,htmlReferenceResults,
            checks:{tested:true,statusOk,contentTypeOk,finalPathOk,stylesheetOk,bodySignatureOk,expectedFinalPath}};
    }catch(e){
        return {...test,ok:false,status:0,statusText:String(e&&e.message||e),finalUrl:'',timeMs:Math.round(performance.now()-started),contentType:'',
            stylesheetDetail:null,htmlReferenceResults:[],
            checks:{tested:true,statusOk:false,contentTypeOk:false,finalPathOk:false,stylesheetOk:false,bodySignatureOk:false,expectedFinalPath:expectedRequestedPath}};
    }
}
async function runChecks(){
    const tbody=document.querySelector('#browser-table tbody');
    tbody.innerHTML='';
    document.querySelector('#browser-summary').textContent='Running checks…';
    const out=[];
    for(const test of tests){
        if(test.type==='not-tested'){
            const item={...test,ok:null,status:null,statusText:'NOT TESTED',finalUrl:'',timeMs:0,contentType:'',checks:{tested:false}};
            out.push(item);
            const tr=document.createElement('tr');
            tr.innerHTML='<td>'+esc(item.type)+'</td><td><code>'+esc(item.url)+'</code></td><td class="warn">NOT TESTED</td><td>—</td><td>—</td><td>'+esc(item.reason||'')+'</td>';
            tbody.appendChild(tr);
            continue;
        }
        const item=await checkOne(test);
        out.push(item);
        const tr=document.createElement('tr');
        const statusLabel=item.ok===true?'PASS':'FAIL';
        const statusClass=item.ok===true?'ok':'bad';
        const detail=item.stylesheetDetail?'<br><small>'+esc(JSON.stringify(item.stylesheetDetail))+'</small>':'';
        tr.innerHTML='<td>'+esc(item.type)+'</td><td><code>'+esc(item.url)+'</code></td><td class="'+statusClass+'">'+statusLabel+'</td><td>'+esc(item.status)+' '+esc(item.statusText)+'</td><td>'+esc(item.contentType)+'</td><td>'+esc(item.finalUrl)+detail+'</td>';
        tbody.appendChild(tr);
    }
    reportData.browserChecks=out;
    const failed=out.filter(x=>x.ok===false);
    const notTested=out.filter(x=>x.ok===null);
    document.querySelector('#browser-summary').innerHTML=failed.length
        ? '<span class="bad">'+failed.length+' browser health check(s) failed.</span>'+(notTested.length?' <span class="warn">'+notTested.length+' not tested.</span>':'')
        : '<span class="ok">All '+out.filter(x=>x.ok!==null).length+' browser health checks passed.</span>'+(notTested.length?' <span class="warn">'+notTested.length+' not tested.</span>':'');
    document.querySelector('#report').textContent=JSON.stringify(reportData,null,2);
    try{await fetch(location.pathname,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({diagnostic_log:JSON.stringify(reportData),csrf_token:csrf}).toString()});}catch(_){}
}


document.querySelector('#run').addEventListener('click',runChecks);
document.querySelector('#copy').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(document.querySelector('#report').textContent);document.querySelector('#copy').textContent='Copied';setTimeout(()=>document.querySelector('#copy').textContent='Copy report',1400);}catch(_){}});
</script>
</body>
</html>
