<?php

declare(strict_types=1);

const SENTRYIQ_IDLE_TIMEOUT = 900;
const SENTRYIQ_FRESH_AUTH_WINDOW = 300;
const SENTRYIQ_ABSOLUTE_SESSION_TIMEOUT = 43200;

function sentryiq_path_is_outside_document_root(string $path): bool
{
    if ($path === '' || !str_starts_with($path, '/') || is_link($path)) return false;
    $realPath = realpath($path);
    if ($realPath === false || rtrim($realPath, DIRECTORY_SEPARATOR) !== rtrim($path, DIRECTORY_SEPARATOR)) return false;

    $documentRoot = trim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
    if ($documentRoot === '') return PHP_SAPI === 'cli';
    $realDocumentRoot = realpath($documentRoot);
    if ($realDocumentRoot === false || !is_dir($realDocumentRoot)) return false;

    $root = rtrim($realDocumentRoot, DIRECTORY_SEPARATOR);
    $target = rtrim($realPath, DIRECTORY_SEPARATOR);
    if ($root === '') $root = DIRECTORY_SEPARATOR;
    if (DIRECTORY_SEPARATOR === '\\') {
        $root = strtolower($root);
        $target = strtolower($target);
    }
    $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return $target !== $root && !str_starts_with($target, $prefix);
}

function sentryiq_data_dir(): string
{
    if (defined('SENTRYIQ_DATA_DIR')
        && is_dir(SENTRYIQ_DATA_DIR)
        && sentryiq_path_is_outside_document_root(SENTRYIQ_DATA_DIR)) {
        return SENTRYIQ_DATA_DIR;
    }

    $configFile = dirname(__DIR__, 2) . '/sentryiq_config.php';
    if (!is_file($configFile) || is_link($configFile)) {
        return '';
    }

    $config = require $configFile;
    if (!is_array($config)) {
        return '';
    }

    $dataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
    if ($dataDir === ''
        || !str_starts_with($dataDir, '/')
        || !is_dir($dataDir)
        || !sentryiq_path_is_outside_document_root($dataDir)) {
        return '';
    }

    if (!defined('SENTRYIQ_DATA_DIR')) {
        define('SENTRYIQ_DATA_DIR', $dataDir);
    }

    return SENTRYIQ_DATA_DIR;
}

function sentryiq_has_registered_passkey(): bool
{
    $dataDir = sentryiq_data_dir();
    if ($dataDir === '') return false;
    $path = $dataDir . '/passkeys.json';
    if (!is_file($path) || is_link($path)) return false;
    $raw = @file_get_contents($path);
    $records = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($records)) return false;
    $credentials = $records['credentials'] ?? null;
    return is_array($credentials) && $credentials !== [];
}

function sentryiq_brand_base_url(): string
{
    $host = trim((string)($_SERVER['SERVER_NAME'] ?? ''));
    if ($host === '' || !preg_match('/^[A-Za-z0-9.-]+$/', $host)) return '';

    $scriptPath = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? ''));
    $directory = rtrim(str_replace('\\', '/', dirname($scriptPath)), '/');
    if ($directory === '.' || $directory === '/') $directory = '';

    return 'https://' . $host . $directory;
}

function sentryiq_brand_head_inject(string $buffer): string
{
    if (stripos($buffer, '</head>') === false) return $buffer;
    if (stripos($buffer, 'sentryiq-icon.php') !== false && stripos($buffer, 'og:image') !== false) return $buffer;

    $baseUrl = sentryiq_brand_base_url();
    $assetUrl = ($baseUrl !== '' ? $baseUrl : '') . '/sentryiq-icon.php';

    $tags = "\n" .
        '<link rel="icon" type="image/png" href="' . htmlspecialchars($assetUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n" .
        '<link rel="apple-touch-icon" href="' . htmlspecialchars($assetUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n" .
        '<meta property="og:type" content="website">' . "\n" .
        '<meta property="og:site_name" content="SentryIQ">' . "\n" .
        '<meta property="og:title" content="SentryIQ">' . "\n" .
        '<meta property="og:description" content="SentryIQ secure digital vault.">' . "\n" .
        '<meta property="og:image" content="' . htmlspecialchars($assetUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n" .
        '<meta property="og:image:alt" content="SentryIQ secure digital vault icon">' . "\n" .
        '<meta name="twitter:card" content="summary_large_image">' . "\n" .
        '<meta name="twitter:title" content="SentryIQ">' . "\n" .
        '<meta name="twitter:description" content="SentryIQ secure digital vault.">' . "\n" .
        '<meta name="twitter:image" content="' . htmlspecialchars($assetUrl, ENT_QUOTES, 'UTF-8') . '">' . "\n";

    if (stripos($buffer, 'id="gallery-upload-form"') !== false && stripos($buffer, 'safari.js') === false) {
        $tags .= '<script src="assets/js/safari.js"></script>' . "\n";
    }

    return str_ireplace('</head>', $tags . '</head>', $buffer);
}

function sentryiq_authenticated_session_expired(array $session, int $now): bool
{
    if (!isset($session['master_key']) || !is_string($session['master_key']) || strlen($session['master_key']) !== 32) {
        return false;
    }
    $authenticatedAt = (int)($session['authenticated_at'] ?? 0);
    $lastActivity = (int)($session['last_activity'] ?? 0);
    if ($authenticatedAt <= 0 || $authenticatedAt > $now + 5 || ($now - $authenticatedAt) > SENTRYIQ_ABSOLUTE_SESSION_TIMEOUT) {
        return true;
    }
    return $lastActivity <= 0 || $lastActivity > $now + 5 || ($now - $lastActivity) > SENTRYIQ_IDLE_TIMEOUT;
}

function sentryiq_security_bootstrap(): void
{
    $dataDir = sentryiq_data_dir();

    if (PHP_SAPI !== 'cli' && (($_SERVER['HTTPS'] ?? '') !== 'on' && (string)($_SERVER['SERVER_PORT'] ?? '') !== '443')) {
        http_response_code(400);
        exit('SentryIQ requires HTTPS.');
    }

    if (session_status() !== PHP_SESSION_ACTIVE) {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.cookie_secure', '1');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.cookie_path', '/');

        session_set_cookie_params([
            'lifetime' => 0,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['lock_vault'])) {
        sentryiq_require_csrf();
        sentryiq_require_auth();

        if ($dataDir !== '' && is_file($dataDir . '/vault_engine.php') && !is_link($dataDir . '/vault_engine.php')) {
            require_once $dataDir . '/vault_engine.php';
        }

        if (function_exists('log_security_event')) {
            log_security_event('VAULT_LOCKED', get_visitor_ip(), $_SESSION['app_username'] ?? 'unknown');
        }

        sentryiq_lock_vault();
        header('Location: index.php');
        exit;
    }

    set_exception_handler(static function (Throwable $exception): void {
        error_log('SentryIQ runtime failure: ' . $exception::class . ': ' . $exception->getMessage());
        http_response_code(500);
        exit('SentryIQ encountered a security failure.');
    });

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header("Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'");

    $script = basename((string)($_SERVER['SCRIPT_FILENAME'] ?? ''));
    $passkeyPath = $script === 'passkey.php' || $script === 'passkey_login.php' || $script === 'passkey_setup.php' || $script === 'passkey_auth.php';
    $passwordFallback = isset($_GET['password']) && $_GET['password'] === '1';

    if (!$passkeyPath && !$passwordFallback && $script === 'index.php') {
        $authenticated = isset($_SESSION['master_key']) && is_string($_SESSION['master_key']) && strlen($_SESSION['master_key']) === 32;
        if ($authenticated && !sentryiq_has_registered_passkey()) {
            header('Location: passkey_setup.php');
            exit;
        }
        if (!$authenticated && sentryiq_has_registered_passkey()) {
            header('Location: passkey_login.php');
            exit;
        }
    }

    if (isset($_SESSION['master_key'])) {
        if (sentryiq_authenticated_session_expired($_SESSION, time())) {
            sentryiq_lock_vault();
            return;
        }
        $_SESSION['last_activity'] = time();
    }

    ob_start('sentryiq_brand_head_inject');
}

function sentryiq_lock_vault(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'] ?? '', (bool)$params['secure'], (bool)$params['httponly']);
    }
    if (session_status() === PHP_SESSION_ACTIVE) session_destroy();
}

function sentryiq_csrf_token(): string
{
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function sentryiq_require_csrf(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit('Method not allowed.');
    }

    $postMax = trim((string)ini_get('post_max_size'));
    $contentLength = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($postMax !== '' && $contentLength > 0) {
        $last = strtolower(substr($postMax, -1));
        $number = (float)$postMax;
        $multiplier = match ($last) {
            'g' => 1024 * 1024 * 1024,
            'm' => 1024 * 1024,
            'k' => 1024,
            default => 1,
        };
        $postMaxBytes = (int)round($number * $multiplier);
        if ($postMaxBytes > 0 && $contentLength > $postMaxBytes && empty($_POST) && empty($_FILES)) {
            http_response_code(413);
            exit('Upload too large for the server.');
        }
    }

    $provided = (string)($_POST['csrf_token'] ?? '');
    if ($provided === '') {
        $provided = trim((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''));
    }

    $expected = (string)($_SESSION['csrf_token'] ?? '');
    if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
        http_response_code(403);
        exit('Security validation failed.');
    }
}

function sentryiq_require_auth(): void
{
    if (!isset($_SESSION['master_key']) || !is_string($_SESSION['master_key']) || strlen($_SESSION['master_key']) !== 32) {
        $isAjax = strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest';
        $acceptsJson = str_contains(strtolower((string)($_SERVER['HTTP_ACCEPT'] ?? '')), 'application/json');

        if (!$isAjax && !$acceptsJson && $_SERVER['REQUEST_METHOD'] === 'GET') {
            header('Location: index.php');
            exit;
        }

        http_response_code(403);
        exit('Authentication required.');
    }
}

function sentryiq_require_fresh_auth(): void
{
    sentryiq_require_auth();
    $authenticatedAt = (int)($_SESSION['authenticated_at'] ?? 0);
    if ($authenticatedAt <= 0 || (time() - $authenticatedAt) > SENTRYIQ_FRESH_AUTH_WINDOW) {
        http_response_code(403);
        exit('Fresh authentication required. Lock and unlock the vault again.');
    }
}

function sentryiq_mark_authenticated(string $key, string $username): void
{
    if (strlen($key) !== 32) throw new RuntimeException('Invalid vault key.');
    session_regenerate_id(true);
    $_SESSION['master_key'] = $key;
    $_SESSION['app_username'] = $username;
    $_SESSION['authenticated_at'] = time();
    $_SESSION['last_activity'] = time();
    unset($_SESSION['pending_key'], $_SESSION['pending_username'], $_SESSION['two_fa_code'], $_SESSION['copy_code_token'], $_SESSION['pending_started_at'], $_SESSION['two_fa_attempts']);
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

function sentryiq_clear_pending_auth(): void
{
    unset($_SESSION['pending_key'], $_SESSION['pending_username'], $_SESSION['two_fa_code'], $_SESSION['copy_code_token'], $_SESSION['pending_started_at'], $_SESSION['two_fa_attempts']);
}

function sentryiq_pending_auth_expired(): bool
{
    $started = (int)($_SESSION['pending_started_at'] ?? 0);
    return $started <= 0 || (time() - $started) > 300;
}

function cleanup_expired_tokens(): void
{
    $dataDir = sentryiq_data_dir();
    if (!isset($_SESSION) || $dataDir === '') return;
    $now = time();
    $tokenFiles = glob($dataDir . '/token_*.json') ?: [];
    usort($tokenFiles, static fn(string $left, string $right): int => (int)@filemtime($left) <=> (int)@filemtime($right));
    foreach (array_slice($tokenFiles, 0, 200) as $file) {
        if (is_link($file) || !is_file($file)) continue;
        $raw = @file_get_contents($file);
        $token = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($token) || (int)($token['expires'] ?? 0) <= $now) {
            @unlink($file);
        }
    }
    $claimedFiles = glob($dataDir . '/consumed_*.token') ?: [];
    usort($claimedFiles, static fn(string $left, string $right): int => (int)@filemtime($left) <=> (int)@filemtime($right));
    foreach (array_slice($claimedFiles, 0, 200) as $file) {
        if (is_link($file) || !is_file($file)) continue;
        $modified = @filemtime($file);
        if (is_int($modified) && $modified <= $now - 600) {
            @unlink($file);
        }
    }
}
