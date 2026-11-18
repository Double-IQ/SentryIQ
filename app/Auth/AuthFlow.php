<?php

declare(strict_types=1);

function sentryiq_try_vault_unlock(string $password): array|false
{
    if ($password === '') return false;
    try {
        $result = vault_unlock($password);
        return is_array($result) ? $result : false;
    } catch (Throwable) {
        // Invalid credentials and malformed/unreadable vault state must follow
        // the same generic failure path so throttling is always applied.
        return false;
    }
}

function sentryiq_get_base_url(): string
{
    $configFile = dirname(__DIR__, 2) . '/sentryiq_config.php';
    $config = is_file($configFile) ? require $configFile : [];
    $baseUrl = is_array($config) ? trim((string)($config['base_url'] ?? '')) : '';
    if (!filter_var($baseUrl, FILTER_VALIDATE_URL)) return '';
    $parts = parse_url($baseUrl);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) return '';
    return rtrim($baseUrl, '/');
}

function sentryiq_throttle_path(): string
{
    return SENTRYIQ_DATA_DIR . '/auth_throttle.json';
}

function sentryiq_throttle_read(): array
{
    if (!ensure_sentryiq_data_directory() || !is_file(sentryiq_throttle_path())) return [];
    $raw = @file_get_contents(sentryiq_throttle_path());
    $data = is_string($raw) ? json_decode($raw, true) : null;
    return is_array($data) ? $data : [];
}

function sentryiq_throttle_write(array $data): void
{
    if (!ensure_sentryiq_data_directory()) return;
    $path = sentryiq_throttle_path();
    $tmp = $path . '.tmp-' . bin2hex(random_bytes(8));
    $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (@file_put_contents($tmp, $json, LOCK_EX) !== false) {
        @chmod($tmp, 0600);
        @rename($tmp, $path);
        @chmod($path, 0600);
    }
}

function sentryiq_throttle_key(string $scope, string $ip): string
{
    return hash('sha256', $scope . '|' . $ip);
}

function sentryiq_throttle_blocked(string $scope, string $ip, int $limit, int $window): bool
{
    $now = time();
    $data = sentryiq_throttle_read();
    $key = sentryiq_throttle_key($scope, $ip);
    $entry = $data[$key] ?? ['count'=>0,'first'=>0,'locked_until'=>0];

    if ((int)($entry['locked_until'] ?? 0) > $now) return true;
    if ((int)($entry['first'] ?? 0) === 0 || ($now - (int)$entry['first']) > $window) return false;
    return (int)($entry['count'] ?? 0) >= $limit;
}

function sentryiq_throttle_failure(string $scope, string $ip, int $limit, int $window, int $lockout): void
{
    $now = time();
    $data = sentryiq_throttle_read();
    $key = sentryiq_throttle_key($scope, $ip);
    $entry = $data[$key] ?? ['count'=>0,'first'=>$now,'locked_until'=>0];
    if (($now - (int)($entry['first'] ?? 0)) > $window) $entry = ['count'=>0,'first'=>$now,'locked_until'=>0];
    $entry['count'] = (int)$entry['count'] + 1;
    if ($entry['count'] >= $limit) $entry['locked_until'] = $now + $lockout;
    $data[$key] = $entry;
    sentryiq_throttle_write($data);
}

function sentryiq_throttle_clear(string $scope, string $ip): void
{
    $data = sentryiq_throttle_read();
    unset($data[sentryiq_throttle_key($scope, $ip)]);
    sentryiq_throttle_write($data);
}

function sentryiq_get_system_config(array $records): array
{
    foreach ($records as $entry) {
        if (($entry['type'] ?? '') === 'system_config') return $entry;
    }
    return [];
}

$decryption_failed = false;
$error_step_2 = '';
$recovery_failed = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['recovery_login'])) {
    sentryiq_require_csrf();
    $ip = get_visitor_ip();
    if (sentryiq_throttle_blocked('recovery', $ip, 5, 900)) {
        $recovery_failed = true;
    } else {
        $recoveryKey = (string)($_POST['recovery_key'] ?? '');
        try {
            $parts = vault_read_envelope();
            $vmk = vault_unwrap_vmk_with_recovery_key($parts['envelope'], $recoveryKey);
        } catch (Throwable) {
            $vmk = false;
        }
        if ($vmk === false) {
            sentryiq_throttle_failure('recovery', $ip, 5, 900, 900);
            log_security_event('FAILED_VAULT_RECOVERY', $ip, 'unknown', ['stage'=>'recovery_key']);
            $recovery_failed = true;
        } else {
            $records = load_passwords($vmk);
            if ($records === false) {
                sentryiq_throttle_failure('recovery', $ip, 5, 900, 900);
                log_security_event('FAILED_VAULT_RECOVERY', $ip, 'unknown', ['stage'=>'recovery_decrypt']);
                $recovery_failed = true;
            } else {
                $system = sentryiq_get_system_config($records);
                $username = trim((string)($system['app_username'] ?? 'unknown')) ?: 'unknown';
                sentryiq_throttle_clear('recovery', $ip);
                sentryiq_mark_authenticated($vmk, $username);
                log_security_event('SUCCESSFUL_VAULT_RECOVERY', $ip, $username, ['stage'=>'recovery_key']);
                header('Location: welcome.php');
                exit;
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_step_1'])) {
    sentryiq_require_csrf();

    if (sentryiq_pending_auth_expired()) sentryiq_clear_pending_auth();

    $ip = get_visitor_ip();
    if (sentryiq_throttle_blocked('master', $ip, 5, 900)) {
        $decryption_failed = true;
    } else {
        $password = (string)($_POST['master_password'] ?? '');
        $unlocked = sentryiq_try_vault_unlock($password);
        if ($unlocked === false) {
            sentryiq_throttle_failure('master', $ip, 5, 900, 900);
            log_security_event('FAILED_MASTER_PASSWORD', $ip, 'unknown', ['stage'=>'master_password']);
            $decryption_failed = true;
        } else {
            sentryiq_throttle_clear('master', $ip);
            $records = $unlocked['records'];
            $system = sentryiq_get_system_config($records);
            $username = trim((string)($system['app_username'] ?? 'unknown')) ?: 'unknown';
            $email = filter_var(trim((string)($system['2fa_email'] ?? TWO_FA_EMAIL)), FILTER_VALIDATE_EMAIL);
            $baseUrl = sentryiq_get_base_url();

            if (!$email || $baseUrl === '') {
                $decryption_failed = true;
                log_security_event('AUTH_CONFIGURATION_INVALID', $ip, $username);
            } else {
                $twoFaCode = str_pad((string)random_int(100000, 999999), 6, '0', STR_PAD_LEFT);
                $copyToken = bin2hex(random_bytes(32));
                $expires = time() + 300;
                $tokenPath = SENTRYIQ_DATA_DIR . '/token_' . $copyToken . '.json';
                $tokenJson = json_encode(['code'=>$twoFaCode,'expires'=>$expires], JSON_UNESCAPED_SLASHES);

                $handle = @fopen($tokenPath, 'xb');
                if ($handle === false) {
                    $decryption_failed = true;
                } else {
                    @chmod($tokenPath, 0600);
                    $ok = fwrite($handle, $tokenJson) === strlen($tokenJson);
                    if (function_exists('fflush')) fflush($handle);
                    if (function_exists('fsync')) @fsync($handle);
                    fclose($handle);

                    if (!$ok) {
                        @unlink($tokenPath);
                        $decryption_failed = true;
                    } else {
                        $_SESSION['pending_key'] = $unlocked['key'];
                        $_SESSION['pending_username'] = $username;
                        $_SESSION['two_fa_code'] = $twoFaCode;
                        $_SESSION['copy_code_token'] = $copyToken;
                        $_SESSION['pending_started_at'] = time();
                        $_SESSION['two_fa_attempts'] = 0;

                        $copyUrl = $baseUrl . '/copy-code.php?t=' . rawurlencode($copyToken);
                        $safeCopyUrl = htmlspecialchars($copyUrl, ENT_QUOTES, 'UTF-8');
                        $safeCode = htmlspecialchars($twoFaCode, ENT_QUOTES, 'UTF-8');
                        $htmlMessage = '<html><body style="margin:0;padding:30px;background:#f4f6f9;font-family:Arial,sans-serif;"><div style="max-width:500px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;border:1px solid #e1e4e8;"><h2 style="color:#1a1a1a;">🔒 SentryIQ Vault Access</h2><p>Your temporary verification code is:</p><div style="font-size:34px;font-weight:bold;letter-spacing:7px;margin:25px 0;color:#0066cc;">' . $safeCode . '</div><p>This code expires in <strong>5 minutes</strong>.</p><p><a href="' . $safeCopyUrl . '" style="display:inline-block;background:#0066cc;color:#fff;text-decoration:none;padding:12px 24px;border-radius:5px;font-weight:bold;">📋 Copy Code</a></p><p style="font-size:12px;color:#777;">If you did not request access, ignore this message.</p></div></body></html>';

                        $host = parse_url($baseUrl, PHP_URL_HOST);
                        $sender = 'security@' . $host;
                        $headers = "MIME-Version: 1.0\r\n" .
                            "Content-Type: text/html; charset=UTF-8\r\n" .
                            "From: SentryIQ Security <" . $sender . ">\r\n" .
                            "Reply-To: " . $sender . "\r\n";

                        if (!mail($email, 'SentryIQ Vault Access: 2FA Code', $htmlMessage, $headers)) {
                            sentryiq_clear_pending_auth();
                            @unlink($tokenPath);
                            log_security_event('EMAIL_SERVER_REJECTED_SEND', $ip, $username, ['stage'=>'master_password']);
                            $decryption_failed = true;
                        } else {
                            log_security_event('2FA_CHALLENGE_SENT', $ip, $username, ['stage'=>'master_password']);
                        }
                    }
                }
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_step_2'])) {
    sentryiq_require_csrf();

    $ip = get_visitor_ip();
    $username = (string)($_SESSION['pending_username'] ?? 'unknown');

    if (sentryiq_pending_auth_expired()) {
        sentryiq_clear_pending_auth();
        log_security_event('EXPIRED_2FA_ATTEMPT', $ip, $username, ['stage'=>'2fa']);
        $error_step_2 = 'Verification window expired. Restart the login process.';
    } elseif (sentryiq_throttle_blocked('2fa', $ip, 5, 900)) {
        sentryiq_clear_pending_auth();
        $error_step_2 = 'Too many verification failures. Restart the login process later.';
    } else {
        $code = trim((string)($_POST['verification_code'] ?? ''));
        $expected = (string)($_SESSION['two_fa_code'] ?? '');
        if ($expected !== '' && hash_equals($expected, $code)) {
            $key = (string)$_SESSION['pending_key'];
            sentryiq_throttle_clear('2fa', $ip);
            sentryiq_mark_authenticated($key, $username);
            log_security_event('SUCCESSFUL_VAULT_LOGIN', $ip, $username, ['stage'=>'2fa']);
            header('Location: welcome.php');
            exit;
        }

        $attempts = (int)($_SESSION['two_fa_attempts'] ?? 0) + 1;
        $_SESSION['two_fa_attempts'] = $attempts;
        sentryiq_throttle_failure('2fa', $ip, 5, 900, 900);
        log_security_event('FAILED_2FA_CODE', $ip, $username, ['stage'=>'2fa']);
        $error_step_2 = $attempts >= 5 ? 'Too many verification failures. Restart the login process later.' : 'Invalid verification code.';
    }
}
