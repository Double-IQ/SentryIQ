<?php
/**
 * SentryIQ - Vault Security Engine
 *
 * Fresh-install vault format only. Legacy vault migration is intentionally not
 * supported by this release.
 */

declare(strict_types=1);

$configFile = __DIR__ . '/sentryiq_config.php';
$config = is_file($configFile) ? require $configFile : [];
if (!is_array($config)) {
    throw new RuntimeException('Invalid SentryIQ secure configuration.');
}

$configuredDataDir = trim((string)($config['data_dir'] ?? ''));
if ($configuredDataDir === '' || !str_starts_with($configuredDataDir, '/')) {
    throw new RuntimeException('SentryIQ secure data directory is not configured.');
}

if (!defined('SENTRYIQ_DATA_DIR')) {
    define('SENTRYIQ_DATA_DIR', rtrim($configuredDataDir, '/'));
}
define('DATA_FILE', SENTRYIQ_DATA_DIR . '/passwords.enc');
define('LOG_FILE', SENTRYIQ_DATA_DIR . '/security_audit.log');
define('DIAGNOSTIC_LOG_FILE', SENTRYIQ_DATA_DIR . '/diagnostic.log');
define('TWO_FA_EMAIL', trim((string)($config['two_fa_email'] ?? '')));
define('TWO_FA_TOKEN_LIFETIME', 300);
define('SENTRYIQ_VAULT_VERSION', 3);
define('SENTRYIQ_KEY_WRAP_VERSION', 1);
define('SENTRYIQ_KDF_OPSLIMIT', 3);
define('SENTRYIQ_KDF_MEMLIMIT', 32 * 1024 * 1024);
define('SENTRYIQ_GCM_NONCE_BYTES', 12);
define('SENTRYIQ_GCM_TAG_BYTES', 16);

function sentryiq_is_trusted_data_directory(?string $directory = null): bool
{
    $directory ??= SENTRYIQ_DATA_DIR;
    $directory = rtrim($directory, '/');

    if ($directory === '' || !str_starts_with($directory, '/')) {
        throw new RuntimeException('trusted_directory:invalid_path');
    }
    if (!is_dir($directory)) {
        throw new RuntimeException('trusted_directory:not_directory');
    }
    if (is_link($directory)) {
        throw new RuntimeException('trusted_directory:is_symlink');
    }

    $real = realpath($directory);
    if ($real === false) {
        throw new RuntimeException('trusted_directory:realpath_failed');
    }
    if (rtrim($real, '/') !== $directory) {
        throw new RuntimeException('trusted_directory:realpath_mismatch');
    }
    if (function_exists('sentryiq_path_is_outside_document_root')
        && !sentryiq_path_is_outside_document_root($directory)) {
        throw new RuntimeException('trusted_directory:inside_document_root');
    }

    $perms = @fileperms($directory);
    if ($perms === false) {
        throw new RuntimeException('trusted_directory:fileperms_failed');
    }
    if (($perms & 0077) !== 0) {
        throw new RuntimeException('trusted_directory:permissions_not_private');
    }

    if (!is_writable($directory)) {
        throw new RuntimeException('trusted_directory:not_writable');
    }

    return true;
}

function ensure_sentryiq_data_directory(): bool
{
    return sentryiq_is_trusted_data_directory();
}

function get_visitor_ip(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return filter_var(trim($ip), FILTER_VALIDATE_IP) ?: '0.0.0.0';
}

function log_security_event(string $eventType, string $ipAddress, ?string $username = null, array $context = []): void
{
    if (!ensure_sentryiq_data_directory()) return;

    $event = [
        'timestamp' => date('c'),
        'event' => $eventType,
        'username' => $username ?? ($_SESSION['app_username'] ?? 'unknown'),
        'ip' => $ipAddress,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'context' => $context,
    ];

    @file_put_contents(
        LOG_FILE,
        json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL,
        FILE_APPEND | LOCK_EX
    );
    @chmod(LOG_FILE, 0600);
}

function read_security_log(): array
{
    if (!is_file(LOG_FILE) || is_link(LOG_FILE)) return [];

    $lines = @file(LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) return [];

    $events = [];

    foreach (array_reverse($lines) as $line) {
        $decoded = json_decode($line, true);

        if (!is_array($decoded)) {
            continue;
        }

        if (
            !isset($decoded['timestamp']) ||
            !is_string($decoded['timestamp']) ||
            !isset($decoded['event']) ||
            !is_string($decoded['event']) ||
            trim($decoded['event']) === ''
        ) {
            continue;
        }

        if (
            !array_key_exists('username', $decoded) ||
            !array_key_exists('ip', $decoded) ||
            !array_key_exists('user_agent', $decoded)
        ) {
            continue;
        }

        $events[] = $decoded;
    }

    return $events;
}

function vault_validate_url(string $url): string|false
{
    $url = trim($url);
    if ($url === '') return '';
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;

    $parts = parse_url($url);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') return false;
    if (empty($parts['host'])) return false;
    if (isset($parts['user']) || isset($parts['pass'])) return false;

    return $url;
}

function normalize_vault_records(array $records): array
{
    $normalized = [];

    foreach ($records as $record) {
        if (!is_array($record)) continue;

        if (($record['type'] ?? '') === 'system_config') {
            $categories = is_array($record['categories'] ?? null)
                ? array_values(array_unique(array_filter(
                    array_map(static fn($value): string => trim((string)$value), $record['categories']),
                    static fn(string $value): bool => $value !== ''
                )))
                : [];

            $folders = [];
            if (is_array($record['folders'] ?? null)) {
                foreach ($record['folders'] as $folderCategory => $folderList) {
                    if (!is_string($folderCategory) || !is_array($folderList)) continue;

                    $cleanFolders = array_values(array_unique(array_filter(
                        array_map(static fn($value): string => trim((string)$value), $folderList),
                        static fn(string $value): bool => $value !== ''
                    )));

                    if ($cleanFolders !== []) {
                        $folders[trim($folderCategory)] = $cleanFolders;
                    }
                }
            }

            $normalized[] = [
                'id' => 'sys_config_node',
                'type' => 'system_config',
                'app_username' => trim((string)($record['app_username'] ?? '')),
                '2fa_email' => trim((string)($record['2fa_email'] ?? '')),
                'imap_password' => (string)($record['imap_password'] ?? ''),
                'categories' => $categories,
                'folders' => $folders,
            ];
            continue;
        }

        if (!array_key_exists('label', $record)) continue;
        $id = isset($record['id']) && is_scalar($record['id']) ? trim((string)$record['id']) : '';
        if ($id === '') $id = bin2hex(random_bytes(16));

        $url = vault_validate_url((string)($record['url'] ?? ''));
        if ($url === false) $url = '';

        $normalized[] = [
            'id' => $id,
            'label' => trim((string)($record['label'] ?? '')),
            'category' => trim((string)($record['category'] ?? '')),
            'folder' => trim((string)($record['folder'] ?? '')),
            'username' => trim((string)($record['username'] ?? '')),
            'password' => (string)($record['password'] ?? ''),
            'url' => $url,
            'notes' => trim((string)($record['notes'] ?? '')),
            'created_at' => $record['created_at'] ?? null,
            'updated_at' => $record['updated_at'] ?? null,
            'icon_type' => $record['icon_type'] ?? null,
            'icon_path' => $record['icon_path'] ?? null,
            'icon_source' => $record['icon_source'] ?? null,
            'icon_fetched_at' => $record['icon_fetched_at'] ?? null,
        ];
    }

    return array_values($normalized);
}

function vault_kdf_metadata(string $salt, int $opslimit = SENTRYIQ_KDF_OPSLIMIT, int $memlimit = SENTRYIQ_KDF_MEMLIMIT): array
{
    return [
        'name' => 'argon2id13',
        'opslimit' => $opslimit,
        'memlimit' => $memlimit,
        'salt' => base64_encode($salt),
    ];
}

function vault_derive_key(string $password, string $salt, int $opslimit, int $memlimit): string
{
    if (!function_exists('sodium_crypto_pwhash')) {
        throw new RuntimeException('Sodium is required for SentryIQ vault key derivation.');
    }
    if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        throw new RuntimeException('Invalid vault KDF salt.');
    }
    if ($opslimit < SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE || $memlimit < 19 * 1024 * 1024) {
        throw new RuntimeException('Vault KDF parameters are too weak.');
    }

    $key = sodium_crypto_pwhash(
        32,
        $password,
        $salt,
        $opslimit,
        $memlimit,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    if (!is_string($key) || strlen($key) !== 32) {
        throw new RuntimeException('Vault key derivation failed.');
    }

    return $key;
}

function vault_build_aad(array $kdf): string
{
    $metadata = [
        'version' => SENTRYIQ_VAULT_VERSION,
        'kdf' => $kdf,
        'cipher' => [
            'name' => 'aes-256-gcm',
            'nonce_bytes' => SENTRYIQ_GCM_NONCE_BYTES,
            'tag_bytes' => SENTRYIQ_GCM_TAG_BYTES,
        ],
    ];

    return (string)json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function vault_decode_base64(string $value, int $exactLength = 0): string|false
{
    $decoded = base64_decode($value, true);
    if ($decoded === false) return false;
    if ($exactLength > 0 && strlen($decoded) !== $exactLength) return false;
    return $decoded;
}

function vault_read_envelope(): array|false
{
    clearstatcache(true, DATA_FILE);

    try {
        ensure_sentryiq_data_directory();
    } catch (Throwable $exception) {
        throw new RuntimeException('vault_read_envelope:' . $exception->getMessage());
    }
    if (!is_file(DATA_FILE)) throw new RuntimeException('vault_read_envelope:data_file_missing');
    if (is_link(DATA_FILE)) throw new RuntimeException('vault_read_envelope:data_file_symlink');

    $raw = @file_get_contents(DATA_FILE);
    if (!is_string($raw) || $raw === '' || strlen($raw) > 32 * 1024 * 1024) {
        throw new RuntimeException('vault_read_envelope:raw_file_invalid');
    }

    try {
        $envelope = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable $exception) {
        throw new RuntimeException('vault_read_envelope:json_decode_failed');
    }
    if (!is_array($envelope)) throw new RuntimeException('vault_read_envelope:envelope_not_array');
    if (($envelope['version'] ?? null) !== SENTRYIQ_VAULT_VERSION) throw new RuntimeException('vault_read_envelope:version_invalid');
    if (!isset($envelope['kdf']) || !is_array($envelope['kdf'])) throw new RuntimeException('vault_read_envelope:kdf_invalid');
    if (($envelope['kdf']['name'] ?? '') !== 'argon2id13') throw new RuntimeException('vault_read_envelope:kdf_name_invalid');
    if (!isset($envelope['cipher']) || !is_array($envelope['cipher'])) throw new RuntimeException('vault_read_envelope:cipher_invalid');
    if (($envelope['cipher']['name'] ?? '') !== 'aes-256-gcm') throw new RuntimeException('vault_read_envelope:cipher_name_invalid');
    if (($envelope['cipher']['nonce_bytes'] ?? null) !== SENTRYIQ_GCM_NONCE_BYTES) throw new RuntimeException('vault_read_envelope:nonce_bytes_invalid');
    if (($envelope['cipher']['tag_bytes'] ?? null) !== SENTRYIQ_GCM_TAG_BYTES) throw new RuntimeException('vault_read_envelope:tag_bytes_invalid');

    $salt = vault_decode_base64((string)($envelope['kdf']['salt'] ?? ''), SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = vault_decode_base64((string)($envelope['nonce'] ?? ''), SENTRYIQ_GCM_NONCE_BYTES);
    $tag = vault_decode_base64((string)($envelope['tag'] ?? ''), SENTRYIQ_GCM_TAG_BYTES);
    $ciphertext = vault_decode_base64((string)($envelope['ciphertext'] ?? ''));
    $aadStored = vault_decode_base64((string)($envelope['aad'] ?? ''));

    if ($salt === false) throw new RuntimeException('vault_read_envelope:salt_invalid');
    if ($nonce === false) throw new RuntimeException('vault_read_envelope:nonce_invalid');
    if ($tag === false) throw new RuntimeException('vault_read_envelope:tag_invalid');
    if ($ciphertext === false) throw new RuntimeException('vault_read_envelope:ciphertext_invalid');
    if ($aadStored === false) throw new RuntimeException('vault_read_envelope:aad_invalid');

    $kdfName = (string)($envelope['kdf']['name'] ?? '');
    $opslimit = (int)($envelope['kdf']['opslimit'] ?? 0);
    $memlimit = (int)($envelope['kdf']['memlimit'] ?? 0);
    if ($kdfName !== 'argon2id13') throw new RuntimeException('vault_read_envelope:kdf_name_invalid_after_decode');
    if ($opslimit < SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE) throw new RuntimeException('vault_read_envelope:opslimit_invalid');
    if ($memlimit < 19 * 1024 * 1024) throw new RuntimeException('vault_read_envelope:memlimit_invalid');

    $kdf = [
        'name' => $kdfName,
        'opslimit' => $opslimit,
        'memlimit' => $memlimit,
        'salt' => base64_encode($salt),
    ];

    return [
        'envelope' => $envelope,
        'salt' => $salt,
        'kdf' => $kdf,
        'nonce' => $nonce,
        'tag' => $tag,
        'ciphertext' => $ciphertext,
        'aad' => $aadStored,
    ];
}

function vault_build_key_wrap_aad(): string
{
    return 'SentryIQ VMK password wrap v1';
}

function vault_wrap_vmk_with_password(string $vmk, string $password, array $kdf): array
{
    if (strlen($vmk) !== 32) throw new RuntimeException('Invalid Vault Master Key.');
    $salt = vault_decode_base64((string)($kdf['salt'] ?? ''), SODIUM_CRYPTO_PWHASH_SALTBYTES);
    if ($salt === false) throw new RuntimeException('Invalid Vault KDF salt.');
    $key = vault_derive_key($password, $salt, (int)$kdf['opslimit'], (int)$kdf['memlimit']);
    $aad = vault_build_key_wrap_aad();
    $nonce = random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $tag = '';
    $ciphertext = openssl_encrypt($vmk, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, SENTRYIQ_GCM_TAG_BYTES);
    if ($ciphertext === false || strlen($tag) !== SENTRYIQ_GCM_TAG_BYTES) throw new RuntimeException('Unable to protect the Vault Master Key.');
    return ['version'=>SENTRYIQ_KEY_WRAP_VERSION,'cipher'=>'aes-256-gcm','aad'=>base64_encode($aad),'nonce'=>base64_encode($nonce),'tag'=>base64_encode($tag),'ciphertext'=>base64_encode($ciphertext)];
}

function vault_unwrap_vmk_with_password(array $envelope, string $password): string|false
{
    $kdf = $envelope['kdf'] ?? null;
    $wrap = $envelope['key_wrap'] ?? null;
    if (!is_array($kdf) || !is_array($wrap)) return false;
    if (($wrap['version'] ?? null) !== SENTRYIQ_KEY_WRAP_VERSION || ($wrap['cipher'] ?? '') !== 'aes-256-gcm') return false;
    $salt = vault_decode_base64((string)($kdf['salt'] ?? ''), SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = vault_decode_base64((string)($wrap['nonce'] ?? ''), SENTRYIQ_GCM_NONCE_BYTES);
    $tag = vault_decode_base64((string)($wrap['tag'] ?? ''), SENTRYIQ_GCM_TAG_BYTES);
    $ciphertext = vault_decode_base64((string)($wrap['ciphertext'] ?? ''));
    $aad = vault_decode_base64((string)($wrap['aad'] ?? ''));
    if ($salt === false || $nonce === false || $tag === false || $ciphertext === false || $aad === false) return false;
    if (!hash_equals(vault_build_key_wrap_aad(), $aad)) return false;
    $key = vault_derive_key($password, $salt, (int)($kdf['opslimit'] ?? 0), (int)($kdf['memlimit'] ?? 0));
    $vmk = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    return is_string($vmk) && strlen($vmk) === 32 ? $vmk : false;
}

function vault_build_recovery_aad(): string
{
    return 'SentryIQ VMK recovery wrap v1';
}

function vault_generate_recovery_key(): string
{
    return strtoupper(bin2hex(random_bytes(32)));
}

function vault_normalize_recovery_key(string $recoveryKey): string
{
    return strtoupper(preg_replace('/[^A-F0-9]/i', '', $recoveryKey) ?? '');
}

function vault_wrap_vmk_with_recovery_key(string $vmk, string $recoveryKey): array
{
    if (strlen($vmk) !== 32) throw new RuntimeException('Invalid Vault Master Key.');
    $recoveryKey = vault_normalize_recovery_key($recoveryKey);
    if (strlen($recoveryKey) !== 64) throw new RuntimeException('Invalid recovery key.');
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $kdf = vault_kdf_metadata($salt, SENTRYIQ_KDF_OPSLIMIT, SENTRYIQ_KDF_MEMLIMIT);
    $key = vault_derive_key($recoveryKey, $salt, SENTRYIQ_KDF_OPSLIMIT, SENTRYIQ_KDF_MEMLIMIT);
    $aad = vault_build_recovery_aad();
    $nonce = random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $tag = '';
    $ciphertext = openssl_encrypt($vmk, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, SENTRYIQ_GCM_TAG_BYTES);
    if ($ciphertext === false || strlen($tag) !== SENTRYIQ_GCM_TAG_BYTES) throw new RuntimeException('Unable to protect the Vault Master Key with recovery material.');
    return ['version'=>1,'cipher'=>'aes-256-gcm','kdf'=>$kdf,'aad'=>base64_encode($aad),'nonce'=>base64_encode($nonce),'tag'=>base64_encode($tag),'ciphertext'=>base64_encode($ciphertext)];
}

function vault_add_recovery_wrapper(string $vmk, string $recoveryKey): bool
{
    if (strlen($vmk) !== 32) return false;
    $parts = vault_read_envelope();
    $parts['envelope']['recovery_wrap'] = vault_wrap_vmk_with_recovery_key($vmk, $recoveryKey);
    $encoded = json_encode($parts['envelope'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $tmp = DATA_FILE . '.tmp-' . bin2hex(random_bytes(12));
    $handle = @fopen($tmp, 'xb');
    if ($handle === false) return false;
    try {
        @chmod($tmp, 0600);
        if (fwrite($handle, $encoded) !== strlen($encoded)) return false;
        if (function_exists('fflush')) fflush($handle);
        if (function_exists('fsync')) @fsync($handle);
    } finally { fclose($handle); }
    @chmod($tmp, 0600);
    if (!@rename($tmp, DATA_FILE)) { @unlink($tmp); return false; }
    @chmod(DATA_FILE, 0600);
    return true;
}

function vault_unwrap_vmk_with_recovery_key(array $envelope, string $recoveryKey): string|false
{
    $wrap = $envelope['recovery_wrap'] ?? null;
    if (!is_array($wrap)) return false;
    if (($wrap['version'] ?? null) !== 1 || ($wrap['cipher'] ?? '') !== 'aes-256-gcm') return false;
    $kdf = $wrap['kdf'] ?? null;
    if (!is_array($kdf)) return false;
    $recoveryKey = vault_normalize_recovery_key($recoveryKey);
    if (strlen($recoveryKey) !== 64) return false;
    $salt = vault_decode_base64((string)($kdf['salt'] ?? ''), SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = vault_decode_base64((string)($wrap['nonce'] ?? ''), SENTRYIQ_GCM_NONCE_BYTES);
    $tag = vault_decode_base64((string)($wrap['tag'] ?? ''), SENTRYIQ_GCM_TAG_BYTES);
    $ciphertext = vault_decode_base64((string)($wrap['ciphertext'] ?? ''));
    $aad = vault_decode_base64((string)($wrap['aad'] ?? ''));
    if ($salt === false || $nonce === false || $tag === false || $ciphertext === false || $aad === false) return false;
    if (!hash_equals(vault_build_recovery_aad(), $aad)) return false;
    $key = vault_derive_key($recoveryKey, $salt, (int)($kdf['opslimit'] ?? 0), (int)($kdf['memlimit'] ?? 0));
    $vmk = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    return is_string($vmk) && strlen($vmk) === 32 ? $vmk : false;
}

function vault_blob_aad(string $context): string
{
    $context = trim($context);
    if ($context === '' || strlen($context) > 255 || preg_match('/[\\x00-\\x1F\\x7F]/', $context)) {
        throw new RuntimeException('Invalid encrypted object context.');
    }
    return 'SentryIQ object v1:' . $context;
}

function vault_encrypt_blob(string $plaintext, string $context): string
{
    $key = $_SESSION['master_key'] ?? null;
    if (!is_string($key) || strlen($key) !== 32) throw new RuntimeException('Vault Master Key is unavailable.');
    if ($plaintext === '') throw new RuntimeException('Cannot encrypt an empty object.');

    $aad = vault_blob_aad($context);
    $nonce = random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, SENTRYIQ_GCM_TAG_BYTES);
    if ($ciphertext === false || strlen($tag) !== SENTRYIQ_GCM_TAG_BYTES) throw new RuntimeException('Unable to encrypt the secure object.');

    return json_encode([
        'version' => 1,
        'cipher' => 'aes-256-gcm',
        'aad' => base64_encode($aad),
        'nonce' => base64_encode($nonce),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($ciphertext),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}

function vault_encrypt_blob_with_key(string $plaintext, string $context, string $key): string
{
    if (strlen($key) !== 32) throw new RuntimeException('Invalid Vault Master Key.');
    if ($plaintext === '') throw new RuntimeException('Cannot encrypt an empty object.');

    $aad = vault_blob_aad($context);
    $nonce = random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, SENTRYIQ_GCM_TAG_BYTES);
    if ($ciphertext === false || strlen($tag) !== SENTRYIQ_GCM_TAG_BYTES) throw new RuntimeException('Unable to encrypt the secure object.');

    return json_encode([
        'version' => 1,
        'cipher' => 'aes-256-gcm',
        'aad' => base64_encode($aad),
        'nonce' => base64_encode($nonce),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($ciphertext),
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
}

function vault_decrypt_blob_with_key(string $envelopeJson, string $context, string $key): string|false
{
    if (strlen($key) !== 32 || $envelopeJson === '') return false;

    try {
        $envelope = json_decode($envelopeJson, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return false;
    }
    if (!is_array($envelope) || ($envelope['version'] ?? null) !== 1 || ($envelope['cipher'] ?? '') !== 'aes-256-gcm') return false;

    $aad = vault_decode_base64((string)($envelope['aad'] ?? ''));
    $nonce = vault_decode_base64((string)($envelope['nonce'] ?? ''), SENTRYIQ_GCM_NONCE_BYTES);
    $tag = vault_decode_base64((string)($envelope['tag'] ?? ''), SENTRYIQ_GCM_TAG_BYTES);
    $ciphertext = vault_decode_base64((string)($envelope['ciphertext'] ?? ''));
    if ($aad === false || $nonce === false || $tag === false || $ciphertext === false) return false;

    try {
        if (!hash_equals(vault_blob_aad($context), $aad)) return false;
    } catch (Throwable) {
        return false;
    }

    $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
    return is_string($plaintext) ? $plaintext : false;
}

function vault_unlock(string $password): array|false
{
    $parts = vault_read_envelope();
    $vmk = vault_unwrap_vmk_with_password($parts['envelope'], $password);
    if ($vmk === false) throw new RuntimeException('vault_unlock:key_wrap_failed');
    $plaintext = openssl_decrypt($parts['ciphertext'], 'aes-256-gcm', $vmk, OPENSSL_RAW_DATA, $parts['nonce'], $parts['tag'], $parts['aad']);
    if ($plaintext === false) throw new RuntimeException('vault_unlock:gcm_decrypt_failed');
    try { $records = json_decode($plaintext, true, 16, JSON_THROW_ON_ERROR); }
    catch (Throwable) { throw new RuntimeException('vault_unlock:plaintext_json_failed'); }
    if (!is_array($records)) throw new RuntimeException('vault_unlock:plaintext_not_array');
    return ['key'=>$vmk,'records'=>normalize_vault_records($records),'kdf'=>$parts['kdf']];
}

function vault_initialize(string $password, array $records = []): bool
{
    if (strlen($password) < 12) return false;
    if (!ensure_sentryiq_data_directory()) return false;
    try {
        $salt=random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $kdf=vault_kdf_metadata($salt,SENTRYIQ_KDF_OPSLIMIT,SENTRYIQ_KDF_MEMLIMIT);
        $vmk=random_bytes(32);
        $wrapped=vault_wrap_vmk_with_password($vmk,$password,$kdf);
        return vault_write_encrypted_records(normalize_vault_records($records),$vmk,$kdf,$wrapped);
    } catch(Throwable $exception) {
        error_log('SentryIQ vault initialization failure: '.$exception::class.': '.$exception->getMessage());
        return false;
    }
}
function vault_write_encrypted_records(array $dataMatrix, string $masterKey, array $kdf, ?array $keyWrap = null): bool
{
    if(strlen($masterKey)!==32||!ensure_sentryiq_data_directory()) return false;
    if(!isset($kdf['salt'],$kdf['opslimit'],$kdf['memlimit'])) return false;
    if($keyWrap===null){$existing=vault_read_envelope();$keyWrap=is_array($existing['envelope']['key_wrap']??null)?$existing['envelope']['key_wrap']:null;}
    if(!is_array($keyWrap)) return false;
    $aad=vault_build_aad($kdf);
    $nonce=random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $plaintext=json_encode(normalize_vault_records($dataMatrix),JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    $tag='';
    $ciphertext=openssl_encrypt($plaintext,'aes-256-gcm',$masterKey,OPENSSL_RAW_DATA,$nonce,$tag,$aad,SENTRYIQ_GCM_TAG_BYTES);
    if($ciphertext===false||strlen($tag)!==SENTRYIQ_GCM_TAG_BYTES) return false;
    $envelope=['version'=>SENTRYIQ_VAULT_VERSION,'kdf'=>$kdf,'key_wrap'=>$keyWrap,'cipher'=>['name'=>'aes-256-gcm','nonce_bytes'=>SENTRYIQ_GCM_NONCE_BYTES,'tag_bytes'=>SENTRYIQ_GCM_TAG_BYTES],'aad'=>base64_encode($aad),'nonce'=>base64_encode($nonce),'tag'=>base64_encode($tag),'ciphertext'=>base64_encode($ciphertext)];
    $encoded=json_encode($envelope,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
    $tmp=DATA_FILE.'.tmp-'.bin2hex(random_bytes(12));
    if(is_link(DATA_FILE)) return false;
    $handle=@fopen($tmp,'xb'); if($handle===false) return false;
    try{ @chmod($tmp,0600); if(fwrite($handle,$encoded)!==strlen($encoded)) return false; if(function_exists('fflush')) fflush($handle); if(function_exists('fsync')) @fsync($handle); } finally{fclose($handle);}
    @chmod($tmp,0600);
    if(!@rename($tmp,DATA_FILE)){@unlink($tmp);return false;}
    @chmod(DATA_FILE,0600);
    return true;
}

function load_passwords(?string $explicitKey = null): array|bool
{
    $key = $explicitKey ?? ($_SESSION['master_key'] ?? null);
    if (!is_string($key) || strlen($key) !== 32) return false;

    $parts = vault_read_envelope();

    $plaintext = openssl_decrypt(
        $parts['ciphertext'],
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $parts['nonce'],
        $parts['tag'],
        $parts['aad']
    );
    if ($plaintext === false) return false;

    $records = json_decode($plaintext, true);
    if (!is_array($records)) return false;

    return normalize_vault_records($records);
}
