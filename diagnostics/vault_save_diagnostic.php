<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_fresh_auth();
sentryiq_require_csrf();

header('Content-Type: application/json; charset=utf-8');

$result = [
    'timestamp' => date('c'),
    'stage' => 'VAULT_SAVE_DIAGNOSTIC',
    'php_version' => PHP_VERSION,
    'sapi' => PHP_SAPI,
];

try {
    $configFile = __DIR__ . '/sentryiq_config.php';
    $config = is_file($configFile) ? require $configFile : [];
    if (!is_array($config)) throw new RuntimeException('config_invalid');

    $dataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
    $dataFile = $dataDir . '/passwords.enc';
    $masterKey = $_SESSION['master_key'] ?? null;

    $result['data_dir'] = $dataDir;
    $result['data_dir_exists'] = is_dir($dataDir);
    $result['data_dir_permissions'] = is_dir($dataDir) ? decoct((int)(fileperms($dataDir) & 0x01ff)) : null;
    $result['data_dir_writable'] = is_dir($dataDir) && is_writable($dataDir);
    $result['data_file_exists'] = is_file($dataFile);
    $result['data_file_is_link'] = is_link($dataFile);
    $result['master_key_valid'] = is_string($masterKey) && strlen($masterKey) === 32;

    if (!$result['master_key_valid']) throw new RuntimeException('master_key_unavailable');

    require_once $dataDir . '/vault_engine.php';

    $parts = vault_read_envelope();
    $result['envelope_read_ok'] = true;
    $result['kdf_present'] = isset($parts['kdf']['salt'], $parts['kdf']['opslimit'], $parts['kdf']['memlimit']);

    if (!$result['kdf_present']) throw new RuntimeException('kdf_metadata_missing');

    $records = load_passwords();
    if ($records === false) throw new RuntimeException('load_passwords_failed');
    $records[] = [
        'id' => '__diagnostic__',
        'label' => '__diagnostic__',
        'username' => 'diagnostic',
        'password' => 'diagnostic',
        'url' => 'https://example.com',
        'notes' => 'diagnostic',
        'created_at' => date('c'),
        'updated_at' => null,
    ];
    $records = normalize_vault_records($records);
    $result['normalized_record_count'] = count($records);

    $aad = vault_build_aad($parts['kdf']);
    $nonce = random_bytes(SENTRYIQ_GCM_NONCE_BYTES);
    $plaintext = json_encode($records, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $tag = '';

    while (openssl_error_string() !== false) { }
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $masterKey,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag,
        $aad,
        SENTRYIQ_GCM_TAG_BYTES
    );
    if ($ciphertext === false) {
        $errors = [];
        while (($error = openssl_error_string()) !== false) $errors[] = $error;
        $result['gcm_encrypt_ok'] = false;
        $result['openssl_errors'] = $errors;
        throw new RuntimeException('gcm_encrypt_failed');
    }
    $result['gcm_encrypt_ok'] = true;
    $result['ciphertext_length'] = strlen($ciphertext);
    $result['tag_length'] = strlen($tag);

    $envelope = [
        'version' => SENTRYIQ_VAULT_VERSION,
        'kdf' => $parts['kdf'],
        'cipher' => [
            'name' => 'aes-256-gcm',
            'nonce_bytes' => SENTRYIQ_GCM_NONCE_BYTES,
            'tag_bytes' => SENTRYIQ_GCM_TAG_BYTES,
        ],
        'aad' => base64_encode($aad),
        'nonce' => base64_encode($nonce),
        'tag' => base64_encode($tag),
        'ciphertext' => base64_encode($ciphertext),
    ];
    $encoded = json_encode($envelope, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $result['encoded_length'] = strlen($encoded);

    $tmp = $dataFile . '.diagnostic-' . bin2hex(random_bytes(8));
    $result['temp_file'] = $tmp;
    $handle = @fopen($tmp, 'xb');
    if ($handle === false) throw new RuntimeException('temp_file_create_failed');
    $result['temp_file_create_ok'] = true;

    try {
        @chmod($tmp, 0600);
        $written = fwrite($handle, $encoded);
        $result['temp_file_write_ok'] = $written === strlen($encoded);
        $result['temp_file_bytes_written'] = is_int($written) ? $written : null;
        if (!$result['temp_file_write_ok']) throw new RuntimeException('temp_file_write_failed');
        fflush($handle);
        if (function_exists('fsync')) @fsync($handle);
    } finally {
        fclose($handle);
    }

    clearstatcache(true, $tmp);
    $result['temp_file_exists_after_close'] = is_file($tmp);
    $result['temp_file_permissions'] = is_file($tmp) ? decoct((int)(fileperms($tmp) & 0x01ff)) : null;

    $probeTarget = $dataDir . '/.sentryiq_rename_probe_' . bin2hex(random_bytes(8));
    if (!@rename($tmp, $probeTarget)) {
        @unlink($tmp);
        throw new RuntimeException('rename_probe_failed');
    }
    $result['rename_probe_ok'] = is_file($probeTarget);
    $result['rename_probe_permissions'] = is_file($probeTarget) ? decoct((int)(fileperms($probeTarget) & 0x01ff)) : null;
    @unlink($probeTarget);
    $result['diagnostic_temp_cleanup_ok'] = !is_file($probeTarget);

    $result['overall'] = 'PASS';
} catch (Throwable $exception) {
    $result['overall'] = 'FAIL';
    $result['failure'] = $exception->getMessage();
    $result['exception_class'] = $exception::class;
}

$logFile = defined('LOG_FILE') ? LOG_FILE : '';
$directory = defined('SENTRYIQ_DATA_DIR') ? SENTRYIQ_DATA_DIR : '';
$line = json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($directory !== '' && $logFile !== '' && is_dir($directory) && is_string($line)) {
    @file_put_contents($logFile, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    @chmod($logFile, 0600);
}

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
