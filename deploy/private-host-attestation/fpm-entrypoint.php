<?php

declare(strict_types=1);

/**
 * Reference PHP-FPM entrypoint for a separately isolated attestation pool.
 *
 * Install this file outside the public document root. The web server must
 * route only the exact POST /private-host-attestation location to a dedicated
 * PHP-FPM pool running as the attestor OS identity. Never include this file
 * from the public SentryIQ application or its normal PHP-FPM pool.
 */

use SentryIQ\Updates\PrivateHostAttestationCollector;
use SentryIQ\Updates\PrivateHostAttestationNonceStore;
use SentryIQ\Updates\PrivateHostAttestationRequestHandler;

require_once dirname(__DIR__, 2) . '/app/Updates/PrivateHostAttestationCollector.php';
require_once dirname(__DIR__, 2) . '/app/Updates/PrivateHostAttestationNonceStore.php';
require_once dirname(__DIR__, 2) . '/app/Updates/PrivateHostAttestationRequestHandler.php';

function privateHostRespond(int $status, string $body): never
{
    if (!headers_sent()) {
        http_response_code($status);
        header('Content-Type: application/json');
        header('Cache-Control: no-store, private');
        header('Pragma: no-cache');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
    }
    echo $body;
    exit;
}

/** @return array<string,mixed> */
function privateHostLoadConfig(string $path): array
{
    if ($path === '' || !str_starts_with($path, DIRECTORY_SEPARATOR)
        || !function_exists('posix_geteuid')) {
        throw new RuntimeException('Attestation service config path or POSIX identity support is unavailable.');
    }
    $real = realpath($path);
    if (!is_string($real) || is_link($path)) {
        throw new RuntimeException('Attestation service config must be a real file, not a symlink.');
    }
    $documentRoot = realpath((string)($_SERVER['DOCUMENT_ROOT'] ?? ''));
    if (is_string($documentRoot)
        && str_starts_with($real, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
        throw new RuntimeException('Attestation service config must be outside the public document root.');
    }
    clearstatcache(true, $real);
    $before = @lstat($real);
    $uid = posix_geteuid();
    if (!is_array($before) || (($before['mode'] ?? 0) & 0170000) !== 0100000
        || (($before['mode'] ?? 0) & 0777) !== 0600
        || ($before['uid'] ?? null) !== $uid
        || ($before['size'] ?? 0) < 2 || ($before['size'] ?? 0) > 65_536) {
        throw new RuntimeException('Attestation service config must be owner-owned, regular, 0600 and bounded.');
    }

    $handle = @fopen($real, 'rb');
    $opened = is_resource($handle) ? fstat($handle) : false;
    if ($handle === false || !is_array($opened)
        || ($opened['dev'] ?? null) !== ($before['dev'] ?? null)
        || ($opened['ino'] ?? null) !== ($before['ino'] ?? null)
        || (($opened['mode'] ?? 0) & 0170000) !== 0100000
        || (($opened['mode'] ?? 0) & 0777) !== 0600
        || ($opened['uid'] ?? null) !== $uid
        || ($opened['size'] ?? 0) !== ($before['size'] ?? -1)) {
        if (is_resource($handle)) fclose($handle);
        throw new RuntimeException('Attestation service config changed during open.');
    }
    try {
        $bytes = stream_get_contents($handle, 65_537);
        $after = fstat($handle);
        clearstatcache(true, $real);
        $pathAfter = @lstat($real);
        if (!is_string($bytes) || strlen($bytes) < 2 || strlen($bytes) > 65_536
            || !is_array($after) || !is_array($pathAfter)
            || ($after['dev'] ?? null) !== ($opened['dev'] ?? null)
            || ($after['ino'] ?? null) !== ($opened['ino'] ?? null)
            || ($after['size'] ?? null) !== ($opened['size'] ?? null)
            || ($after['mtime'] ?? null) !== ($opened['mtime'] ?? null)
            || ($after['ctime'] ?? null) !== ($opened['ctime'] ?? null)
            || ($pathAfter['dev'] ?? null) !== ($opened['dev'] ?? null)
            || ($pathAfter['ino'] ?? null) !== ($opened['ino'] ?? null)
            || (($pathAfter['mode'] ?? 0) & 0170000) !== 0100000
            || (($pathAfter['mode'] ?? 0) & 0777) !== 0600
            || ($pathAfter['uid'] ?? null) !== $uid) {
            throw new RuntimeException('Attestation service config changed while being read.');
        }
    } finally {
        fclose($handle);
    }

    try {
        $config = json_decode($bytes, true, 16, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        throw new RuntimeException('Attestation service config is invalid JSON.', 0, $exception);
    }
    if (!is_array($config) || array_is_list($config)) {
        throw new RuntimeException('Attestation service config must be a JSON object.');
    }
    $required = [
        'public_web_root', 'private_data_directory', 'signing_key_path',
        'expected_files', 'private_config', 'monitored_directories', 'node_tokens'
    ];
    if (array_diff(array_keys($config), $required) !== []
        || array_diff($required, array_keys($config)) !== []) {
        throw new RuntimeException('Attestation service config has missing or unexpected fields.');
    }

    if (!is_string($config['public_web_root']) || !is_string($config['private_data_directory'])
        || !is_string($config['signing_key_path'])) {
        throw new RuntimeException('Attestation service path settings must be strings.');
    }
    $web = realpath($config['public_web_root']);
    $private = realpath($config['private_data_directory']);
    if (!is_string($web) || !is_dir($web) || !is_string($private) || !is_dir($private)
        || is_link((string)$config['public_web_root']) || is_link((string)$config['private_data_directory'])
        || (($privateStat = @lstat($private)) === false)
        || (($privateStat['mode'] ?? 0) & 0170000) !== 0040000
        || (($privateStat['mode'] ?? 0) & 0777) !== 0700
        || ($privateStat['uid'] ?? null) !== $uid
        || $private === $web
        || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
        || !str_starts_with($real, rtrim($private, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
        throw new RuntimeException('Attestation config and private state must be owner-only and outside the public webroot.');
    }
    if (!is_array($config['expected_files']) || !is_array($config['private_config'])
        || !is_array($config['monitored_directories']) || !array_is_list($config['monitored_directories'])
        || !is_array($config['node_tokens']) || array_is_list($config['node_tokens'])) {
        throw new RuntimeException('Attestation service config inventory types are invalid.');
    }
    return $config;
}

try {
    if (PHP_SAPI !== 'fpm-fcgi') {
        throw new RuntimeException('Attestation entrypoint must run only inside its dedicated PHP-FPM pool.');
    }
    $configPath = $_SERVER['PRIVATE_HOST_ATTESTATION_CONFIG'] ?? getenv('PRIVATE_HOST_ATTESTATION_CONFIG');
    if (!is_string($configPath) || $configPath === '') {
        throw new RuntimeException('Dedicated PHP-FPM pool did not provide the private config path.');
    }
    $config = privateHostLoadConfig($configPath);

    $collector = new PrivateHostAttestationCollector(
        'sentryiq-host-attestor',
        $config['public_web_root'],
        $config['private_data_directory'],
        $config['signing_key_path'],
        $config['expected_files'],
        $config['private_config'],
        'https://sentryiq.bichet.co.za',
        null,
        $config['monitored_directories']
    );
    $nonceStore = new PrivateHostAttestationNonceStore(
        $config['private_data_directory'],
        $config['public_web_root']
    );
    $handler = new PrivateHostAttestationRequestHandler(
        $collector,
        $config['node_tokens'],
        static fn(string $nodeId, string $nonce, int $expiresAt): bool =>
            $nonceStore->consume($nodeId, $nonce, $expiresAt)
    );

    $headers = function_exists('getallheaders') ? getallheaders() : [];
    if (!is_array($headers)) $headers = [];
    $serverAuthorization = $_SERVER['HTTP_AUTHORIZATION'] ?? null;
    $serverContentType = $_SERVER['CONTENT_TYPE'] ?? null;
    foreach ([
        'Authorization' => $serverAuthorization,
        'Content-Type' => $serverContentType
    ] as $name => $serverValue) {
        if (!is_string($serverValue) || $serverValue === '') continue;
        $found = null;
        foreach ($headers as $headerName => $headerValue) {
            if (is_string($headerName) && strcasecmp($headerName, $name) === 0) {
                $found = is_string($headerValue) ? $headerValue : null;
                break;
            }
        }
        if ($found !== null && !hash_equals($found, $serverValue)) {
            privateHostRespond(400, '{"error":"private_host_attestation_unavailable"}');
        }
        if ($found === null) $headers[$name] = $serverValue;
    }

    $input = @fopen('php://input', 'rb');
    if (!is_resource($input)) {
        privateHostRespond(400, '{"error":"private_host_attestation_unavailable"}');
    }
    try {
        $body = stream_get_contents($input, 4097);
    } finally {
        fclose($input);
    }
    if (!is_string($body) || strlen($body) > 4096) {
        privateHostRespond(400, '{"error":"private_host_attestation_unavailable"}');
    }

    $result = $handler->handle(
        is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : '',
        $headers,
        $body
    );
    privateHostRespond($result['status'], $result['body']);
} catch (Throwable $exception) {
    // Do not log request headers, credentials, config contents or signed evidence.
    error_log('private-host attestation service failure: ' . get_class($exception));
    privateHostRespond(503, '{"error":"private_host_attestation_unavailable"}');
}
