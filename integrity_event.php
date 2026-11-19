<?php

declare(strict_types=1);

/**
 * Machine-to-machine BTM-SA / Node 4 integrity event endpoint.
 *
 * Configure integrity_event in the private sentryiq_config.php:
 * [
 *   'data_dir' => '/absolute/private/app-data',
 *   'integrity_event' => [
 *     'enabled' => true,
 *     'node_tokens' => ['integrity-a' => '<random-32-byte-token>',
 *                       'integrity-b' => '<random-32-byte-token>'],
 *     'node_public_keys' => ['integrity-a' => '<base64-ed25519-public-key>',
 *                            'integrity-b' => '<base64-ed25519-public-key>'],
 *   ],
 * ]
 *
 * The tokens and private data directory must never be committed or served.
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Allow: POST');

function integrityEventRespond(int $status, array $body): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    integrityEventRespond(405, ['status' => 'error', 'message' => 'POST required.']);
}
if (!in_array(strtolower((string)($_SERVER['HTTPS'] ?? '')), ['on', '1', 'https'], true)) {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'HTTPS is required.']);
}
$host = strtolower(trim((string)($_SERVER['HTTP_HOST'] ?? '')));
if (!in_array($host, ['sentryiq.bichet.co.za', 'sentryiq.bichet.co.za:443'], true)) {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'Canonical Host header is required.']);
}
$contentType = strtolower(trim(explode(';', (string)($_SERVER['CONTENT_TYPE'] ?? ''))[0]));
if ($contentType !== 'application/json') {
    integrityEventRespond(415, ['status' => 'error', 'message' => 'application/json required.']);
}
$contentLengthRaw = (string)($_SERVER['CONTENT_LENGTH'] ?? '');
if (!preg_match('/^[0-9]{1,5}$/', $contentLengthRaw)) {
    integrityEventRespond(413, ['status' => 'error', 'message' => 'Request size is invalid.']);
}
$contentLength = (int)$contentLengthRaw;
if ($contentLength < 1 || $contentLength > 32768) {
    integrityEventRespond(413, ['status' => 'error', 'message' => 'Request size is invalid.']);
}

require_once __DIR__ . '/app/Updates/IntegrityNode4RuntimeConfig.php';
require_once __DIR__ . '/app/Updates/IntegrityEventRequestDecoder.php';
try {
    $config = SentryIQ\Updates\IntegrityNode4RuntimeConfig::load(__DIR__ . '/sentryiq_config.php');
} catch (Throwable) {
    integrityEventRespond(503, ['status' => 'error', 'message' => 'Node 4 private runtime configuration is unavailable.']);
}
$eventConfig = $config['integrity_event'] ?? null;
$dataDir = (string)($config['data_dir'] ?? '');
$storageDir = is_array($eventConfig) ? (string)($eventConfig['storage_dir'] ?? '') : '';
$realDataDir = $dataDir !== '' ? realpath($dataDir) : false;
$realStorageDir = $storageDir !== '' ? realpath($storageDir) : false;
if (!is_array($eventConfig) || ($eventConfig['enabled'] ?? false) !== true
    || !is_string($realDataDir) || !is_string($realStorageDir)
    || !str_starts_with($realStorageDir, rtrim($realDataDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || !is_dir($realStorageDir) || is_link($storageDir)) {
    integrityEventRespond(503, ['status' => 'error', 'message' => 'Node 4 event service is not configured.']);
}

$body = file_get_contents('php://input', false, null, 0, 32769);
if (!is_string($body) || strlen($body) > 32768 || strlen($body) !== $contentLength || $body === '') {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'Request body could not be read.']);
}
try {
    $request = SentryIQ\Updates\IntegrityEventRequestDecoder::decode($body, 32768);
} catch (Throwable) {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'Request JSON is invalid or ambiguous.']);
}

$authorization = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '');
if ($authorization === '' && function_exists('getallheaders')) {
    $requestHeaders = getallheaders();
    if (is_array($requestHeaders)) {
        foreach ($requestHeaders as $name => $value) {
            if (is_string($name) && strtolower($name) === 'authorization' && is_string($value)) {
                $authorization = $value;
                break;
            }
        }
    }
}
if (!preg_match('/^Bearer ([A-Za-z0-9_-]{40,128})$/', $authorization, $match)) {
    integrityEventRespond(401, ['status' => 'error', 'message' => 'Node authentication required.']);
}
$token = $match[1];

$expectedFields = match ($request['action']) {
    'challenge' => ['action', 'node_id', 'target_origin', 'release_version', 'commit', 'artifact_sha256', 'manifest_sha256'],
    'report' => ['action', 'envelope'],
    default => ['action'],
};
try {
    SentryIQ\Updates\IntegrityEventRequestDecoder::assertExactFields($request, $expectedFields);
} catch (Throwable) {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'Request fields do not match the selected action.']);
}

require_once __DIR__ . '/app/Updates/FileIntegrityEventStore.php';
require_once __DIR__ . '/app/Updates/IntegrityEventReportVerifier.php';

try {
    $store = new SentryIQ\Updates\FileIntegrityEventStore($realStorageDir);
    if ($request['action'] === 'challenge') {
        $nodeId = $request['node_id'] ?? null;
        $tokens = $eventConfig['node_tokens'] ?? [];
        if (!is_string($nodeId) || !in_array($nodeId, ['integrity-a', 'integrity-b'], true)
            || !is_array($tokens) || !is_string($tokens[$nodeId] ?? null)
            || !hash_equals($tokens[$nodeId], $token)) {
            integrityEventRespond(401, ['status' => 'error', 'message' => 'Node authentication failed.']);
        }
        foreach (['target_origin', 'release_version', 'commit', 'artifact_sha256', 'manifest_sha256'] as $field) {
            if (!is_string($request[$field] ?? null)) {
                integrityEventRespond(400, ['status' => 'error', 'message' => 'Challenge binding fields are invalid.']);
            }
        }
        if ($request['target_origin'] !== 'https://sentryiq.bichet.co.za') {
            integrityEventRespond(400, ['status' => 'error', 'message' => 'Node 4 only accepts the canonical SentryIQ production origin.']);
        }
        $challenge = $store->issueChallenge(
            $nodeId,
            $request['target_origin'],
            $request['release_version'],
            $request['commit'],
            $request['artifact_sha256'],
            $request['manifest_sha256']
        );
        integrityEventRespond(201, ['status' => 'ok'] + $challenge);
    }

    if ($request['action'] === 'report') {
        // A signed report is independently authenticated by its Ed25519 node key.
        // The bearer token also protects the public endpoint from unsolicited traffic.
        $tokens = $eventConfig['node_tokens'] ?? [];
        $envelope = $request['envelope'] ?? null;
        $authenticated = false;
        $signedNodeId = null;
        if (is_string($envelope)) {
            \SentryIQ\Updates\IntegrityEventRequestDecoder::assertNoDuplicateObjectKeys($envelope);
            $outer = json_decode($envelope, true);
            $raw = is_array($outer) ? base64_decode((string)($outer['payload'] ?? ''), true) : false;
            if (is_string($raw)) \SentryIQ\Updates\IntegrityEventRequestDecoder::assertNoDuplicateObjectKeys($raw);
            $signedPayload = is_string($raw) ? json_decode($raw, true) : null;
            $signedNodeId = is_array($signedPayload) ? ($signedPayload['node_id'] ?? null) : null;
        }
        if (is_string($signedNodeId) && in_array($signedNodeId, ['integrity-a', 'integrity-b'], true)
            && is_array($tokens) && is_string($tokens[$signedNodeId] ?? null)
            && hash_equals($tokens[$signedNodeId], $token)) {
            $authenticated = true;
        }
        if (!$authenticated || !is_string($envelope)) {
            integrityEventRespond(401, ['status' => 'error', 'message' => 'Node authentication failed.']);
        }
        $keys = $eventConfig['node_public_keys'] ?? [];
        if (!is_array($keys)) {
            integrityEventRespond(503, ['status' => 'error', 'message' => 'Node trust keys are unavailable.']);
        }
        $verifier = new SentryIQ\Updates\IntegrityEventReportVerifier(
            $keys,
            [$store, 'consumeAndStore']
        );
        $accepted = $verifier->accept($request['envelope']);
        integrityEventRespond(202, ['status' => 'accepted'] + $accepted);
    }

    integrityEventRespond(400, ['status' => 'error', 'message' => 'Unknown event action.']);
} catch (Throwable $exception) {
    integrityEventRespond(400, ['status' => 'error', 'message' => 'Integrity event request was rejected.']);
}
