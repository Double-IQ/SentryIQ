<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/security_bootstrap.php';
sentryiq_security_bootstrap();

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');

function copy_code_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if ($method === 'GET') {
    header('Content-Type: text/html; charset=UTF-8');
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="no-referrer">
    <title>SentryIQ — Copy Verification Code</title>
    <link rel="stylesheet" href="assets/css/copy_code.css">
</head>
<body>
<div class="card">
    <h2 style="color:#0066cc;margin-top:0;font-size:22px;">SentryIQ Verification</h2>
    <p id="status" class="hint">Retrieving your one-time verification code…</p>
    <div id="auth-code" class="code-display" hidden></div>
    <button type="button" id="copy-btn" class="btn-copy" hidden>Copy Verification Code</button>
    <p class="hint">The token is consumed once and cannot be reused.</p>
</div>
<script src="assets/js/copy_code.js" defer></script>
</body>
</html>
    <?php
    exit;
}

if ($method !== 'POST') {
    header('Allow: GET, POST');
    copy_code_json(['status' => 'error', 'message' => 'Method not allowed.'], 405);
}

$inboundToken = (string)($_POST['t'] ?? '');
if (!preg_match('/^[a-f0-9]{64}$/i', $inboundToken)) {
    copy_code_json(['status' => 'error', 'message' => 'Token unavailable.'], 404);
}

$dataDir = sentryiq_data_dir();
if ($dataDir === '' || !is_dir($dataDir) || is_link($dataDir)) {
    copy_code_json(['status' => 'error', 'message' => 'Token unavailable.'], 404);
}

$tokenFile = $dataDir . '/token_' . strtolower($inboundToken) . '.json';
if (!is_file($tokenFile) || is_link($tokenFile)) {
    copy_code_json(['status' => 'error', 'message' => 'Token unavailable or already consumed.'], 404);
}

$claimedFile = $dataDir . '/consumed_' . bin2hex(random_bytes(16)) . '.token';
if (!@rename($tokenFile, $claimedFile)) {
    copy_code_json(['status' => 'error', 'message' => 'Token unavailable or already consumed.'], 404);
}

$response = ['status' => 'error', 'message' => 'Token unavailable.'];
$responseStatus = 404;
try {
    if (!is_link($claimedFile) && is_file($claimedFile)) {
        $size = @filesize($claimedFile);
        $permissions = @fileperms($claimedFile);
        if (is_int($size) && $size >= 1 && $size <= 1024
            && is_int($permissions) && (($permissions & 0077) === 0)) {
            $raw = @file_get_contents($claimedFile);
            try {
                $data = is_string($raw) ? json_decode($raw, true, 8, JSON_THROW_ON_ERROR) : null;
            } catch (Throwable) {
                $data = null;
            }
            if (is_array($data) && is_int($data['expires'] ?? null) && is_string($data['code'] ?? null)) {
                if (time() >= $data['expires']) {
                    $response = ['status' => 'error', 'message' => 'Verification token expired.'];
                    $responseStatus = 410;
                } elseif (preg_match('/^\d{6}$/', $data['code'])) {
                    $response = ['status' => 'ok', 'code' => $data['code']];
                    $responseStatus = 200;
                }
            }
        }
    }
} finally {
    if (is_file($claimedFile) && !is_link($claimedFile)) {
        @unlink($claimedFile);
    }
}

copy_code_json($response, $responseStatus);
