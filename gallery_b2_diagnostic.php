<?php
declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

require_once __DIR__ . '/cloud/Gallery/Storage/BackblazeB2Signer.php';

use SentryIQCloud\Gallery\Storage\BackblazeB2Signer;

header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $raw = file_get_contents('php://input');
        if (!is_string($raw) || strlen($raw) > 4096) {
            throw new RuntimeException('Invalid diagnostic request.');
        }
        $request = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        $provided = is_array($request) ? (string)($request['csrf_token'] ?? '') : '';
        $expected = (string)($_SESSION['csrf_token'] ?? '');
        if ($provided === '' || $expected === '' || !hash_equals($expected, $provided)) {
            http_response_code(403);
            throw new RuntimeException('Security validation failed. Reload the page and try again.');
        }
        if (($request['action'] ?? '') !== 'prepare') {
            http_response_code(400);
            throw new RuntimeException('Unknown diagnostic operation.');
        }
        $dataDirectory = sentryiq_data_dir();
        if (!is_string($dataDirectory) || $dataDirectory === '') {
            throw new RuntimeException('SentryIQ private runtime directory is unavailable.');
        }
        $signer = BackblazeB2Signer::fromRuntimeDirectory($dataDirectory);
        $objectKey = BackblazeB2Signer::newObjectKey('metadata');
        echo json_encode([
            'status' => 'ok',
            'put' => $signer->presign('PUT', $objectKey, 180),
            'get' => $signer->presign('GET', $objectKey, 180),
            'delete' => $signer->presign('DELETE', $objectKey, 180),
            'contentType' => 'application/octet-stream',
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    } catch (Throwable $exception) {
        if (http_response_code() < 400) http_response_code(400);
        error_log('SentryIQ B2 diagnostic failed: ' . $exception::class);
        echo json_encode([
            'status' => 'error',
            'message' => $exception->getMessage() !== '' ? $exception->getMessage() : 'B2 diagnostic could not be prepared.',
        ], JSON_UNESCAPED_SLASHES);
    }
    exit;
}

$csrf = sentryiq_csrf_token();
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<meta name="robots" content="noindex,nofollow">
<title>SentryIQ — Backblaze B2 diagnostic</title>
<style>
body{font:16px/1.5 system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 18px;color:#20242a}
button{padding:11px 18px;border:0;border-radius:7px;background:#175cd3;color:white;font-weight:600;cursor:pointer}
button:disabled{opacity:.55;cursor:wait}
#result{white-space:pre-wrap;padding:14px;background:#f3f5f7;border-radius:8px;margin-top:18px;min-height:48px}
a{color:#175cd3}
</style>
</head>
<body>
<h1>Backblaze B2 connection test</h1>
<p>This authenticated test writes a tiny random, non-image object to your private bucket, reads it back, compares the bytes, and attempts to delete it. It does not use Gallery photos or store credentials in the browser.</p>
<p><strong>Run this after deploying the latest SentryIQ main branch.</strong></p>
<button id="run" type="button">Run B2 connection test</button>
<pre id="result" role="status" aria-live="polite">Ready. No test object has been created.</pre>
<p><a href="gallery.php">Return to Secure Gallery</a></p>
<script src="assets/js/gallery_b2_diagnostic.js" defer></script>
</body>
</html>
