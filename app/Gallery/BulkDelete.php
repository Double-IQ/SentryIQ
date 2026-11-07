<?php

declare(strict_types=1);

// Legacy server-side Gallery handling is intentionally disabled.
// Photo bytes must never be uploaded to or decrypted by PHP.
http_response_code(410);
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
echo json_encode([
    'status' => 'error',
    'code' => 'GALLERY_SERVER_STORAGE_DISABLED',
    'message' => 'Server-side Gallery storage has been retired. Use the browser-encrypted Gallery flow.',
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
exit;
