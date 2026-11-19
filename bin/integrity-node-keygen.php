<?php

declare(strict_types=1);

use SentryIQ\Updates\IntegrityNodeKeyGenerator;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once __DIR__ . '/../app/Updates/IntegrityNodeKeyGenerator.php';

$nodeId = $argv[1] ?? '';
$privateDataDirectory = $argv[2] ?? '';
$publicWebRoot = $argv[3] ?? '';

try {
    $result = (new IntegrityNodeKeyGenerator())->generate(
        $nodeId,
        $privateDataDirectory,
        $publicWebRoot
    );
    fwrite(STDOUT, json_encode([
        'node_id' => $result['node_id'],
        'private_key_path' => $result['private_key_path'],
        'public_key_path' => $result['public_key_path'],
        'public_key_base64' => $result['public_key_base64'],
        'private_key_exported' => false,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(0);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Integrity node key generation failed: ' . get_class($exception) . PHP_EOL);
    exit(1);
}
