<?php

declare(strict_types=1);

$entrypoint = __DIR__ . '/../deploy/private-host-attestation/fpm-entrypoint.php';
$source = file_get_contents($entrypoint);
if (!is_string($source) || $source === '') {
    throw new RuntimeException('Isolated FPM attestation entrypoint is missing or unreadable.');
}

try {
    token_get_all($source, TOKEN_PARSE);
} catch (ParseError $error) {
    throw new RuntimeException('Isolated FPM attestation entrypoint has invalid PHP syntax.', 0, $error);
}

$required = [
    "PHP_SAPI !== 'fpm-fcgi'",
    'PRIVATE_HOST_ATTESTATION_CONFIG',
    'posix_geteuid',
    'Cache-Control',
    'X-Content-Type-Options',
    "stream_get_contents($input, 4097)",
    'privateHostRespond(503',
];
foreach ($required as $contract) {
    if (!str_contains($source, $contract)) {
        throw new RuntimeException('Isolated FPM entrypoint is missing a required security contract: ' . $contract);
    }
}

if (preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\b/', $source) === 1
    || preg_match('/\b(?:eval|shell_exec|exec|passthru|system)\s*\(/', $source) === 1) {
    throw new RuntimeException('Isolated FPM entrypoint must not accept request-controlled config or execute commands.');
}

echo "Private host attestation FPM entrypoint contract tests passed.\n";
