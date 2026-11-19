<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityOriginSecurityHeaderVerifier.php';

use SentryIQ\Updates\IntegrityOriginSecurityHeaderVerifier;

function originHeaderAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function originHeaderReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$headers = [
    'Strict-Transport-Security' => 'max-age=31536000',
    'X-Content-Type-Options' => 'nosniff',
    'X-Frame-Options' => 'DENY',
    'Referrer-Policy' => 'strict-origin-when-cross-origin',
    'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy' => "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
];
$verifier = new IntegrityOriginSecurityHeaderVerifier(
    static fn(string $url): array => ['status' => 200, 'headers' => $headers]
);
$result = $verifier->verify('https://sentryiq.bichet.co.za');
originHeaderAssert($result['approved'] === true && $result['mismatches'] === [], 'Expected origin headers should approve.');

$weak = new IntegrityOriginSecurityHeaderVerifier(
    static fn(string $url): array => ['status' => 200, 'headers' => ['X-Content-Type-Options' => 'nosniff']]
);
$weakResult = $weak->verify('https://sentryiq.bichet.co.za');
originHeaderAssert($weakResult['approved'] === false, 'Missing required headers must reject.');
originHeaderAssert(in_array('strict-transport-security', $weakResult['mismatches'], true), 'Missing HSTS must be identified.');
originHeaderAssert(in_array('content-security-policy:frame-ancestors \'none\'', $weakResult['mismatches'], true),
    'Missing frame-ancestors policy must be identified.');

$shortHsts = new IntegrityOriginSecurityHeaderVerifier(
    static fn(string $url): array => ['status' => 200, 'headers' => ['Strict-Transport-Security' => 'max-age=100']]
);
originHeaderAssert(in_array('strict-transport-security', $shortHsts->verify('https://sentryiq.bichet.co.za')['mismatches'], true),
    'Short HSTS max-age must reject.');

$redirect = new IntegrityOriginSecurityHeaderVerifier(
    static fn(string $url): array => ['status' => 301, 'headers' => $headers]
);
originHeaderReject(fn() => $redirect->verify('https://sentryiq.bichet.co.za'),
    'Origin header probe must not follow redirects.');

originHeaderReject(fn() => $verifier->verify('https://attacker.example'),
    'Origin header verifier must pin the canonical origin.');

echo "Integrity origin security header tests passed.\n";
