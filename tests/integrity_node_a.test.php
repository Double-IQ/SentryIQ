<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeA.php';

use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityReportSigner;

function nodeAAssert(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$keypair = sodium_crypto_sign_keypair();
$signer = new IntegrityReportSigner(
    'integrity-a',
    base64_encode(sodium_crypto_sign_secretkey($keypair)),
    static fn(): int => 1794200000
);

$publicBody = "console.log('SentryIQ');\n";
$manifest = [
    'format' => 2,
    'repository' => 'Double-IQ/SentryIQ',
    'repository_id' => '1345956206',
    'version' => '0.1.3',
    'commit' => str_repeat('a', 40),
    'workflow_path' => '.github/workflows/release.yml',
    'public_files' => ['assets/app.js'],
    'public_http_files' => ['assets/app.js'],
    'files' => [[
        'path' => 'assets/app.js',
        'size' => strlen($publicBody),
        'sha256' => hash('sha256', $publicBody),
    ]],
];

$manifestPath = tempnam(sys_get_temp_dir(), 'sentryiq-manifest-');
$artifactPath = tempnam(sys_get_temp_dir(), 'sentryiq-zip-');
file_put_contents($manifestPath, json_encode($manifest, JSON_THROW_ON_ERROR));
file_put_contents($artifactPath, "synthetic zip bytes");

$verifyCalls = [];
$verifier = static function (string $path, string $version, string $commit, string $installed) use (&$verifyCalls): void {
    $verifyCalls[] = [$path, $version, $commit, $installed];
};
$fetch = static fn(string $url): string => $publicBody;
$alertNoop = static function (string $nodeId, string $reason, array $context): void {};
$headerNoop = static fn(string $origin): array => ['approved' => true, 'mismatches' => [], 'headers' => []];

$wrongIdentityRejected = false;
try {
    $wrongSigner = new IntegrityReportSigner(
        'integrity-b',
        base64_encode(sodium_crypto_sign_secretkey($keypair)),
        static fn(): int => 1794200000
    );
    new IntegrityNodeA($wrongSigner, $verifier, $fetch);
} catch (RuntimeException) {
    $wrongIdentityRejected = true;
}
nodeAAssert($wrongIdentityRejected, 'Node A must reject a signer using Node B identity.');
$missingAlertRejected = false;
try { new IntegrityNodeA($signer, $verifier, $fetch); } catch (RuntimeException) { $missingAlertRejected = true; }
nodeAAssert($missingAlertRejected, 'Node A must refuse startup without a direct owner-alert transport.');

try {
    $node = new IntegrityNodeA($signer, $verifier, $fetch, $alertNoop, $headerNoop);
    $approved = $node->verify(
        $manifestPath,
        $artifactPath,
        'v0.1.3',
        str_repeat('a', 40),
        '0.1.2',
        'https://example.invalid/SentryIQ',
        ['assets/app.js'],
        str_repeat('c', 64)
    );
    nodeAAssert($approved['approved'] === true, 'Matching public file should approve.');
    $signedEnvelope = json_decode($approved['report'], true, 16, JSON_THROW_ON_ERROR);
    $signedPayload = json_decode(base64_decode($signedEnvelope['payload'], true), true, 32, JSON_THROW_ON_ERROR);
    nodeAAssert(($signedPayload['schema_version'] ?? null) === 2, 'Node report must use the signed event-evidence schema.');
    nodeAAssert(($signedPayload['target_origin'] ?? null) === 'https://example.invalid/SentryIQ', 'Signed report must bind the monitored origin.');
    nodeAAssert(($signedPayload['manifest_sha256'] ?? null) === $approved['manifest_sha256'], 'Signed report must bind the manifest digest.');
    nodeAAssert(($signedPayload['checked_paths'] ?? null) === ['assets/app.js'], 'Signed report must include checked paths.');
    nodeAAssert(($signedPayload['mismatches'] ?? null) === [], 'Signed report must include mismatch evidence.');

    nodeAAssert(count($verifyCalls) === 2, 'Both manifest and ZIP provenance must be verified.');
    nodeAAssert($approved['checked_paths'] === ['assets/app.js'], 'Configured path should be checked.');

    $alerts = [];
    $tamperedNode = new IntegrityNodeA(
        $signer,
        $verifier,
        static fn(string $url): string => 'tampered',
        static function (string $nodeId, string $reason, array $context) use (&$alerts): void {
            $alerts[] = [$nodeId, $reason, $context];
        },
        $headerNoop
    );
    $rejected = $tamperedNode->verify(
        $manifestPath,
        $artifactPath,
        '0.1.3',
        str_repeat('a', 40),
        '0.1.2',
        'https://example.invalid/SentryIQ',
        ['assets/app.js'],
        str_repeat('d', 64)
    );
    nodeAAssert($rejected['approved'] === false, 'Changed public file must reject.');
    nodeAAssert($rejected['mismatches'][0]['reason'] === 'content_mismatch', 'Mismatch evidence should be retained.');
    nodeAAssert(count($alerts) === 1 && $alerts[0][0] === 'integrity-a' && $alerts[0][1] === 'origin_integrity_mismatch', 'A rejected origin must trigger the node\'s direct owner alert.');

    $unsafeRejected = false;
    try {
        $node->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['../config.php'], str_repeat('e', 64)
        );
    } catch (RuntimeException) {
        $unsafeRejected = true;
    }
    nodeAAssert($unsafeRejected, 'Path traversal must be rejected.');

    echo "Integrity Node A tests passed.\n";
} finally {
    @unlink($manifestPath);
    @unlink($artifactPath);
}
