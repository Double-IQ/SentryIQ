<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeC.php';

use SentryIQ\Updates\IntegrityNodeC;
use SentryIQ\Updates\IntegrityReportSigner;

function nodeCAssert(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$keypair = sodium_crypto_sign_keypair();
$signer = new IntegrityReportSigner(
    'integrity-c',
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

try {
    $wrongSigner = new IntegrityReportSigner(
        'integrity-b',
        base64_encode(sodium_crypto_sign_secretkey($keypair)),
        static fn(): int => 1794200000
    );
    $wrongIdentityRejected = false;
    try {
        new IntegrityNodeC($wrongSigner, $verifier, $fetch);
    } catch (RuntimeException) {
        $wrongIdentityRejected = true;
    }
    nodeCAssert($wrongIdentityRejected, 'Node C must reject a signer configured with another node identity.');
$missingAlertRejected = false;
try { new IntegrityNodeC($signer, $verifier, $fetch); } catch (RuntimeException) { $missingAlertRejected = true; }
nodeCAssert($missingAlertRejected, 'Node C must refuse startup without a direct owner-alert transport.');

    $node = new IntegrityNodeC($signer, $verifier, $fetch, $alertNoop, $headerNoop);
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
    nodeCAssert($approved['approved'] === true, 'Matching public file should approve.');
    nodeCAssert(count($verifyCalls) === 2, 'Both manifest and ZIP provenance must be verified.');
    nodeCAssert($approved['checked_paths'] === ['assets/app.js', '@origin-headers'], 'Configured path should be checked.');
    $approvedEnvelope = json_decode($approved['report'], true, 8, JSON_THROW_ON_ERROR);
    $approvedPayload = json_decode(base64_decode($approvedEnvelope['payload'], true), true, 16, JSON_THROW_ON_ERROR);
    nodeCAssert(($approvedPayload['schema_version'] ?? null) === 2
        && ($approvedPayload['target_origin'] ?? null) === 'https://example.invalid/SentryIQ'
        && ($approvedPayload['manifest_sha256'] ?? null) === hash_file('sha256', $manifestPath),
        'Node C report must sign origin and manifest evidence.');

    $alerts = [];
    $tamperedNode = new IntegrityNodeC(
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
    nodeCAssert($rejected['approved'] === false, 'Changed public file must reject.');
    nodeCAssert($rejected['mismatches'][0]['reason'] === 'content_mismatch', 'Mismatch evidence should be retained.');
    nodeCAssert(count($alerts) === 1 && $alerts[0][0] === 'integrity-c'
        && $alerts[0][1] === 'origin_integrity_mismatch', 'Node C must directly alert its owner on an origin mismatch.');

    $unsafeRejected = false;
    try {
        $node->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['../config.php'], str_repeat('e', 64)
        );
    } catch (RuntimeException) {
        $unsafeRejected = true;
    }
    nodeCAssert($unsafeRejected, 'Path traversal must be rejected.');

    // Manifest attestation failure must abort before any public-origin request.
    $manifestFetchCalls = 0;
    $manifestFailureNode = new IntegrityNodeC(
        $signer,
        static function (string $path, string $version, string $commit, string $installed): void {
            throw new RuntimeException('simulated manifest trust-root failure');
        },
        static function (string $url) use (&$manifestFetchCalls, $publicBody): string {
            $manifestFetchCalls++;
            return $publicBody;
        },
        $alertNoop,
        $headerNoop
    );
    $manifestFailureRejected = false;
    try {
        $manifestFailureNode->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['assets/app.js'], str_repeat('1', 64)
        );
    } catch (RuntimeException) {
        $manifestFailureRejected = true;
    }
    nodeCAssert($manifestFailureRejected && $manifestFetchCalls === 0,
        'Manifest attestation failure must abort before public-origin access.');

    // Artifact attestation failure must also abort before public-origin access.
    $attestationCalls = 0;
    $artifactFetchCalls = 0;
    $artifactFailureNode = new IntegrityNodeC(
        $signer,
        static function (string $path, string $version, string $commit, string $installed) use (&$attestationCalls): void {
            $attestationCalls++;
            if ($attestationCalls === 2) {
                throw new RuntimeException('simulated ZIP attestation failure');
            }
        },
        static function (string $url) use (&$artifactFetchCalls, $publicBody): string {
            $artifactFetchCalls++;
            return $publicBody;
        },
        $alertNoop,
        $headerNoop
    );
    $artifactFailureRejected = false;
    try {
        $artifactFailureNode->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['assets/app.js'], str_repeat('2', 64)
        );
    } catch (RuntimeException) {
        $artifactFailureRejected = true;
    }
    nodeCAssert($artifactFailureRejected && $artifactFetchCalls === 0,
        'ZIP attestation failure must abort before public-origin access.');

    // An origin outage is a signed rejection, never an approval.
    $offlineAlerts = [];
    $offlineNode = new IntegrityNodeC(
        $signer,
        $verifier,
        static function (string $url): string {
            throw new RuntimeException('simulated origin outage');
        },
        static function (string $nodeId, string $reason, array $context) use (&$offlineAlerts): void {
            $offlineAlerts[] = [$nodeId, $reason];
        },
        $headerNoop
    );
    $offline = $offlineNode->verify(
        $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
        'https://example.invalid/SentryIQ', ['assets/app.js'], str_repeat('3', 64)
    );
    nodeCAssert($offline['approved'] === false
        && ($offline['mismatches'][0]['reason'] ?? null) === 'fetch_failed',
        'Origin outage must be represented as signed fetch_failed evidence.');
    nodeCAssert($offlineAlerts === [['integrity-c', 'origin_integrity_mismatch']],
        'Origin outage must trigger Node C direct owner alerting.');


    $attestationAlerts = [];
    $attestationRejected = false;
    $rejectAttestation = static function (): void {
        throw new RuntimeException('synthetic attestation rejection');
    };
    $alertingNode = new IntegrityNodeC(
        $signer,
        $rejectAttestation,
        $fetch,
        static function (string $nodeId, string $reason, array $context) use (&$attestationAlerts): void {
            $attestationAlerts[] = [$nodeId, $reason];
        },
        $headerNoop
    );
    try {
        $alertingNode->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['assets/app.js'], str_repeat('f', 64)
        );
    } catch (RuntimeException) {
        $attestationRejected = true;
    }
    nodeCAssert($attestationRejected && $attestationAlerts === [['integrity-c', 'release_attestation_rejected']],
        'Node C must directly alert its owner when release attestation is rejected.');

    $headerMismatchNode = new IntegrityNodeC(
        $signer,
        $verifier,
        $fetch,
        $alertNoop,
        static fn(string $origin): array => [
            'approved' => false,
            'mismatches' => ['x-frame-options'],
            'headers' => [],
        ]
    );
    $headerRejected = $headerMismatchNode->verify(
        $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
        'https://example.invalid/SentryIQ', ['assets/app.js'], str_repeat('9', 64)
    );
    nodeCAssert($headerRejected['approved'] === false
        && in_array(['path' => '@origin-headers', 'reason' => 'security_header_mismatch'], $headerRejected['mismatches'], true),
        'Origin security-header mismatch must become signed rejection evidence.');

    echo "Integrity Node C tests passed.\n";
} finally {
    @unlink($manifestPath);
    @unlink($artifactPath);
}
