<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationGate.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeA.php';

use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationVerifier;
use SentryIQ\Updates\PrivateHostAttestationGate;

function nodeAAssert(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}


function nodeAPrivateHostGate(bool $approve = true, string $nodeId = 'integrity-a'): PrivateHostAttestationGate
{
    $now = time();
    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $expected = hash('sha256', 'approved deployed file');
    $observed = $approve ? $expected : hash('sha256', 'tampered deployed file');
    $fileMap = ['app/Updates/UpdateManager.php' => $expected];
    $client = new PrivateHostAttestationClient(
        $nodeId,
        str_repeat('A', 64),
        'https://sentryiq.bichet.co.za/private-host-attestation',
        static function (string $url, array $headers, string $body, int $maxBytes) use ($now, $secret, $expected, $observed, $approve): array {
            $request = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
            $payload = [
                'schema_version' => 1,
                'collector_id' => 'sentryiq-host-attestor',
                'issued_at' => $now,
                'expires_at' => $now + 60,
                'nonce' => $request['nonce'],
                'target_origin' => 'https://sentryiq.bichet.co.za',
                'repository' => 'Double-IQ/SentryIQ',
                'repository_id' => '1345956206',
                'release_version' => $request['release_version'],
                'tag' => 'v' . $request['release_version'],
                'commit' => $request['commit'],
                'manifest_sha256' => $request['manifest_sha256'],
                'artifact_sha256' => $request['artifact_sha256'],
                'files' => [[
                    'path' => 'app/Updates/UpdateManager.php',
                    'expected_sha256' => $expected,
                    'observed_sha256' => $observed,
                    'result' => $approve ? 'match' : 'digest_mismatch',
                ]],
                'private_config' => [],
                'decision' => $approve ? 'approve' : 'reject',
            ];
            $bytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            return ['status' => 200, 'body' => json_encode([
                'payload' => base64_encode($bytes),
                'signature' => base64_encode(sodium_crypto_sign_detached($bytes, $secret)),
            ], JSON_THROW_ON_ERROR)];
        }
    );
    $verifier = new PrivateHostAttestationVerifier(base64_encode($public), static fn(): int => $now);
    $gate = new PrivateHostAttestationGate($nodeId, $client, $verifier, $fileMap, []);
    sodium_memzero($secret);
    return $gate;
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
    new IntegrityNodeA($wrongSigner, $verifier, nodeAPrivateHostGate(), $fetch, $alertNoop, $headerNoop);
} catch (Throwable) {
    $wrongIdentityRejected = true;
}
nodeAAssert($wrongIdentityRejected, 'Node A must reject a signer using Node B identity.');
$wrongGateRejected = false;
try { new IntegrityNodeA($signer, $verifier, nodeBPrivateHostGate(), $fetch, $alertNoop, $headerNoop); } catch (RuntimeException) { $wrongGateRejected = true; }
nodeAAssert($wrongGateRejected, 'Node A must reject the other node\'s private-host gate.');
$missingAlertRejected = false;
try { new IntegrityNodeA($signer, $verifier, nodeAPrivateHostGate(), $fetch, null, $headerNoop); } catch (RuntimeException) { $missingAlertRejected = true; }
nodeAAssert($missingAlertRejected, 'Node A must refuse startup without a direct owner-alert transport.');
$missingPrivateHostRejected = false;
try { new IntegrityNodeA($signer, $verifier, null, $fetch, $alertNoop, $headerNoop); } catch (Throwable) { $missingPrivateHostRejected = true; }
nodeAAssert($missingPrivateHostRejected, 'Node A must refuse startup without private-host attestation.');

try {
    $node = new IntegrityNodeA($signer, $verifier, nodeAPrivateHostGate(), $fetch, $alertNoop, $headerNoop);
    $approved = $node->verify(
        $manifestPath,
        $artifactPath,
        'v0.1.3',
        str_repeat('a', 40),
        '0.1.2',
        'https://sentryiq.bichet.co.za',
        ['assets/app.js'],
        str_repeat('c', 64)
    );
    nodeAAssert($approved['approved'] === true, 'Matching public file should approve.');
    $signedEnvelope = json_decode($approved['report'], true, 16, JSON_THROW_ON_ERROR);
    $signedPayload = json_decode(base64_decode($signedEnvelope['payload'], true), true, 32, JSON_THROW_ON_ERROR);
    nodeAAssert(($signedPayload['schema_version'] ?? null) === 2, 'Node report must use the signed event-evidence schema.');
    nodeAAssert(($signedPayload['target_origin'] ?? null) === 'https://sentryiq.bichet.co.za', 'Signed report must bind the monitored origin.');
    nodeAAssert(($signedPayload['manifest_sha256'] ?? null) === $approved['manifest_sha256'], 'Signed report must bind the manifest digest.');
    nodeAAssert(($signedPayload['checked_paths'] ?? null) === ['assets/app.js', '@origin-headers', '@private-host-attestation'], 'Signed report must include checked paths.');
    nodeAAssert(($signedPayload['mismatches'] ?? null) === [], 'Signed report must include mismatch evidence.');

    nodeAAssert(count($verifyCalls) === 2, 'Both manifest and ZIP provenance must be verified.');
    nodeAAssert($approved['checked_paths'] === ['assets/app.js', '@origin-headers', '@private-host-attestation'], 'Configured path should be checked.');

    $alerts = [];
    $tamperedNode = new IntegrityNodeA(
        $signer,
        $verifier,
        nodeAPrivateHostGate(),
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
        'https://sentryiq.bichet.co.za',
        ['assets/app.js'],
        str_repeat('d', 64)
    );
    nodeAAssert($rejected['approved'] === false, 'Changed public file must reject.');
    nodeAAssert($rejected['mismatches'][0]['reason'] === 'content_mismatch', 'Mismatch evidence should be retained.');
    nodeAAssert(count($alerts) === 1 && $alerts[0][0] === 'integrity-a' && $alerts[0][1] === 'origin_integrity_mismatch', 'A rejected origin must trigger the node\'s direct owner alert.');
    $privateHostAlerts = [];
    $privateHostRejectedNode = new IntegrityNodeA(
        $signer,
        $verifier,
        nodeAPrivateHostGate(false),
        $fetch,
        static function (string $nodeId, string $reason, array $context) use (&$privateHostAlerts): void {
            $privateHostAlerts[] = [$nodeId, $reason, $context];
        },
        $headerNoop
    );
    $privateHostRejected = $privateHostRejectedNode->verify(
        $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
        'https://sentryiq.bichet.co.za', ['assets/app.js'], str_repeat('f', 64)
    );
    nodeAAssert($privateHostRejected['approved'] === false
        && in_array(['path' => '@private-host-attestation', 'reason' => 'private_host_attestation_failed'], $privateHostRejected['mismatches'], true),
        'A signed private-host rejection must reject the overall node decision.');
    nodeAAssert(count($privateHostAlerts) === 1 && $privateHostAlerts[0][1] === 'private_host_attestation_rejected',
        'A signed private-host rejection must trigger a direct owner alert.');

    $unsafeRejected = false;
    try {
        $node->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://sentryiq.bichet.co.za', ['../config.php'], str_repeat('e', 64)
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
