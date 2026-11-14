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

$publicBody = "<?php echo 'SentryIQ';\n";
$manifest = [
    'format' => 2,
    'repository' => 'Double-IQ/SentryIQ',
    'repository_id' => '1345956206',
    'version' => '0.1.3',
    'commit' => str_repeat('a', 40),
    'workflow_path' => '.github/workflows/release.yml',
    'files' => [[
        'path' => 'index.php',
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

    $node = new IntegrityNodeC($signer, $verifier, $fetch);
    $approved = $node->verify(
        $manifestPath,
        $artifactPath,
        'v0.1.3',
        str_repeat('a', 40),
        '0.1.2',
        'https://example.invalid/SentryIQ',
        ['index.php'],
        str_repeat('c', 64)
    );
    nodeCAssert($approved['approved'] === true, 'Matching public file should approve.');
    nodeCAssert(count($verifyCalls) === 2, 'Both manifest and ZIP provenance must be verified.');
    nodeCAssert($approved['checked_paths'] === ['index.php'], 'Configured path should be checked.');

    $tamperedNode = new IntegrityNodeC($signer, $verifier, static fn(string $url): string => 'tampered');
    $rejected = $tamperedNode->verify(
        $manifestPath,
        $artifactPath,
        '0.1.3',
        str_repeat('a', 40),
        '0.1.2',
        'https://example.invalid/SentryIQ',
        ['index.php'],
        str_repeat('d', 64)
    );
    nodeCAssert($rejected['approved'] === false, 'Changed public file must reject.');
    nodeCAssert($rejected['mismatches'][0]['reason'] === 'content_mismatch', 'Mismatch evidence should be retained.');

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

    // Fail closed if attestation verification of the manifest fails.
    $fetchCalls = 0;
    $manifestFailureNode = new IntegrityNodeC(
        $signer,
        static function (string $path, string $version, string $commit, string $installed): void {
            throw new RuntimeException('simulated trust-root refresh failure');
        },
        static function (string $url) use (&$fetchCalls): string {
            $fetchCalls++;
            return $publicBody;
        }
    );
    $manifestFailureRejected = false;
    try {
        $manifestFailureNode->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['index.php'], str_repeat('f', 64)
        );
    } catch (RuntimeException) {
        $manifestFailureRejected = true;
    }
    nodeCAssert($manifestFailureRejected, 'Manifest attestation failure must abort verification.');
    nodeCAssert($fetchCalls === 0, 'No origin fetch may occur after manifest attestation failure.');

    // Fail closed independently if the artifact attestation fails after the manifest passes.
    $attestationCall = 0;
    $artifactFailureNode = new IntegrityNodeC(
        $signer,
        static function (string $path, string $version, string $commit, string $installed) use (&$attestationCall): void {
            $attestationCall++;
            if ($attestationCall === 2) {
                throw new RuntimeException('simulated artifact attestation failure');
            }
        },
        static function (string $url) use (&$fetchCalls): string {
            $fetchCalls++;
            return $publicBody;
        }
    );
    $artifactFailureRejected = false;
    try {
        $artifactFailureNode->verify(
            $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
            'https://example.invalid/SentryIQ', ['index.php'], str_repeat('1', 64)
        );
    } catch (RuntimeException) {
        $artifactFailureRejected = true;
    }
    nodeCAssert($artifactFailureRejected, 'Artifact attestation failure must abort verification.');
    nodeCAssert($fetchCalls === 0, 'No origin fetch may occur after artifact attestation failure.');

    // An origin outage is represented as a signed rejection, never approval.
    $offlineNode = new IntegrityNodeC(
        $signer,
        $verifier,
        static function (string $url): string {
            throw new RuntimeException('simulated network outage');
        }
    );
    $offline = $offlineNode->verify(
        $manifestPath, $artifactPath, '0.1.3', str_repeat('a', 40), '0.1.2',
        'https://example.invalid/SentryIQ', ['index.php'], str_repeat('2', 64)
    );
    nodeCAssert($offline['approved'] === false, 'Origin network failure must never approve.');
    nodeCAssert(
        ($offline['mismatches'][0]['reason'] ?? null) === 'fetch_failed',
        'Origin network failure must be recorded as fetch_failed.'
    );

    echo "Integrity Node C tests passed.\n";
} finally {
    @unlink($manifestPath);
    @unlink($artifactPath);
}
