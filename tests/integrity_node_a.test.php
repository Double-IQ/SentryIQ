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
    $node = new IntegrityNodeA($signer, $verifier, $fetch);
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
    nodeAAssert($approved['approved'] === true, 'Matching public file should approve.');
    nodeAAssert(count($verifyCalls) === 2, 'Both manifest and ZIP provenance must be verified.');
    nodeAAssert($approved['checked_paths'] === ['index.php'], 'Configured path should be checked.');

    $tamperedNode = new IntegrityNodeA($signer, $verifier, static fn(string $url): string => 'tampered');
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
    nodeAAssert($rejected['approved'] === false, 'Changed public file must reject.');
    nodeAAssert($rejected['mismatches'][0]['reason'] === 'content_mismatch', 'Mismatch evidence should be retained.');

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
