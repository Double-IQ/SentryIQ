<?php

declare(strict_types=1);

use SentryIQ\Updates\NativeSigstoreReleaseVerifier;

if ($argc !== 4) {
    fwrite(STDERR, "Usage: php native_release_attestation.integration.php AUTOLOAD ZIP PRIVATE_DIR\n");
    exit(2);
}

[$script, $autoload, $zip, $privateDirectory] = $argv;
foreach ([$autoload, $zip] as $path) {
    if (!is_file($path) || !is_readable($path)) {
        throw new RuntimeException('Integration-test input file is unavailable: ' . $path);
    }
}
if (!is_dir($privateDirectory) && !mkdir($privateDirectory, 0700, true) && !is_dir($privateDirectory)) {
    throw new RuntimeException('Unable to create isolated integration-test data directory.');
}
chmod($privateDirectory, 0700);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';
require_once __DIR__ . '/../app/Updates/FulcioCertificateClaims.php';
require_once __DIR__ . '/../app/Updates/SnappyBlockDecoder.php';
require_once __DIR__ . '/../app/Updates/SigstoreProvenance.php';
require_once __DIR__ . '/../app/Updates/NativeSigstoreReleaseVerifier.php';

$invalidTokenRejected = false;
try {
    new NativeSigstoreReleaseVerifier($autoload, $privateDirectory, 'invalid-token');
} catch (Throwable) {
    $invalidTokenRejected = true;
}
if (!$invalidTokenRejected) throw new RuntimeException('Native verifier must reject malformed optional GitHub API tokens.');

$verifier = new NativeSigstoreReleaseVerifier($autoload, $privateDirectory);
$claims = $verifier->verifyRelease($zip, '0.1.2');

if (($claims['cryptographically_verified'] ?? false) !== true
    || ($claims['repository'] ?? null) !== 'Double-IQ/SentryIQ'
    || ($claims['source_ref'] ?? null) !== 'refs/tags/v0.1.2'
    || ($claims['source_commit'] ?? null) !== '9c639a4792cadd5421f01ed198ba2a9261c5145f'
    || ($claims['subject_sha256'] ?? null) !== '41cc5fc46055836ebb21ed4501bd6bd3ace249c4f352da0373b85e5a57d9c49e') {
    throw new RuntimeException('The v0.1.2 release attestation did not satisfy the expected authenticated claims.');
}

echo "Native v0.1.2 release attestation verified: signature, Fulcio identity, Rekor proof, SLSA provenance, source commit, and ZIP digest.\n";
