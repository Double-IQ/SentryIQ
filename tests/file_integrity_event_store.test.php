<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityEventReportVerifier.php';
require_once __DIR__ . '/../app/Updates/FileIntegrityEventStore.php';

use SentryIQ\Updates\FileIntegrityEventStore;
use SentryIQ\Updates\IntegrityEventReportVerifier;
use SentryIQ\Updates\IntegrityReportSigner;

function storeAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function storeReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException($message);
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sentryiq-node4-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary Node 4 test directory.');
}

try {
    $store = new FileIntegrityEventStore($directory);
    $keyA = sodium_crypto_sign_keypair();
    $secretA = sodium_crypto_sign_secretkey($keyA);
    $publicA = sodium_crypto_sign_publickey($keyA);
    $keyB = sodium_crypto_sign_keypair();
    $publicB = sodium_crypto_sign_publickey($keyB);
    $now = time();

    $version = '0.1.3';
    $commit = str_repeat('b', 40);
    $artifact = str_repeat('c', 64);
    $manifest = str_repeat('d', 64);
    $origin = 'https://sentryiq.bichet.co.za';

    $challenge = $store->issueChallenge(
        'integrity-a',
        $origin,
        $version,
        $commit,
        $artifact,
        $manifest
    );

    $signer = new IntegrityReportSigner('integrity-a', base64_encode($secretA));
    $envelope = $signer->createReport(
        $version,
        $commit,
        $artifact,
        $challenge['nonce'],
        'approve',
        [
            'target_origin' => $origin,
            'manifest_sha256' => $manifest,
            'checked_paths' => ['index.php', 'assets/app.js'],
            'mismatches' => [],
        ]
    );

    $verifier = new IntegrityEventReportVerifier(
        [
            'integrity-a' => base64_encode($publicA),
            'integrity-b' => base64_encode($publicB),
        ],
        [$store, 'consumeAndStore']
    );

    $accepted = $verifier->accept($envelope);
    storeAssert($accepted['accepted'] === true, 'Valid challenged report must be accepted.');
    $snapshot = $store->snapshot();
    storeAssert(count($snapshot['challenges']) === 0, 'Accepted challenge must be consumed.');
    storeAssert(count($snapshot['reports']) === 1, 'Accepted report must be durably retained.');

    storeReject(
        fn() => $verifier->accept($envelope),
        'A consumed challenge must not accept a replay.'
    );

    $wrongBinding = $store->issueChallenge(
        'integrity-a',
        $origin,
        $version,
        $commit,
        $artifact,
        $manifest
    );
    $wrongSigner = $signer->createReport(
        $version,
        $commit,
        $artifact,
        $wrongBinding['nonce'],
        'approve',
        [
            'target_origin' => $origin,
            'manifest_sha256' => str_repeat('e', 64),
            'checked_paths' => ['index.php'],
            'mismatches' => [],
        ]
    );
    storeReject(
        fn() => $verifier->accept($wrongSigner),
        'A report with a mismatched manifest binding must be rejected.'
    );

    $snapshot = $store->snapshot();
    storeAssert(count($snapshot['challenges']) === 1, 'Rejected binding must not consume the legitimate challenge.');
    storeAssert(count($snapshot['reports']) === 1, 'Rejected binding must not create evidence.');
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) {
            unlink($file);
        }
    }
    rmdir($directory);
}

echo "File-backed Node 4 event store tests passed.\n";
