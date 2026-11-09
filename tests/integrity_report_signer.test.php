<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityReportVerifier.php';

use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\IntegrityReportVerifier;

function assertSigner(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}

$keyA = sodium_crypto_sign_keypair();
$keyB = sodium_crypto_sign_keypair();
$secretA = sodium_crypto_sign_secretkey($keyA);
$secretB = sodium_crypto_sign_secretkey($keyB);
$publicA = sodium_crypto_sign_publickey($keyA);
$publicB = sodium_crypto_sign_publickey($keyB);

$clock = static fn(): int => 1794200000;
$signerA = new IntegrityReportSigner('integrity-a', base64_encode($secretA), $clock);
$signerB = new IntegrityReportSigner('integrity-b', base64_encode($secretB), $clock);

$nonce = bin2hex(random_bytes(32));
$commit = str_repeat('a', 40);
$digest = str_repeat('b', 64);
$reportA = $signerA->createReport('v0.1.3', $commit, $digest, $nonce);
$reportB = $signerB->createReport('0.1.3', $commit, $digest, $nonce);

$verifier = new IntegrityReportVerifier([
    'integrity-a' => base64_encode($publicA),
    'integrity-b' => base64_encode($publicB),
], $clock);

$result = $verifier->assertTwoNodeApproval(
    [$reportA, $reportB],
    '0.1.3',
    $commit,
    $digest,
    $nonce
);
assertSigner($result['approved'] === true, 'Two signer reports should verify.');
assertSigner(count($result['node_ids']) === 2, 'Both node identities should be present.');

$badNonceRejected = false;
try {
    $verifier->assertTwoNodeApproval([$reportA, $reportB], '0.1.3', $commit, $digest, str_repeat('c', 64));
} catch (RuntimeException) {
    $badNonceRejected = true;
}
assertSigner($badNonceRejected, 'Reports for a different nonce must be rejected.');

$rejectReport = $signerA->createReport('0.1.3', $commit, $digest, $nonce, 'reject');
$rejectRejected = false;
try {
    $verifier->assertTwoNodeApproval([$rejectReport, $reportB], '0.1.3', $commit, $digest, $nonce);
} catch (RuntimeException) {
    $rejectRejected = true;
}
assertSigner($rejectRejected, 'A signed rejection must not be accepted as approval.');

$invalidKeyRejected = false;
try {
    new IntegrityReportSigner('integrity-a', base64_encode(random_bytes(12)), $clock);
} catch (RuntimeException) {
    $invalidKeyRejected = true;
}
assertSigner($invalidKeyRejected, 'Malformed private keys must be rejected.');

echo "Integrity report signer tests passed.\n";
