<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEvidenceStore.php';

use SentryIQ\Updates\IntegrityNodeEvidenceStore;
use SentryIQ\Updates\IntegrityReportSigner;

function evidenceStoreAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function evidenceStoreReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-node-c-evidence-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/public';
mkdir($private, 0700, true);
mkdir($web, 0700, true);

try {
    $keyPair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($keyPair);
    $public = sodium_crypto_sign_publickey($keyPair);
    $signer = new IntegrityReportSigner('integrity-c', base64_encode($secret));
    $store = new IntegrityNodeEvidenceStore($private, $web, $signer->publicKeyBase64());
    $manifestDigest = str_repeat('b', 64);
    $artifactDigest = str_repeat('c', 64);
    $commit = str_repeat('a', 40);
    $nonce = str_repeat('d', 64);
    $report = $signer->createReport(
        '1.2.3',
        $commit,
        $artifactDigest,
        $nonce,
        'approve',
        [
            'target_origin' => 'https://sentryiq.bichet.co.za',
            'manifest_sha256' => $manifestDigest,
            'checked_paths' => ['VERSION', 'assets/app.js', '@origin-headers'],
            'mismatches' => [],
        ]
    );
    $stored = $store->append($report, '1.2.3', $commit, $manifestDigest, $artifactDigest, true, $nonce);
    $record = json_decode((string)file_get_contents($stored['evidence_path']), true, 16, JSON_THROW_ON_ERROR);
    evidenceStoreAssert(is_file($stored['evidence_path']), 'Signed Node C evidence must be durably stored.');
    evidenceStoreAssert(((fileperms($stored['evidence_path']) ?: 0) & 0077) === 0, 'Evidence records must be private mode 0600.');
    evidenceStoreAssert(((fileperms($private . '/integrity-node-c-evidence') ?: 0) & 0077) === 0, 'Evidence directory must be private mode 0700.');
    evidenceStoreAssert($record['evidence_id'] === hash('sha256', $report), 'Evidence ID must bind the exact signed envelope.');
    evidenceStoreAssert($record['decision'] === 'approve' && $record['manifest_sha256'] === $manifestDigest,
        'Stored evidence must retain the signed decision and manifest digest.');
    evidenceStoreAssert(sodium_crypto_sign_verify_detached(
        base64_decode(json_decode($report, true, 8, JSON_THROW_ON_ERROR)['signature'], true),
        base64_decode(json_decode($report, true, 8, JSON_THROW_ON_ERROR)['payload'], true),
        $public
    ), 'Stored report signature must verify with the node public key.');

    $oldEvidencePath = $private . '/integrity-node-c-evidence/report-' . (time() - 31 * 86400) . '-' . str_repeat('f', 64) . '.json';
    file_put_contents($oldEvidencePath, '{}');
    chmod($oldEvidencePath, 0600);
    touch($oldEvidencePath, time() - 31 * 86400);
    $retentionNonce = str_repeat('8', 64);
    $retentionReport = $signer->createReport(
        '1.2.3', $commit, $artifactDigest, $retentionNonce, 'approve',
        [
            'target_origin' => 'https://sentryiq.bichet.co.za',
            'manifest_sha256' => $manifestDigest,
            'checked_paths' => ['VERSION', '@origin-headers'],
            'mismatches' => [],
        ]
    );
    $store->append($retentionReport, '1.2.3', $commit, $manifestDigest, $artifactDigest, true, $retentionNonce);
    evidenceStoreAssert(!file_exists($oldEvidencePath), 'Node C must prune evidence older than its 30-day retention window.');
    evidenceStoreReject(fn() => $store->append($report, '1.2.3', $commit, $manifestDigest, $artifactDigest, true), 'A repeated nonce/report must not overwrite an existing evidence record.');
    evidenceStoreReject(fn() => $store->append($report, '1.2.3', $commit, $manifestDigest, $artifactDigest, false, $nonce), 'The signed decision must match the scheduler approval result.');
    evidenceStoreReject(fn() => $store->append($report, '1.2.3', $commit, $manifestDigest, $artifactDigest, true, str_repeat('f', 64)), 'A valid old report must not satisfy a different scheduler challenge nonce.');

    $expiredSigner = new IntegrityReportSigner('integrity-c', base64_encode($secret), static fn(): int => time() - 400);
    $expiredNonce = str_repeat('9', 64);
    $expiredReport = $expiredSigner->createReport(
        '1.2.3', $commit, $artifactDigest, $expiredNonce, 'approve',
        [
            'target_origin' => 'https://sentryiq.bichet.co.za',
            'manifest_sha256' => $manifestDigest,
            'checked_paths' => ['VERSION', '@origin-headers'],
            'mismatches' => [],
        ]
    );
    evidenceStoreReject(
        fn() => $store->append($expiredReport, '1.2.3', $commit, $manifestDigest, $artifactDigest, true, $expiredNonce),
        'Expired signed evidence must not be accepted into the Node C evidence store.'
    );

    $rejectedReport = $signer->createReport(
        '1.2.3',
        $commit,
        $artifactDigest,
        str_repeat('e', 64),
        'reject',
        [
            'target_origin' => 'https://sentryiq.bichet.co.za',
            'manifest_sha256' => $manifestDigest,
            'checked_paths' => ['VERSION', '@origin-headers'],
            'mismatches' => [['path' => '@origin-headers', 'reason' => 'security_header_mismatch']],
        ]
    );
    $rejectedStored = $store->append($rejectedReport, '1.2.3', $commit, $manifestDigest, $artifactDigest, false, str_repeat('e', 64));
    $rejectedRecord = json_decode((string)file_get_contents($rejectedStored['evidence_path']), true, 16, JSON_THROW_ON_ERROR);
    evidenceStoreAssert($rejectedRecord['decision'] === 'reject'
        && $rejectedRecord['mismatches'] === [['path' => '@origin-headers', 'reason' => 'security_header_mismatch']],
        'Node C must durably retain signed rejection evidence and mismatch reasons.');

    $tampered = json_decode($report, true, 8, JSON_THROW_ON_ERROR);
    $tampered['signature'] = base64_encode(str_repeat("x", SODIUM_CRYPTO_SIGN_BYTES));
    evidenceStoreReject(fn() => $store->append(json_encode($tampered, JSON_THROW_ON_ERROR), '1.2.3', $commit, $manifestDigest, $artifactDigest, true, $nonce),
        'Invalid report signatures must be rejected before persistence.');

    $otherSigner = new IntegrityReportSigner('integrity-b', base64_encode($secret));
    $otherReport = $otherSigner->createReport(
        '1.2.3', $commit, $artifactDigest, str_repeat('e', 64), 'approve',
        [
            'target_origin' => 'https://sentryiq.bichet.co.za',
            'manifest_sha256' => $manifestDigest,
            'checked_paths' => ['VERSION', '@origin-headers', '@private-host-attestation'],
            'mismatches' => [],
        ]
    );
    evidenceStoreReject(fn() => $store->append($otherReport, '1.2.3', $commit, $manifestDigest, $artifactDigest, true, str_repeat('e', 64)), 'Evidence from another node identity must be rejected.');

    $insideWebrootRejected = false;
    try {
        new IntegrityNodeEvidenceStore($web, $web, base64_encode($public));
    } catch (RuntimeException) {
        $insideWebrootRejected = true;
    }
    evidenceStoreAssert($insideWebrootRejected, 'Evidence must never be stored inside the public webroot.');
    sodium_memzero($secret);
} finally {
    $evidenceDirectory = $private . '/integrity-node-c-evidence';
    foreach (glob($evidenceDirectory . '/*.json') ?: [] as $file) @unlink($file);
    @rmdir($evidenceDirectory);
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}

echo "Integrity Node C evidence store tests passed.\\n";
