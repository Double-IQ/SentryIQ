<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportVerifier.php';

use SentryIQ\Updates\IntegrityReportVerifier;

function integrityReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

if (!extension_loaded('sodium') || !function_exists('sodium_crypto_sign_verify_detached')) {
    throw new RuntimeException('Sodium is required for Integrity Node verifier tests.');
}

$now = 1794200000;
$keys = [];
$secretKeys = [];
foreach (['integrity-a', 'integrity-b'] as $nodeId) {
    $pair = sodium_crypto_sign_keypair();
    $keys[$nodeId] = base64_encode(sodium_crypto_sign_publickey($pair));
    $secretKeys[$nodeId] = sodium_crypto_sign_secretkey($pair);
}
$verifier = new IntegrityReportVerifier($keys, static fn(): int => $now);
$version = '1.2.3';
$commit = str_repeat('a', 40);
$digest = hash('sha256', 'release archive');
$nonce = str_repeat('b', 64);

$makeReport = static function (string $nodeId, array $changes = []) use ($secretKeys, $now, $version, $commit, $digest, $nonce): string {
    $payload = array_replace([
        'schema_version' => 1,
        'node_id' => $nodeId,
        'decision' => 'approve',
        'issued_at' => $now,
        'expires_at' => $now + 180,
        'nonce' => $nonce,
        'repository' => 'Double-IQ/SentryIQ',
        'repository_id' => '1345956206',
        'release_version' => $version,
        'tag' => 'v' . $version,
        'commit' => $commit,
        'artifact_sha256' => $digest,
        'workflow_path' => '.github/workflows/release.yml',
    ], $changes);
    $raw = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    $signature = sodium_crypto_sign_detached($raw, $secretKeys[$nodeId]);
    return json_encode([
        'payload' => base64_encode($raw),
        'signature' => base64_encode($signature),
    ], JSON_THROW_ON_ERROR);
};

$reports = [$makeReport('integrity-a'), $makeReport('integrity-b')];

$eventEvidence = [
    'schema_version' => 2,
    'target_origin' => 'https://sentryiq.bichet.co.za',
    'manifest_sha256' => hash('sha256', 'attested manifest'),
    'checked_paths' => ['index.php', 'assets/app.js'],
    'mismatches' => [],
];
$eventReports = [
    $makeReport('integrity-a', $eventEvidence),
    $makeReport('integrity-b', $eventEvidence),
];
$eventResult = $verifier->assertTwoNodeApproval($eventReports, $version, $commit, $digest, $nonce);
if (($eventResult['approved'] ?? false) !== true) {
    throw new RuntimeException('Valid signed event-evidence reports should remain valid release approvals.');
}
$invalidEventReports = [
    $makeReport('integrity-a', array_replace($eventEvidence, ['target_origin' => 'http://untrusted.invalid'])),
    $eventReports[1],
];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($invalidEventReports, $version, $commit, $digest, $nonce),
    'Version-2 reports with an invalid target origin must be rejected.'
);

$privateHostMismatchEvidence = array_replace($eventEvidence, [
    'checked_paths' => ['assets/app.js', '@private-host-attestation'],
    'mismatches' => [[
        'path' => '@private-host-attestation',
        'reason' => 'private_host_attestation_failed',
    ]],
]);
$falsePrivateHostApproval = [
    $makeReport('integrity-a', $privateHostMismatchEvidence),
    $eventReports[1],
];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($falsePrivateHostApproval, $version, $commit, $digest, $nonce),
    'A signed approval containing a private-host attestation failure must be rejected.'
);
$result = $verifier->assertTwoNodeApproval($reports, $version, $commit, $digest, $nonce);
if (($result['approved'] ?? false) !== true || count($result['node_ids'] ?? []) !== 2) {
    throw new RuntimeException('Two valid independent approvals should pass.');
}

integrityReject(
    fn() => $verifier->assertTwoNodeApproval([$reports[0], $reports[0]], $version, $commit, $digest, $nonce),
    'Duplicate node reports must be rejected.'
);
integrityReject(
    fn() => $verifier->assertTwoNodeApproval([$reports[0]], $version, $commit, $digest, $nonce),
    'A single approval must be rejected.'
);

$tampered = json_decode($reports[0], true, 16, JSON_THROW_ON_ERROR);
$tamperedPayload = json_decode(base64_decode($tampered['payload'], true), true, 32, JSON_THROW_ON_ERROR);
$tamperedPayload['decision'] = 'approve-anyway';
$tampered['payload'] = base64_encode(json_encode($tamperedPayload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
integrityReject(
    fn() => $verifier->assertTwoNodeApproval([json_encode($tampered, JSON_THROW_ON_ERROR), $reports[1]], $version, $commit, $digest, $nonce),
    'A modified signed payload must fail signature verification.'
);

$wrongNonce = [$makeReport('integrity-a', ['nonce' => str_repeat('c', 64)]), $reports[1]];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($wrongNonce, $version, $commit, $digest, $nonce),
    'A report for a different update attempt must be rejected.'
);

$expired = [$makeReport('integrity-a', ['issued_at' => $now - 600, 'expires_at' => $now - 300]), $reports[1]];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($expired, $version, $commit, $digest, $nonce),
    'Expired reports must be rejected.'
);

$wrongDigest = [$makeReport('integrity-a', ['artifact_sha256' => hash('sha256', 'other')]), $reports[1]];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($wrongDigest, $version, $commit, $digest, $nonce),
    'A report for a different artifact must be rejected.'
);

$wrongRepo = [$makeReport('integrity-a', ['repository_id' => '999']), $reports[1]];
integrityReject(
    fn() => $verifier->assertTwoNodeApproval($wrongRepo, $version, $commit, $digest, $nonce),
    'A report for a different immutable repository ID must be rejected.'
);

integrityReject(
    fn() => new IntegrityReportVerifier(['integrity-a' => $keys['integrity-a']], static fn(): int => $now),
    'The verifier must not start with fewer than two configured node keys.'
);

echo "Dual Integrity Node report verifier tests passed.\n";
