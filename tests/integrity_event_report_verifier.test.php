<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityEventReportVerifier.php';

use SentryIQ\Updates\IntegrityEventReportVerifier;

function eventAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function eventEnvelope(string $secretKey, array $payload): string
{
    $raw = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    return json_encode([
        'payload' => base64_encode($raw),
        'signature' => base64_encode(sodium_crypto_sign_detached($raw, $secretKey)),
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
}

$now = 1794900000;
$keyA = sodium_crypto_sign_keypair();
$keyB = sodium_crypto_sign_keypair();
$secretA = sodium_crypto_sign_secretkey($keyA);
$secretB = sodium_crypto_sign_secretkey($keyB);
$publicA = sodium_crypto_sign_publickey($keyA);
$publicB = sodium_crypto_sign_publickey($keyB);
$encodedA = base64_encode($publicA);
$encodedB = base64_encode($publicB);
$consumed = [];

$store = static function (string $nodeId, array $payload, string $envelope, string $raw) use (&$consumed): string {
    $nonceKey = $nodeId . ':' . $payload['nonce'];
    if (isset($consumed[$nonceKey])) {
        throw new RuntimeException('Challenge already consumed.');
    }
    // A production adapter performs this compare/consume and insert in one DB transaction.
    $consumed[$nonceKey] = hash('sha256', $raw);
    return 'event-' . count($consumed);
};

$verifier = new IntegrityEventReportVerifier(
    ['integrity-a' => $encodedA, 'integrity-b' => $encodedB],
    $store,
    static fn(): int => $now
);

$payload = [
    'schema_version' => 2,
    'node_id' => 'integrity-a',
    'decision' => 'approve',
    'issued_at' => $now,
    'expires_at' => $now + 300,
    'nonce' => str_repeat('a', 64),
    'repository' => 'Double-IQ/SentryIQ',
    'repository_id' => '1345956206',
    'release_version' => '0.1.3',
    'tag' => 'v0.1.3',
    'commit' => str_repeat('b', 40),
    'artifact_sha256' => str_repeat('c', 64),
    'workflow_path' => '.github/workflows/release.yml',
    'target_origin' => 'https://sentryiq.bichet.co.za',
    'manifest_sha256' => str_repeat('d', 64),
    'checked_paths' => ['assets/app.js', '@origin-headers'],
    'mismatches' => [],
];

$valid = eventEnvelope($secretA, $payload);
$accepted = $verifier->accept($valid);
eventAssert($accepted['accepted'] === true, 'Valid Node A report should be accepted.');
eventAssert($accepted['node_id'] === 'integrity-a', 'Accepted report must retain its signed node identity.');
eventAssert($accepted['report_id'] === 'event-1', 'Accepted report must return durable report ID.');

$reject = static function (callable $operation, string $message): void {
    try {
        $operation();
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException($message);
};

$reject(fn() => $verifier->accept($valid), 'Replayed report must be rejected by the atomic challenge store.');

$outerDuplicate = '{"payload":"ambiguous",' . substr($valid, 1);
$reject(
    fn() => $verifier->accept($outerDuplicate),
    'Duplicate envelope keys must be rejected before signature processing.'
);

$outer = json_decode($valid, true, 8, JSON_THROW_ON_ERROR);
$rawPayload = base64_decode($outer['payload'], true);
$duplicateDecisionPayload = str_replace(
    '"decision":"approve"',
    '"decision":"approve","decision":"reject"',
    $rawPayload
);
$duplicateDecisionEnvelope = json_encode([
    'payload' => base64_encode($duplicateDecisionPayload),
    'signature' => base64_encode(sodium_crypto_sign_detached($duplicateDecisionPayload, $secretA)),
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
$reject(
    fn() => $verifier->accept($duplicateDecisionEnvelope),
    'Duplicate signed payload fields must be rejected even when the altered payload has a valid signature.'
);

$nestedDuplicatePayload = array_replace($payload, [
    'decision' => 'reject',
    'mismatches' => [['path' => 'assets/app.js', 'reason' => 'content_mismatch']],
]);
$nestedRaw = json_encode($nestedDuplicatePayload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
$nestedRaw = str_replace(
    '"path":"assets/app.js"',
    '"path":"assets/app.js","path":"assets/app.js"',
    $nestedRaw
);
$nestedDuplicateEnvelope = json_encode([
    'payload' => base64_encode($nestedRaw),
    'signature' => base64_encode(sodium_crypto_sign_detached($nestedRaw, $secretA)),
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
$reject(
    fn() => $verifier->accept($nestedDuplicateEnvelope),
    'Duplicate nested evidence fields must be rejected.'
);

$badSignature = json_decode($valid, true, 8, JSON_THROW_ON_ERROR);
$badSignature['signature'] = base64_encode(random_bytes(SODIUM_CRYPTO_SIGN_BYTES));
$reject(
    fn() => $verifier->accept(json_encode($badSignature, JSON_THROW_ON_ERROR)),
    'Forged signature must be rejected.'
);

$nodeBPayload = array_replace($payload, [
    'node_id' => 'integrity-b',
    'decision' => 'reject',
    'nonce' => str_repeat('e', 64),
    'checked_paths' => ['assets/app.js', '@origin-headers', '@private-host-attestation'],
    'mismatches' => [
        ['path' => '@origin-headers', 'reason' => 'security_header_mismatch'],
        ['path' => '@private-host-attestation', 'reason' => 'private_host_attestation_failed'],
    ],
]);
$nodeBEnvelope = eventEnvelope($secretB, $nodeBPayload);
$nodeB = $verifier->accept($nodeBEnvelope);
eventAssert($nodeB['decision'] === 'reject', 'Signed rejection must be retained as an accepted event.');

$unsafePayload = array_replace($payload, [
    'nonce' => str_repeat('f', 64),
    'checked_paths' => ['../private/config.php'],
]);
$reject(
    fn() => $verifier->accept(eventEnvelope($secretA, $unsafePayload)),
    'Path traversal evidence must be rejected.'
);

$encodedPathPayload = array_replace($payload, [
    'nonce' => str_repeat('2', 64),
    'checked_paths' => ['%2e%2e/private/config.php'],
]);
$reject(
    fn() => $verifier->accept(eventEnvelope($secretA, $encodedPathPayload)),
    'Encoded traversal evidence must be rejected.'
);

$repeatedSlashPayload = array_replace($payload, [
    'nonce' => str_repeat('3', 64),
    'checked_paths' => ['assets//app.js'],
]);
$reject(
    fn() => $verifier->accept(eventEnvelope($secretA, $repeatedSlashPayload)),
    'Repeated-slash evidence paths must be rejected.'
);

$conflictingPayload = array_replace($payload, [
    'nonce' => str_repeat('1', 64),
    'decision' => 'approve',
    'mismatches' => [['path' => 'assets/app.js', 'reason' => 'content_mismatch']],
]);
$reject(
    fn() => $verifier->accept(eventEnvelope($secretA, $conflictingPayload)),
    'Approval with mismatch evidence must be rejected.'
);

echo "Integrity event report verifier tests passed.\\n";
