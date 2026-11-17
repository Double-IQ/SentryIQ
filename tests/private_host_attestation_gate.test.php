<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationGate.php';

use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationVerifier;
use SentryIQ\Updates\PrivateHostAttestationGate;

function privateHostGateAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function privateHostGateReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$now = time();
$pair = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey($pair);
$public = sodium_crypto_sign_publickey($pair);
$nonce = str_repeat('a', 64);
$version = '1.2.3';
$commit = str_repeat('b', 40);
$manifest = hash('sha256', 'manifest');
$artifact = hash('sha256', 'artifact');
$fileDigest = hash('sha256', 'release-file');
$configDigest = hash('sha256', 'private-config');
$payload = [
    'schema_version' => 1,
    'collector_id' => 'sentryiq-host-attestor',
    'issued_at' => $now,
    'expires_at' => $now + 60,
    'nonce' => $nonce,
    'target_origin' => 'https://sentryiq.bichet.co.za',
    'repository' => 'Double-IQ/SentryIQ',
    'repository_id' => '1345956206',
    'release_version' => $version,
    'tag' => 'v' . $version,
    'commit' => $commit,
    'manifest_sha256' => $manifest,
    'artifact_sha256' => $artifact,
    'files' => [[
        'path' => 'app/release.php',
        'expected_sha256' => $fileDigest,
        'observed_sha256' => $fileDigest,
        'result' => 'match',
    ]],
    'private_config' => [[
        'policy_id' => 'node-private-config',
        'expected_sha256' => $configDigest,
        'observed_sha256' => $configDigest,
        'result' => 'match',
    ]],
    'decision' => 'approve',
];
$payloadBytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
$envelope = json_encode([
    'payload' => base64_encode($payloadBytes),
    'signature' => base64_encode(sodium_crypto_sign_detached($payloadBytes, $secret)),
], JSON_THROW_ON_ERROR);

$client = new PrivateHostAttestationClient(
    'integrity-a',
    str_repeat('A', 64),
    'https://sentryiq.bichet.co.za/private-host-attestation',
    static fn(): array => ['status' => 200, 'body' => $envelope]
);
$verifier = new PrivateHostAttestationVerifier(base64_encode($public), static fn(): int => $now);
$gate = new PrivateHostAttestationGate(
    'integrity-a',
    $client,
    $verifier,
    ['app/release.php' => $fileDigest],
    ['node-private-config' => $configDigest]
);
$result = $gate($version, $commit, $manifest, $artifact, $nonce, [], 'https://sentryiq.bichet.co.za');
privateHostGateAssert($result['approved'] === true && $result['mismatches'] === [],
    'A correctly bound transport, collector pin and policy must approve.');
privateHostGateAssert($gate->nodeId() === 'integrity-a'
    && preg_match('/^[a-f0-9]{64}$/', $gate->credentialFingerprint()) === 1
    && preg_match('/^[a-f0-9]{64}$/', $gate->collectorKeyFingerprint()) === 1,
    'Gate must expose only stable audit fingerprints, not credentials or key material.');

privateHostGateReject(
    fn() => new PrivateHostAttestationGate(
        'integrity-b', $client, $verifier,
        ['app/release.php' => $fileDigest],
        ['node-private-config' => $configDigest]
    ),
    'Node B must not be wired to a Node A collector client.'
);
privateHostGateReject(
    fn() => new PrivateHostAttestationGate(
        'integrity-a', $client, $verifier, [], []
    ),
    'An empty deployed-file policy must fail at bootstrap.'
);
privateHostGateReject(
    fn() => $gate($version, $commit, $manifest, $artifact, $nonce, [], 'https://attacker.invalid'),
    'Gate must reject a non-canonical SentryIQ origin.'
);

sodium_memzero($secret);
echo "Private host attestation gate tests passed.\n";
