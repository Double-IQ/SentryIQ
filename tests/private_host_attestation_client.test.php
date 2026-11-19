<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';

use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationVerifier;

function privateHostClientAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function privateHostClientReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$pair = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey($pair);
$public = sodium_crypto_sign_publickey($pair);
$now = time();
$nonce = str_repeat('a', 64);
$commit = str_repeat('b', 40);
$manifest = hash('sha256', 'manifest');
$artifact = hash('sha256', 'artifact');
$payload = [
    'schema_version' => 1,
    'collector_id' => 'sentryiq-host-attestor',
    'issued_at' => $now,
    'expires_at' => $now + 60,
    'nonce' => $nonce,
    'target_origin' => 'https://sentryiq.bichet.co.za',
    'repository' => 'Double-IQ/SentryIQ',
    'repository_id' => '1345956206',
    'release_version' => '1.2.3',
    'tag' => 'v1.2.3',
    'commit' => $commit,
    'manifest_sha256' => $manifest,
    'artifact_sha256' => $artifact,
    'files' => [[
        'path' => 'app/release.php',
        'expected_sha256' => hash('sha256', 'release'),
        'observed_sha256' => hash('sha256', 'release'),
        'result' => 'match',
    ]],
    'private_config' => [],
    'decision' => 'approve',
];
$payloadBytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
$envelope = json_encode([
    'payload' => base64_encode($payloadBytes),
    'signature' => base64_encode(sodium_crypto_sign_detached($payloadBytes, $secret)),
], JSON_THROW_ON_ERROR);

$captured = [];
$token = str_repeat('T', 64);
$client = new PrivateHostAttestationClient(
    'integrity-a',
    $token,
    'https://sentryiq.bichet.co.za/private-host-attestation',
    static function (string $url, array $headers, string $body, int $maxBytes) use (&$captured, $envelope): array {
        $captured = ['url' => $url, 'headers' => $headers, 'body' => $body, 'max' => $maxBytes];
        return ['status' => 200, 'body' => $envelope];
    }
);
$returned = $client->request($nonce, 'v1.2.3', $commit, $manifest, $artifact);
privateHostClientAssert($returned === $envelope, 'Client must return original envelope bytes unchanged.');
privateHostClientAssert($captured['url'] === 'https://sentryiq.bichet.co.za/private-host-attestation'
    && ($captured['headers']['Authorization'] ?? null) === 'Bearer ' . $token
    && $captured['max'] === 1_048_576,
    'Client must use the pinned HTTPS route, node token and bounded response size.');
$request = json_decode($captured['body'], true, 8, JSON_THROW_ON_ERROR);
privateHostClientAssert(($request['node_id'] ?? null) === 'integrity-a'
    && ($request['nonce'] ?? null) === $nonce
    && !array_key_exists('paths', $request),
    'Client must bind node identity and challenge without allowing caller-selected paths.');

$verifier = new PrivateHostAttestationVerifier(base64_encode($public), static fn(): int => $now);
$verified = $verifier->assertAttested($returned, $nonce, '1.2.3', $commit, $manifest, $artifact,
    ['app/release.php' => hash('sha256', 'release')], []);
privateHostClientAssert($verified['approved'] === true, 'Client response must remain verifiable by the pinned collector key.');

privateHostClientReject(
    fn() => new PrivateHostAttestationClient('integrity-c', $token),
    'Node C must not use the A/B Node 4-facing collector client.'
);
privateHostClientReject(
    fn() => new PrivateHostAttestationClient('integrity-a', $token, 'https://attacker.invalid/private-host-attestation'),
    'Client must reject a non-canonical collector endpoint.'
);
$unavailable = new PrivateHostAttestationClient(
    'integrity-b', $token, 'https://sentryiq.bichet.co.za/private-host-attestation',
    static fn(): array => ['status' => 503, 'body' => '']
);
privateHostClientReject(
    fn() => $unavailable->request($nonce, '1.2.3', $commit, $manifest, $artifact),
    'Client must fail closed when the collector transport is unavailable.'
);

sodium_memzero($secret);
echo "Private host attestation client tests passed.\n";
