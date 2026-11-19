<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';

use SentryIQ\Updates\PrivateHostAttestationVerifier;

function privateHostAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function privateHostReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$now = time();
$pair = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey($pair);
$public = sodium_crypto_sign_publickey($pair);
$verifier = new PrivateHostAttestationVerifier(base64_encode($public), static fn(): int => $now);
$nonce = str_repeat('a', 64);
$version = '1.2.3';
$commit = str_repeat('b', 40);
$manifest = hash('sha256', 'manifest');
$artifact = hash('sha256', 'archive');
$filePolicy = [
    'app/Updates/UpdateManager.php' => hash('sha256', 'release-file-a'),
    'runtime/bootstrap.php' => hash('sha256', 'release-file-b'),
];
$configPolicy = [
    'private-bootstrap-config' => hash('sha256', 'approved-private-config'),
];

$makeEnvelope = static function (array $changes = []) use (
    $secret, $now, $nonce, $version, $commit, $manifest, $artifact, $filePolicy, $configPolicy
): string {
    $files = [];
    foreach ($filePolicy as $path => $digest) {
        $files[] = [
            'path' => $path,
            'expected_sha256' => $digest,
            'observed_sha256' => $digest,
            'result' => 'match',
        ];
    }
    $config = [];
    foreach ($configPolicy as $id => $digest) {
        $config[] = [
            'policy_id' => $id,
            'expected_sha256' => $digest,
            'observed_sha256' => $digest,
            'result' => 'match',
        ];
    }
    $payload = array_replace([
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
        'files' => $files,
        'private_config' => $config,
        'decision' => 'approve',
    ], $changes);
    $bytes = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    return json_encode([
        'payload' => base64_encode($bytes),
        'signature' => base64_encode(sodium_crypto_sign_detached($bytes, $secret)),
    ], JSON_THROW_ON_ERROR);
};

$expectedFiles = static fn(): array => $filePolicy;
$expectedConfig = static fn(): array => $configPolicy;
$good = $verifier->assertAttested(
    $makeEnvelope(), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()
);
privateHostAssert($good['approved'] === true && $good['files_checked'] === 2
    && $good['private_config_checked'] === 1 && $good['mismatches'] === [],
    'A valid signed private-host attestation should be accepted.');

$wrongNonce = str_repeat('c', 64);
privateHostReject(
    fn() => $verifier->assertAttested($makeEnvelope(['collector_id' => 'untrusted-collector']), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'An attestation carrying an unrecognized collector identity must be rejected.'
);

privateHostReject(
    fn() => $verifier->assertAttested($makeEnvelope(), $wrongNonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'A report for another challenge nonce must be rejected.'
);
privateHostReject(
    fn() => $verifier->assertAttested($makeEnvelope(['artifact_sha256' => str_repeat('0', 64)]), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'A report for a different release archive must be rejected.'
);
privateHostReject(
    fn() => $verifier->assertAttested($makeEnvelope(['files' => []]), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'An incomplete file inventory must be rejected.'
);
privateHostReject(
    fn() => $verifier->assertAttested($makeEnvelope(['target_origin' => 'https://attacker.invalid']), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'An attestation for another origin must be rejected.'
);

privateHostReject(
    fn() => $verifier->assertAttested(
        $makeEnvelope(['issued_at' => $now - 200, 'expires_at' => $now - 140]),
        $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()
    ),
    'An expired signed private-host attestation must be rejected.'
);
privateHostReject(
    fn() => $verifier->assertAttested(
        $makeEnvelope(['issued_at' => $now + 60, 'expires_at' => $now + 120]),
        $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()
    ),
    'A future-dated signed private-host attestation must be rejected.'
);

$rejectFiles = [
    [
        'path' => 'app/Updates/UpdateManager.php',
        'expected_sha256' => $filePolicy['app/Updates/UpdateManager.php'],
        'observed_sha256' => str_repeat('0', 64),
        'result' => 'digest_mismatch',
    ],
    [
        'path' => 'runtime/bootstrap.php',
        'expected_sha256' => $filePolicy['runtime/bootstrap.php'],
        'observed_sha256' => null,
        'result' => 'missing',
    ],
];
$rejected = $verifier->assertAttested(
    $makeEnvelope(['files' => $rejectFiles, 'decision' => 'reject']),
    $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()
);
privateHostAssert($rejected['approved'] === false && count($rejected['mismatches']) === 2,
    'A correctly signed rejection with file mismatches must be retained as a valid failed attestation.');

privateHostReject(
    fn() => $verifier->assertAttested(
        $makeEnvelope(['files' => $rejectFiles, 'decision' => 'approve']),
        $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()
    ),
    'A signed approval that contains file mismatches must be rejected.'
);

$tampered = json_decode($makeEnvelope(), true, 8, JSON_THROW_ON_ERROR);
$tampered['signature'] = base64_encode(str_repeat('x', SODIUM_CRYPTO_SIGN_BYTES));
privateHostReject(
    fn() => $verifier->assertAttested(json_encode($tampered, JSON_THROW_ON_ERROR), $nonce, $version, $commit, $manifest, $artifact, $expectedFiles(), $expectedConfig()),
    'An invalid collector signature must be rejected.'
);

sodium_memzero($secret);
echo "Private host attestation verifier tests passed.\n";
