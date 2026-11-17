<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationCollector.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';

use SentryIQ\Updates\PrivateHostAttestationCollector;
use SentryIQ\Updates\PrivateHostAttestationVerifier;

function collectorAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function collectorReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$base = sys_get_temp_dir() . '/sentryiq-private-host-collector-' . bin2hex(random_bytes(8));
$web = $base . '/httpdocs';
$private = $base . '/private';
mkdir($base, 0700);
mkdir($web, 0700);
mkdir($private, 0700);
try {
    mkdir($web . '/app', 0700);
    mkdir($private . '/runtime', 0700);
    file_put_contents($web . '/app/release.php', '<?php return true;');
    file_put_contents($private . '/runtime/bootstrap.php', '<?php return [];');
    chmod($web . '/app/release.php', 0644);
    $fileDigest = hash_file('sha256', $web . '/app/release.php');
    $configDigest = hash_file('sha256', $private . '/runtime/bootstrap.php');

    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $keyPath = $private . '/collector.key';
    file_put_contents($keyPath, base64_encode($secret) . "\n");
    chmod($keyPath, 0600);

    $now = time();
    $collector = new PrivateHostAttestationCollector(
        'sentryiq-host-attestor',
        $web,
        $private,
        $keyPath,
        ['app/release.php' => ['sha256' => $fileDigest, 'mode' => 0644]],
        ['private-bootstrap' => ['path' => 'runtime/bootstrap.php', 'sha256' => $configDigest]],
        'https://sentryiq.bichet.co.za',
        static fn(): int => $now,
        ['app']
    );
    $verifier = new PrivateHostAttestationVerifier(base64_encode($public), static fn(): int => $now);
    $nonce = str_repeat('a', 64);
    $commit = str_repeat('b', 40);
    $manifest = hash('sha256', 'manifest');
    $artifact = hash('sha256', 'artifact');

    $envelope = json_encode($collector->collect($nonce, '1.2.3', $commit, $manifest, $artifact), JSON_THROW_ON_ERROR);
    $result = $verifier->assertAttested(
        $envelope, $nonce, '1.2.3', $commit, $manifest, $artifact,
        ['app/release.php' => $fileDigest],
        ['private-bootstrap' => $configDigest]
    );
    collectorAssert($result['approved'] === true && $result['files_checked'] === 1
        && $result['private_config_checked'] === 1, 'Collector must produce a verifier-accepted approval.');

    file_put_contents($web . '/app/release.php', 'tampered');
    $rejectedEnvelope = json_encode($collector->collect($nonce, '1.2.3', $commit, $manifest, $artifact), JSON_THROW_ON_ERROR);
    $rejected = $verifier->assertAttested(
        $rejectedEnvelope, $nonce, '1.2.3', $commit, $manifest, $artifact,
        ['app/release.php' => $fileDigest],
        ['private-bootstrap' => $configDigest]
    );
    collectorAssert($rejected['approved'] === false
        && ($rejected['mismatches'][0]['reason'] ?? null) === 'digest_mismatch',
        'Collector must sign a rejection when a pinned deployed file changes.');

    file_put_contents($web . '/app/release.php', '<?php return true;');
    chmod($web . '/app/release.php', 0600);
    $permissionEnvelope = json_encode($collector->collect($nonce, '1.2.3', $commit, $manifest, $artifact), JSON_THROW_ON_ERROR);
    $permissionResult = $verifier->assertAttested(
        $permissionEnvelope, $nonce, '1.2.3', $commit, $manifest, $artifact,
        ['app/release.php' => $fileDigest],
        ['private-bootstrap' => $configDigest]
    );
    collectorAssert($permissionResult['approved'] === false
        && ($permissionResult['mismatches'][0]['reason'] ?? null) === 'permission_mismatch',
        'Collector must reject a pinned deployed-file permission change.');

    chmod($web . '/app/release.php', 0644);
    file_put_contents($web . '/app/extra.txt', 'unexpected');
    $unexpectedEnvelope = json_encode($collector->collect($nonce, '1.2.3', $commit, $manifest, $artifact), JSON_THROW_ON_ERROR);
    $unexpectedResult = $verifier->assertAttested(
        $unexpectedEnvelope, $nonce, '1.2.3', $commit, $manifest, $artifact,
        ['app/release.php' => $fileDigest],
        ['private-bootstrap' => $configDigest]
    );
    collectorAssert($unexpectedResult['approved'] === false
        && in_array('unexpected', array_column($unexpectedResult['mismatches'], 'reason'), true),
        'Collector must reject files outside the fixed release inventory in monitored directories.');

    collectorReject(
        fn() => new PrivateHostAttestationCollector(
            'sentryiq-host-attestor', $web, $web, $keyPath,
            ['app/release.php' => $fileDigest], [],
        ),
        'Collector must reject private storage inside the public webroot.'
    );
    collectorReject(
        fn() => $collector->collect('not-a-nonce', '1.2.3', $commit, $manifest, $artifact),
        'Collector must reject malformed request context.'
    );

    sodium_memzero($secret);
    echo "Private host attestation collector tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($base);
}
