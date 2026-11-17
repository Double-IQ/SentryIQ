<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/PrivateHostAttestationCollector.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationRequestHandler.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationNonceStore.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';

use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationCollector;
use SentryIQ\Updates\PrivateHostAttestationRequestHandler;
use SentryIQ\Updates\PrivateHostAttestationNonceStore;
use SentryIQ\Updates\PrivateHostAttestationVerifier;

function hostHandlerAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function hostHandlerReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$base = sys_get_temp_dir() . '/sentryiq-private-host-handler-' . bin2hex(random_bytes(8));
$web = $base . '/httpdocs';
$private = $base . '/private';
mkdir($base, 0700);
mkdir($web, 0700);
mkdir($private, 0700);
try {
    mkdir($web . '/app', 0700);
    file_put_contents($web . '/app/release.php', 'release');
    $digest = hash_file('sha256', $web . '/app/release.php');
    $pair = sodium_crypto_sign_keypair();
    $secret = sodium_crypto_sign_secretkey($pair);
    $public = sodium_crypto_sign_publickey($pair);
    $keyPath = $private . '/collector.key';
    file_put_contents($keyPath, base64_encode($secret) . "\n");
    chmod($keyPath, 0600);

    $collector = new PrivateHostAttestationCollector(
        'sentryiq-host-attestor',
        $web,
        $private,
        $keyPath,
        ['app/release.php' => $digest],
        []
    );
    $tokenA = str_repeat('A', 64);
    $tokenB = str_repeat('B', 64);
    $nonceStore = new PrivateHostAttestationNonceStore($private, $web);
    $handler = new PrivateHostAttestationRequestHandler(
        $collector,
        ['integrity-a' => $tokenA, 'integrity-b' => $tokenB],
        static fn(string $nodeId, string $nonce, int $expiresAt): bool =>
            $nonceStore->consume($nodeId, $nonce, $expiresAt)
    );

    $nonce = str_repeat('a', 64);
    $commit = str_repeat('b', 40);
    $manifest = hash('sha256', 'manifest');
    $artifact = hash('sha256', 'artifact');
    $client = new PrivateHostAttestationClient(
        'integrity-a',
        $tokenA,
        'https://sentryiq.bichet.co.za/private-host-attestation',
        static function (string $url, array $headers, string $body, int $maxBytes) use ($handler): array {
            return $handler->handle('POST', $headers, $body);
        }
    );
    $envelope = $client->request($nonce, '1.2.3', $commit, $manifest, $artifact);
    $verifier = new PrivateHostAttestationVerifier(base64_encode($public));
    $result = $verifier->assertAttested(
        $envelope, $nonce, '1.2.3', $commit, $manifest, $artifact,
        ['app/release.php' => $digest], []
    );
    hostHandlerAssert($result['approved'] === true, 'Authenticated request must produce a verifier-approved signed envelope.');

    $request = json_encode([
        'schema_version' => 1,
        'node_id' => 'integrity-a',
        'nonce' => $nonce,
        'release_version' => '1.2.3',
        'commit' => $commit,
        'manifest_sha256' => $manifest,
        'artifact_sha256' => $artifact,
    ], JSON_THROW_ON_ERROR);
    $headers = ['Authorization' => 'Bearer ' . $tokenA, 'Content-Type' => 'application/json'];
    hostHandlerAssert($handler->handle('POST', $headers, $request)['status'] === 409,
        'The same node nonce must be rejected on replay.');
    $reloadedNonceStore = new PrivateHostAttestationNonceStore($private, $web);
    hostHandlerAssert($reloadedNonceStore->consume('integrity-a', $nonce, time() + 120) === false,
        'Nonce replay history must persist across store instances.');
    hostHandlerAssert($handler->handle('POST', ['Authorization' => 'Bearer wrong', 'Content-Type' => 'application/json'], $request)['status'] === 401,
        'Unknown bearer tokens must be rejected.');
    $crossNode = json_decode($request, true, 8, JSON_THROW_ON_ERROR);
    $crossNode['node_id'] = 'integrity-b';
    hostHandlerAssert($handler->handle('POST', ['Authorization' => 'Bearer ' . $tokenA, 'Content-Type' => 'application/json'],
        json_encode($crossNode, JSON_THROW_ON_ERROR))['status'] === 400,
        'A token cannot claim the other node identity.');
    $arbitraryPath = json_decode($request, true, 8, JSON_THROW_ON_ERROR);
    $arbitraryPath['paths'] = ['/etc/passwd'];
    hostHandlerAssert($handler->handle('POST', $headers, json_encode($arbitraryPath, JSON_THROW_ON_ERROR))['status'] === 400,
        'Remote callers cannot supply filesystem paths.');
    hostHandlerAssert($handler->handle('GET', $headers, $request)['status'] === 400,
        'Only POST requests are accepted.');

    hostHandlerReject(
        fn() => new PrivateHostAttestationRequestHandler($collector, ['integrity-a' => $tokenA, 'integrity-b' => $tokenA],
            static fn(): bool => true),
        'A/B bearer tokens must be distinct.'
    );
    sodium_memzero($secret);
    echo "Private host attestation request handler tests passed.\n";
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
