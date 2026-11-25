<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/BootstrapChallengeStore.php';

use SentryIQ\Security\BootstrapChallengeStore;

function bootstrapChallengeAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function bootstrapChallengeReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-bootstrap-challenge-' . bin2hex(random_bytes(8));
if (!mkdir($root, 0700, true)) throw new RuntimeException('Unable to create private test directory.');
$store = new BootstrapChallengeStore($root);
$owner = 'owner-test-001';
$digest = str_repeat('a', 64);

$challenge = $store->issue($owner, $digest, 1000);
bootstrapChallengeAssert(strlen($challenge) === 43, 'Issued challenge must encode exactly 32 random bytes.');
$record = $store->consume($challenge, $owner, $digest, 1300);
bootstrapChallengeAssert($record['purpose'] === 'owner-bootstrap-approval', 'Consumed challenge purpose must be explicit.');
bootstrapChallengeAssert($record['expires_at'] === 1300, 'Challenge must expire at the requested bounded lifetime.');
bootstrapChallengeReject(
    fn() => $store->consume($challenge, $owner, $digest, 1300),
    'A consumed challenge must not be replayable.'
);

$wrongBinding = $store->issue($owner, $digest, 2000);
bootstrapChallengeReject(
    fn() => $store->consume($wrongBinding, 'different-owner', $digest, 2001),
    'Challenge must reject an owner binding mismatch.'
);
bootstrapChallengeReject(
    fn() => $store->consume($wrongBinding, $owner, $digest, 2001),
    'A challenge with a failed binding must still be burned.'
);

$wrongDigest = $store->issue($owner, $digest, 3000);
bootstrapChallengeReject(
    fn() => $store->consume($wrongDigest, $owner, str_repeat('b', 64), 3001),
    'Challenge must reject a candidate bundle digest mismatch.'
);
bootstrapChallengeReject(
    fn() => $store->consume($wrongDigest, $owner, $digest, 3001),
    'A challenge with a failed digest binding must still be burned.'
);

$expired = $store->issue($owner, $digest, 4000, 30);
bootstrapChallengeReject(
    fn() => $store->consume($expired, $owner, $digest, 4031),
    'Expired challenges must be rejected.'
);
bootstrapChallengeReject(
    fn() => $store->consume('not-a-challenge', $owner, $digest, 4001),
    'Malformed challenges must be rejected.'
);
bootstrapChallengeReject(
    fn() => $store->issue($owner, $digest, 5000, 301),
    'Challenge TTL must never exceed five minutes.'
);
bootstrapChallengeReject(
    fn() => $store->issue($owner, 'bad-digest', 5000),
    'Challenge issue must require a SHA-256 bundle digest.'
);

$storePath = $root . '/.bootstrap-challenges.json';
bootstrapChallengeAssert(is_file($storePath), 'Challenge state must be durably stored.');
bootstrapChallengeAssert(((fileperms($storePath) ?: 0) & 0777) === 0600, 'Challenge state must be owner-only.');
$lockPath = $root . '/.bootstrap-challenges.lock';
bootstrapChallengeAssert(((fileperms($lockPath) ?: 0) & 0777) === 0600, 'Challenge lock must be owner-only.');

file_put_contents($storePath, '{"version":99,"records":[]}');
bootstrapChallengeReject(
    fn() => $store->issue($owner, $digest, 6000),
    'Corrupt or unsupported store versions must fail closed rather than reset replay state.'
);

@unlink($storePath);
@unlink($lockPath);
@rmdir($root);
echo "Durable owner bootstrap challenge tests passed.\n";
