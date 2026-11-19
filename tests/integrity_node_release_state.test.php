<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityNodeReleaseStateStore.php';

use SentryIQ\Updates\IntegrityNodeReleaseStateStore;

function releaseStateAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function releaseStateReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-release-state-' . bin2hex(random_bytes(8));
$private = $root . '/private';
$web = $root . '/public';
mkdir($private, 0700, true);
mkdir($web, 0700, true);
$lockPath = $private . '/integrity-release-state.lock';
file_put_contents($lockPath, '');
chmod($lockPath, 0600);

try {
    $store = new IntegrityNodeReleaseStateStore($private, $web);
    releaseStateReject(fn() => $store->current(), 'A missing baseline must fail closed.');
    releaseStateAssert((fileperms($private) & 0777) === 0700, 'Constructor must preserve the pre-provisioned private directory mode.');
    releaseStateAssert((fileperms($lockPath) & 0777) === 0600, 'Pre-provisioned lock must remain exactly 0600.');
    releaseStateReject(
        fn() => new IntegrityNodeReleaseStateStore($root . '/unsafe-private', $web),
        'A private directory with unsafe permissions must be rejected.'
    );
    mkdir($root . '/unsafe-private', 0750);
    $unsafeMode = fileperms($root . '/unsafe-private') & 0777;
    releaseStateReject(
        fn() => new IntegrityNodeReleaseStateStore($root . '/unsafe-private', $web),
        'A group-accessible private directory must be rejected.'
    );
    releaseStateAssert((fileperms($root . '/unsafe-private') & 0777) === $unsafeMode, 'Rejected directory permissions must not be modified.');
    rmdir($root . '/unsafe-private');
    $commitA = str_repeat('a', 40);
    $commitB = str_repeat('b', 40);
    $manifestA = str_repeat('c', 64);
    $artifactA = str_repeat('d', 64);
    $manifestB = str_repeat('e', 64);
    $artifactB = str_repeat('f', 64);
    $store->initializeBaseline('v1.2.3', $commitA, $manifestA, $artifactA);
    releaseStateAssert($store->current()['version'] === '1.2.3', 'Explicit baseline should be persisted.');
    releaseStateAssert((fileperms($private . '/integrity-release-state.json') & 0777) === 0600, 'Persisted release state must be exactly 0600.');
    $store->assertCandidate('1.2.3', $commitA, $manifestA, $artifactA);
    $store->assertCandidate('1.2.4', $commitB, $manifestB, $artifactB);
    releaseStateReject(fn() => $store->assertCandidate('1.2.2', $commitA, $manifestA, $artifactA), 'Older release must be rejected.');
    releaseStateReject(fn() => $store->assertCandidate('1.2.3', $commitB, $manifestA, $artifactA), 'Same-version tag retarget must be rejected.');
    releaseStateReject(fn() => $store->assertCandidate('1.2.3', $commitA, $manifestB, $artifactB), 'Same-version artifact replacement must be rejected after digest pinning.');
    releaseStateReject(fn() => $store->initializeBaseline('1.2.4', $commitB), 'Existing baseline must not be silently replaced.');
    releaseStateReject(fn() => $store->initializeBaseline('1.2.3', $commitA, 'invalid', $artifactA), 'Baseline must reject an invalid manifest digest.');
    releaseStateReject(fn() => $store->runExclusive(fn() => $store->recordApproved('1.2.3', $commitA, $manifestB, $artifactB)), 'Same-version digest replacement must be rejected while recording approval.');
    releaseStateReject(fn() => $store->recordApproved('1.2.4', $commitB, $manifestB, $artifactB), 'State may advance only under the exclusive run lock.');

    $store->runExclusive(function () use ($store, $commitB, $manifestB, $artifactB): void {
        $store->recordApproved('1.2.4', $commitB, $manifestB, $artifactB);
    });
    $state = $store->current();
    releaseStateAssert($state['version'] === '1.2.4' && $state['commit'] === $commitB && $state['manifest_sha256'] === $manifestB && $state['artifact_sha256'] === $artifactB, 'Approved newer release should advance the version, commit and artifact digest pins.');
    releaseStateReject(fn() => $store->runExclusive(fn() => $store->runExclusive(static fn() => null)), 'The run lock must not be re-entered.');
} finally {
    @unlink($private . '/integrity-release-state.json');
    @unlink($private . '/integrity-release-state.lock');
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}

echo "Integrity node release state tests passed.\n";
