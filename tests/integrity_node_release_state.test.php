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

try {
    $store = new IntegrityNodeReleaseStateStore($private, $web);
    releaseStateReject(fn() => $store->current(), 'A missing baseline must fail closed.');
    $commitA = str_repeat('a', 40);
    $commitB = str_repeat('b', 40);
    $store->initializeBaseline('v1.2.3', $commitA);
    releaseStateAssert($store->current()['version'] === '1.2.3', 'Explicit baseline should be persisted.');
    $store->assertCandidate('1.2.3', $commitA);
    $store->assertCandidate('1.2.4', $commitB);
    releaseStateReject(fn() => $store->assertCandidate('1.2.2', $commitA), 'Older release must be rejected.');
    releaseStateReject(fn() => $store->assertCandidate('1.2.3', $commitB), 'Same-version tag retarget must be rejected.');
    releaseStateReject(fn() => $store->initializeBaseline('1.2.4', $commitB), 'Existing baseline must not be silently replaced.');
    releaseStateReject(fn() => $store->recordApproved('1.2.4', $commitB), 'State may advance only under the exclusive run lock.');

    $store->runExclusive(function () use ($store, $commitB): void {
        $store->recordApproved('1.2.4', $commitB);
    });
    $state = $store->current();
    releaseStateAssert($state['version'] === '1.2.4' && $state['commit'] === $commitB, 'Approved newer release should advance the pin.');
    releaseStateReject(fn() => $store->runExclusive(fn() => $store->runExclusive(static fn() => null)), 'The run lock must not be re-entered.');
} finally {
    @unlink($private . '/integrity-release-state.json');
    @unlink($private . '/integrity-release-state.lock');
    @rmdir($private);
    @rmdir($web);
    @rmdir($root);
}

echo "Integrity node release state tests passed.\n";
