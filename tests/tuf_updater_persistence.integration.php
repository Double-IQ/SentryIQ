<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';

use K2gl\Tuf\Exception\DownloadException;
use K2gl\Tuf\Tests\Support\LocalFetcher;
use K2gl\Tuf\Tests\Support\RepoBuilder;
use K2gl\Tuf\Tests\Support\SigningKey;
use K2gl\Tuf\Updater;
use SentryIQ\Updates\TufRootStore;

require_once __DIR__ . '/../../upstream-tuf/vendor/autoload.php';

const META_URL = 'https://example.test/metadata';
const TARGET_URL = 'https://example.test/targets';

function integrationAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

/** @return LocalFetcher */
function publishRepository(RepoBuilder $repo, ?string $rotatedRoot = null): LocalFetcher
{
    $fetcher = new LocalFetcher();
    if ($rotatedRoot !== null) {
        $fetcher->put(META_URL . '/2.root.json', $rotatedRoot);
    }
    $fetcher->put(META_URL . '/timestamp.json', $repo->timestampDoc());
    $fetcher->put(META_URL . '/' . $repo->snapshotVersion . '.snapshot.json', $repo->snapshotDoc());
    $fetcher->put(META_URL . '/' . $repo->targetsVersion . '.targets.json', $repo->targetsDoc());

    return $fetcher;
}

$directory = sys_get_temp_dir() . '/sentryiq-tuf-updater-' . bin2hex(random_bytes(6));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create TUF integration test directory.');
}

try {
    $store = new TufRootStore($directory);
    $repo = new RepoBuilder();
    $embeddedRoot = $repo->rootDoc();

    // Rotate the timestamp key. The new root is signed by the old trusted root key.
    $oldRootKey = $repo->rootKey;
    $repo->timestampKey = SigningKey::generate();
    $repo->rootVersion = 2;
    $rotatedRoot = $repo->rootDoc([$oldRootKey]);

    $fetcher = publishRepository($repo, $rotatedRoot);
    $trustedRoot = $store->load() ?? $embeddedRoot;
    $updater = new Updater($trustedRoot, META_URL, TARGET_URL, $fetcher);
    $updater->refresh();

    // Persist only after the complete TUF refresh (root, timestamp, snapshot, targets) succeeds.
    $store->storeVerifiedRoot($updater->getTrustedRootBytes());
    integrationAssert($store->load() === $rotatedRoot, 'A successful real Updater refresh must persist the rotated root.');

    // Simulate the next PHP request: load persisted bytes and construct a fresh Updater.
    $nextRequestRoot = $store->load();
    integrationAssert($nextRequestRoot === $rotatedRoot, 'The next request must start from the persisted rotated root.');
    $nextRequestUpdater = new Updater(
        $nextRequestRoot,
        META_URL,
        TARGET_URL,
        publishRepository($repo),
    );
    $nextRequestUpdater->refresh();
    integrationAssert(
        $nextRequestUpdater->getTrustedRootBytes() === $rotatedRoot,
        'A fresh Updater must retain the persisted root without reusing the embedded root.',
    );

    // A failed refresh after a candidate root is available must not update durable trust state.
    $failureRepo = new RepoBuilder();
    $failureEmbeddedRoot = $failureRepo->rootDoc();
    $failureOldRootKey = $failureRepo->rootKey;
    $failureRepo->timestampKey = SigningKey::generate();
    $failureRepo->rootVersion = 2;
    $failureRotatedRoot = $failureRepo->rootDoc([$failureOldRootKey]);
    $failureFetcher = new LocalFetcher();
    $failureFetcher->put(META_URL . '/2.root.json', $failureRotatedRoot);
    // Intentionally omit timestamp.json: refresh must fail after root rotation.
    $failureUpdater = new Updater($failureEmbeddedRoot, META_URL, TARGET_URL, $failureFetcher);
    $failedAsExpected = false;
    try {
        $failureUpdater->refresh();
        $store->storeVerifiedRoot($failureUpdater->getTrustedRootBytes());
    } catch (DownloadException) {
        $failedAsExpected = true;
    }
    integrationAssert($failedAsExpected, 'An incomplete TUF refresh must fail.');
    integrationAssert(
        $store->load() === $rotatedRoot,
        'A failed refresh must not replace the previously persisted trusted root.',
    );

    echo "Real K2gl\\Tuf\\Updater root rotation and durable persistence integration passed.\\n";
} finally {
    foreach (glob($directory . '/*') ?: [] as $file) {
        if (is_file($file) || is_link($file)) {
            @unlink($file);
        }
    }
    @rmdir($directory);
}
