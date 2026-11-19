<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/TufRootStore.php';
require_once __DIR__ . '/../upstream-tuf/vendor/autoload.php';

use K2gl\Tuf\Exception\DownloadException;
use K2gl\Tuf\Tests\Support\LocalFetcher;
use K2gl\Tuf\Tests\Support\RepoBuilder;
use K2gl\Tuf\Tests\Support\SigningKey;
use K2gl\Tuf\Updater;
use SentryIQ\Updates\TufRootStore;

const SENTRYIQ_TUF_META_URL = 'https://example.test/metadata';
const SENTRYIQ_TUF_TARGET_URL = 'https://example.test/targets';

function tufPersistenceAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function tufPersistencePublish(RepoBuilder $repo, ?string $rotatedRoot = null): LocalFetcher
{
    $fetcher = new LocalFetcher();
    if ($rotatedRoot !== null) $fetcher->put(SENTRYIQ_TUF_META_URL . '/2.root.json', $rotatedRoot);
    $fetcher->put(SENTRYIQ_TUF_META_URL . '/timestamp.json', $repo->timestampDoc());
    $fetcher->put(SENTRYIQ_TUF_META_URL . '/' . $repo->snapshotVersion . '.snapshot.json', $repo->snapshotDoc());
    $fetcher->put(SENTRYIQ_TUF_META_URL . '/' . $repo->targetsVersion . '.targets.json', $repo->targetsDoc());
    return $fetcher;
}

$base = sys_get_temp_dir() . '/sentryiq-tuf-updater-' . bin2hex(random_bytes(8));
$private = $base . '/private';
if (!mkdir($private, 0700, true)) throw new RuntimeException('Unable to create TUF integration directory.');

try {
    $store = new TufRootStore($private);
    $repo = new RepoBuilder();
    $embeddedRoot = $repo->rootDoc();
    $oldRootKey = $repo->rootKey;
    $repo->timestampKey = SigningKey::generate();
    $repo->rootVersion = 2;
    $rotatedRoot = $repo->rootDoc([$oldRootKey]);

    $updater = new Updater($store->load() ?? $embeddedRoot, SENTRYIQ_TUF_META_URL, SENTRYIQ_TUF_TARGET_URL, tufPersistencePublish($repo, $rotatedRoot));
    $updater->refresh();
    $store->storeVerifiedRoot($updater->getTrustedRootBytes());
    tufPersistenceAssert($store->load() === $rotatedRoot, 'Successful TUF refresh must persist the exact rotated root.');

    $nextUpdater = new Updater($store->load(), SENTRYIQ_TUF_META_URL, SENTRYIQ_TUF_TARGET_URL, tufPersistencePublish($repo));
    $nextUpdater->refresh();
    tufPersistenceAssert($nextUpdater->getTrustedRootBytes() === $rotatedRoot, 'A fresh updater must start from the persisted root.');

    $failedRepo = new RepoBuilder();
    $failedEmbeddedRoot = $failedRepo->rootDoc();
    $failedOldRootKey = $failedRepo->rootKey;
    $failedRepo->timestampKey = SigningKey::generate();
    $failedRepo->rootVersion = 2;
    $failedRoot = $failedRepo->rootDoc([$failedOldRootKey]);
    $failedFetcher = new LocalFetcher();
    $failedFetcher->put(SENTRYIQ_TUF_META_URL . '/2.root.json', $failedRoot);
    $failedUpdater = new Updater($failedEmbeddedRoot, SENTRYIQ_TUF_META_URL, SENTRYIQ_TUF_TARGET_URL, $failedFetcher);
    $failed = false;
    try {
        $failedUpdater->refresh();
        $store->storeVerifiedRoot($failedUpdater->getTrustedRootBytes());
    } catch (DownloadException) {
        $failed = true;
    }
    tufPersistenceAssert($failed, 'An incomplete TUF refresh must fail.');
    tufPersistenceAssert($store->load() === $rotatedRoot, 'Failed refresh must not replace the last trusted root.');

    echo "TUF updater persistence integration tests passed.\n";
} finally {
    foreach (glob($private . '/*') ?: [] as $file) if (is_file($file) || is_link($file)) @unlink($file);
    @rmdir($private);
    @rmdir($base);
}
