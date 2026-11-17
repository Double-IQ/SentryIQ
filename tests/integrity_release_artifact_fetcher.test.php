<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReleaseArtifactFetcher.php';

use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;

$fetcher = new IntegrityReleaseArtifactFetcher();
$root = sys_get_temp_dir() . '/sentryiq-release-fetcher-' . bin2hex(random_bytes(6));
if (!mkdir($root, 0700)) throw new RuntimeException('Unable to create fetcher fixture.');
$publicRoot = $root . '/public';
if (!mkdir($publicRoot, 0700)) throw new RuntimeException('Unable to create public-root fixture.');

try {
    $rejectedVersion = false;
    try {
        $fetcher->fetch('../latest', $root . '/stage', $publicRoot);
    } catch (RuntimeException) {
        $rejectedVersion = true;
    }
    if (!$rejectedVersion) throw new RuntimeException('Fetcher must reject unsafe release versions before network access.');

    $target = $root . '/real';
    mkdir($target, 0700);
    $link = $root . '/linked';
    if (!symlink($target, $link)) throw new RuntimeException('Unable to create symlink fixture.');
    $rejectedLink = false;
    try {
        $fetcher->fetch('1.2.3', $link, $publicRoot);
    } catch (RuntimeException) {
        $rejectedLink = true;
    }
    if (!$rejectedLink) throw new RuntimeException('Fetcher must reject symlinked private staging directories.');

    $rejectedParentLink = false;
    try {
        $fetcher->fetch('1.2.3', $link . '/nested-stage', $publicRoot);
    } catch (RuntimeException) {
        $rejectedParentLink = true;
    }
    if (!$rejectedParentLink) throw new RuntimeException('Fetcher must reject symlinked parent components.');

    $rootRejected = false;
    try {
        $fetcher->fetch('1.2.3', DIRECTORY_SEPARATOR, $publicRoot);
    } catch (RuntimeException) {
        $rootRejected = true;
    }
    if (!$rootRejected) throw new RuntimeException('Fetcher must reject the filesystem root as a staging directory.');

    $webrootRejected = false;
    try {
        $fetcher->fetch('1.2.3', $publicRoot . '/release-assets', $publicRoot);
    } catch (RuntimeException) {
        $webrootRejected = true;
    }
    if (!$webrootRejected) throw new RuntimeException('Fetcher must reject staging inside the public webroot.');

    echo "Integrity release artifact fetcher tests passed.\n";
} finally {
    @rmdir($root . '/linked');
    @rmdir($root . '/real');
    @rmdir($publicRoot);
    @rmdir($root);
}
