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

    $privateRoot = $root . '/private';
    $releaseRoot = $privateRoot . '/integrity-releases';
    mkdir($privateRoot, 0700);
    mkdir($releaseRoot, 0700);
    foreach (['1.2.0', '1.2.1', '1.2.2', '1.2.3'] as $version) {
        $versionDirectory = $releaseRoot . '/' . $version;
        mkdir($versionDirectory, 0700);
        $manifestPath = $versionDirectory . '/release-manifest.json';
        $artifactPath = $versionDirectory . '/sentryiq-' . $version . '.zip';
        file_put_contents($manifestPath, json_encode(['version' => $version], JSON_THROW_ON_ERROR));
        file_put_contents($artifactPath, 'test-zip-' . $version);
        chmod($manifestPath, 0600);
        chmod($artifactPath, 0600);
        $cache = [
            'schema_version' => 1,
            'version' => $version,
            'manifest_sha256' => hash_file('sha256', $manifestPath),
            'artifact_sha256' => hash_file('sha256', $artifactPath),
        ];
        file_put_contents($versionDirectory . '/.integrity-cache.json', json_encode($cache, JSON_THROW_ON_ERROR) . "\n");
        chmod($versionDirectory . '/.integrity-cache.json', 0600);
    }
    $cached = $fetcher->fetch('1.2.3', $releaseRoot . '/1.2.3', $publicRoot);
    if (file_get_contents($cached['artifact_path']) !== 'test-zip-1.2.3') {
        throw new RuntimeException('Fetcher must reuse a complete private cache without downloading the same release every run.');
    }
    if (is_dir($releaseRoot . '/1.2.0') || !is_dir($releaseRoot . '/1.2.1')
        || !is_dir($releaseRoot . '/1.2.2') || !is_dir($releaseRoot . '/1.2.3')) {
        throw new RuntimeException('Fetcher must retain the current and two most recent release caches only.');
    }
    file_put_contents($cached['artifact_path'], 'corrupted');
    $cacheMethod = new ReflectionMethod(IntegrityReleaseArtifactFetcher::class, 'isReusableCache');
    $cacheMethod->setAccessible(true);
    $cacheValid = $cacheMethod->invoke(
        $fetcher,
        '1.2.3',
        $cached['manifest_path'],
        $cached['artifact_path'],
        dirname($cached['artifact_path']) . '/.integrity-cache.json'
    );
    if ($cacheValid !== false) throw new RuntimeException('Fetcher must not reuse a cache whose artifact digest changed.');

    echo "Integrity release artifact fetcher tests passed.\n";
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        if ($item->isDir() && !$item->isLink()) @rmdir($item->getPathname());
        else @unlink($item->getPathname());
    }
    @rmdir($root);
}
