<?php

declare(strict_types=1);

use K2gl\Sigstore\TrustedRoot;
use K2gl\Tuf\HttpFetcher;
use K2gl\Tuf\Updater;
use SentryIQ\Updates\TufRootStore;

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/TufRootStore.php';

function sentryIqBootstrapRoot(): string
{
    $packageDirectory = __DIR__ . '/vendor/k2gl/sigstore-verify';
    if (!is_dir($packageDirectory)) {
        throw new RuntimeException('Pinned Sigstore verifier package is missing.');
    }

    $matches = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($packageDirectory, FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $file) {
        if (!$file->isFile() || $file->getFilename() !== 'root.json') {
            continue;
        }
        $bytes = file_get_contents($file->getPathname());
        if (!is_string($bytes)) {
            continue;
        }
        try {
            $document = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            continue;
        }
        if (($document['signed']['_type'] ?? null) === 'root'
            && is_int($document['signed']['version'] ?? null)) {
            $matches[] = $bytes;
        }
    }

    if (count($matches) !== 1) {
        throw new RuntimeException('Could not identify exactly one bundled Sigstore TUF bootstrap root.');
    }

    return $matches[0];
}

function sentryIqRootVersion(string $bytes): int
{
    $document = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
    $version = $document['signed']['version'] ?? null;
    if (($document['signed']['_type'] ?? null) !== 'root' || !is_int($version) || $version < 1) {
        throw new RuntimeException('TUF root metadata has an invalid type or version.');
    }

    return $version;
}

function runSentryIqTufPersistenceProbe(string $mode): never
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');

    try {
        $store = new TufRootStore(__DIR__);
        $persistedBefore = $store->load();
        $bootstrap = sentryIqBootstrapRoot();

        if ($mode === 'refresh') {
            $startingRoot = $persistedBefore ?? $bootstrap;
            $startingSource = $persistedBefore === null ? 'bundled_bootstrap' : 'persisted_root';
        } elseif ($mode === 'reload') {
            if ($persistedBefore === null) {
                throw new RuntimeException('No persisted root exists; run the refresh endpoint first.');
            }
            $startingRoot = $persistedBefore;
            $startingSource = 'persisted_root';
        } else {
            throw new RuntimeException('Unknown probe mode.');
        }

        $startingVersion = sentryIqRootVersion($startingRoot);
        $updater = new Updater(
            $startingRoot,
            'https://tuf-repo-cdn.sigstore.dev',
            'https://tuf-repo-cdn.sigstore.dev/targets',
            new HttpFetcher(20),
        );

        // fromTuf completes refresh and verifies/downloads trusted_root.json before returning.
        $trustedRoot = TrustedRoot::fromTuf($updater);
        $verifiedRootBytes = $updater->getTrustedRootBytes();
        $verifiedVersion = sentryIqRootVersion($verifiedRootBytes);

        if ($verifiedVersion < $startingVersion) {
            throw new RuntimeException('Verified TUF root version moved backwards.');
        }

        // Persist only after the complete TUF refresh and trusted-root target verification.
        $store->storeVerifiedRoot($verifiedRootBytes);
        $persistedAfter = $store->load();
        if ($persistedAfter !== $verifiedRootBytes) {
            throw new RuntimeException('Persisted TUF root does not match the verified root bytes.');
        }

        $result = [
            'probe' => 'sentryiq-heliohost-tuf-persistence',
            'mode' => $mode,
            'status' => 'passed',
            'starting_root_source' => $startingSource,
            'starting_root_version' => $startingVersion,
            'starting_root_sha256' => hash('sha256', $startingRoot),
            'verified_root_version' => $verifiedVersion,
            'verified_root_sha256' => hash('sha256', $verifiedRootBytes),
            'persisted_root_sha256' => hash('sha256', $persistedAfter),
            'loaded_persisted_root' => $mode === 'reload',
            'certificate_authority_count' => count($trustedRoot->certificateAuthorities),
            'transparency_log_count' => count($trustedRoot->transparencyLogs),
            'timestamp_authority_count' => count($trustedRoot->timestampAuthorities),
            'ct_log_count' => count($trustedRoot->ctLogs),
        ];

        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        exit(0);
    } catch (Throwable $exception) {
        http_response_code(500);
        echo json_encode([
            'probe' => 'sentryiq-heliohost-tuf-persistence',
            'mode' => $mode,
            'status' => 'failed',
            'exception_class' => get_class($exception),
            'message' => $exception->getMessage(),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit(1);
    }
}
