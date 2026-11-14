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
    // k2gl/sigstore-verify 1.6.1 stores its pinned TUF bootstrap metadata
    // at this exact package resource path (not as a file named root.json).
    $rootPath = __DIR__ . '/vendor/k2gl/sigstore-verify/resources/sigstore-tuf-root.json';
    if (!is_file($rootPath) || is_link($rootPath) || !is_readable($rootPath)) {
        throw new RuntimeException('Pinned Sigstore TUF bootstrap root is missing or unreadable.');
    }

    $bytes = file_get_contents($rootPath);
    if (!is_string($bytes)) {
        throw new RuntimeException('Could not read the pinned Sigstore TUF bootstrap root.');
    }

    try {
        $document = json_decode($bytes, true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        throw new RuntimeException('Pinned Sigstore TUF bootstrap root is not valid JSON.', 0, $exception);
    }

    if (!is_array($document)
        || ($document['signed']['_type'] ?? null) !== 'root'
        || !is_int($document['signed']['version'] ?? null)
        || $document['signed']['version'] < 1) {
        throw new RuntimeException('Pinned Sigstore TUF bootstrap root has invalid root metadata.');
    }

    return $bytes;
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

        if ($mode === 'refresh') {
            $startingRoot = $persistedBefore ?? sentryIqBootstrapRoot();
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
