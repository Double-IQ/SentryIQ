<?php

declare(strict_types=1);

/**
 * Read-only CLI qualification of a provisioned private bootstrap runtime.
 * Does not issue challenges, approve, write receipts, alter trust state, or deploy.
 *
 * Usage:
 *   SENTRYIQ_QUALIFY_USERNAME='known-account' php scripts/qualify-bootstrap-runtime.php
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/app/Security/SecurityBootstrap.php';
require_once dirname(__DIR__) . '/app/Security/BootstrapChallengeStore.php';
require_once dirname(__DIR__) . '/app/Security/TrustBundleValidator.php';
require_once dirname(__DIR__) . '/app/Security/RegistryAnchorVerifier.php';
require_once dirname(__DIR__) . '/app/Security/OwnerApprovalProofVerifier.php';
require_once dirname(__DIR__) . '/app/Security/OwnerBootstrapApi.php';
require_once dirname(__DIR__) . '/app/Security/BootstrapTargetStore.php';

use SentryIQ\Security\BootstrapChallengeStore;
use SentryIQ\Security\BootstrapTargetStore;
use SentryIQ\Security\OwnerBootstrapApi;
use SentryIQ\Security\RegistryAnchorVerifier;
use SentryIQ\Security\TrustBundleValidator;

function qualificationFail(string $message): never
{
    fwrite(STDERR, "Bootstrap runtime qualification FAILED: {$message}\n");
    exit(1);
}

$dataDirectory = sentryiq_data_dir();
if ($dataDirectory === '' || !is_dir($dataDirectory) || is_link($dataDirectory)
    || (((fileperms($dataDirectory) ?: 0) & 0077) !== 0)
    || !sentryiq_path_is_outside_document_root($dataDirectory)) {
    qualificationFail('private data directory is missing, unsafe, or web-accessible.');
}

$runtimePath = $dataDirectory . '/bootstrap-runtime.php';
if (is_link($runtimePath) || !is_file($runtimePath)
    || (((fileperms($runtimePath) ?: 0) & 0777) !== 0600)) {
    qualificationFail('runtime configuration must be a regular file with mode 0600.');
}

$username = getenv('SENTRYIQ_QUALIFY_USERNAME');
if (!is_string($username) || $username === '' || strlen($username) > 256) {
    qualificationFail('set SENTRYIQ_QUALIFY_USERNAME to an account used for owner mapping qualification.');
}

try {
    $runtime = require $runtimePath;
    if (!is_array($runtime)
        || !is_callable($runtime['resolve_owner_id'] ?? null)
        || !is_callable($runtime['verify_tuf'] ?? null)
        || !is_callable($runtime['resolve_target'] ?? null)
        || !is_string($runtime['bundle_json'] ?? null)
        || !is_string($runtime['registry_anchor_payload'] ?? null)
        || !is_string($runtime['registry_anchor_signature_base64url'] ?? null)
        || !is_array($runtime['registry_signer_keys'] ?? null)
        || !is_array($runtime['bundle_signer_keys'] ?? null)
        || !is_array($runtime['tuf_metadata'] ?? null)) {
        qualificationFail('runtime configuration shape or required callbacks are invalid.');
    }

    $ownerId = ($runtime['resolve_owner_id'])($username);
    if (!is_string($ownerId) || !preg_match('/^[A-Za-z0-9._:-]{1,256}$/D', $ownerId)) {
        qualificationFail('owner mapping callback did not return a valid immutable owner ID.');
    }

    $api = new OwnerBootstrapApi(
        new BootstrapChallengeStore($dataDirectory),
        $dataDirectory,
        new TrustBundleValidator(),
        new RegistryAnchorVerifier(),
        $ownerId,
        $runtime['bundle_json'],
        $runtime['registry_anchor_payload'],
        $runtime['registry_anchor_signature_base64url'],
        $runtime['registry_signer_keys'],
        $runtime['bundle_signer_keys'],
        $runtime['tuf_metadata'],
        is_string($runtime['current_sequence'] ?? null) ? $runtime['current_sequence'] : null,
        is_string($runtime['current_bundle_digest'] ?? null) ? $runtime['current_bundle_digest'] : null,
        $runtime['verify_tuf']
    );

    $snapshot = $api->snapshot(time());
    foreach (['root.json', 'timestamp.json', 'snapshot.json', 'targets.json'] as $required) {
        if (!isset($snapshot['tuf_metadata'][$required])) {
            qualificationFail('signed TUF metadata set is incomplete.');
        }
    }
    if (!hash_equals($snapshot['bundle_sha256'], hash('sha256', $snapshot['canonical_bundle']))) {
        qualificationFail('bundle canonical digest consistency check failed.');
    }
    $targetPath = getenv('SENTRYIQ_QUALIFY_TARGET_PATH');
    if (!is_string($targetPath) || !BootstrapTargetStore::validRelativePath($targetPath)) {
        qualificationFail('set SENTRYIQ_QUALIFY_TARGET_PATH to a known signed target path for read-only target qualification.');
    }
    $resolved = ($runtime['resolve_target'])($targetPath, $snapshot['validated_bundle'], $snapshot['tuf_metadata']);
    if (!is_array($resolved) || !is_string($resolved['bytes'] ?? null) || !is_array($resolved['descriptor'] ?? null)) {
        qualificationFail('target resolver did not return bytes and a signed TUF descriptor.');
    }
    BootstrapTargetStore::verifyResolverBytes($resolved['bytes'], $resolved['descriptor']);
    fwrite(STDOUT, "Bootstrap runtime qualification PASSED.\n");
    fwrite(STDOUT, "Owner mapping, signed registry anchor, trust bundle, and TUF callback verified.\n");
    fwrite(STDOUT, "No challenges or receipts were created; no trust state or deployment changed.\n");
} catch (Throwable) {
    qualificationFail('runtime verification failed; details withheld to avoid leaking configuration or key material.');
}
