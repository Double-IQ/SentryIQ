<?php

declare(strict_types=1);

use SentryIQ\Security\BootstrapChallengeStore;
use SentryIQ\Security\OwnerBootstrapApi;
use SentryIQ\Security\RegistryAnchorVerifier;
use SentryIQ\Security\TrustBundleValidator;

require_once dirname(__DIR__) . '/app/Security/SecurityBootstrap.php';
require_once dirname(__DIR__) . '/app/Security/BootstrapChallengeStore.php';
require_once dirname(__DIR__) . '/app/Security/TrustBundleValidator.php';
require_once dirname(__DIR__) . '/app/Security/RegistryAnchorVerifier.php';
require_once dirname(__DIR__) . '/app/Security/OwnerApprovalProofVerifier.php';
require_once dirname(__DIR__) . '/app/Security/OwnerBootstrapApi.php';
require_once dirname(__DIR__) . '/app/Security/BootstrapTargetStore.php';

sentryiq_security_bootstrap();
sentryiq_require_fresh_auth();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

function owner_bootstrap_respond(int $status, array $payload): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function owner_bootstrap_b64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

$dataDirectory = sentryiq_data_dir();
if ($dataDirectory === '') {
    owner_bootstrap_respond(503, ['error' => 'bootstrap_unavailable']);
}
$runtimePath = $dataDirectory . '/bootstrap-runtime.php';
if (is_link($runtimePath) || !is_file($runtimePath)
    || (((fileperms($runtimePath) ?: 0) & 0077) !== 0)) {
    owner_bootstrap_respond(503, ['error' => 'bootstrap_not_provisioned']);
}

try {
    $runtime = require $runtimePath;
    if (!is_array($runtime)
        || !is_callable($runtime['resolve_owner_id'] ?? null)
        || !is_callable($runtime['verify_tuf'] ?? null)
        || !is_string($runtime['bundle_json'] ?? null)
        || !is_string($runtime['registry_anchor_payload'] ?? null)
        || !is_string($runtime['registry_anchor_signature_base64url'] ?? null)
        || !is_array($runtime['registry_signer_keys'] ?? null)
        || !is_array($runtime['bundle_signer_keys'] ?? null)
        || !is_array($runtime['tuf_metadata'] ?? null)
        || !is_callable($runtime['resolve_target'] ?? null)) {
        owner_bootstrap_respond(503, ['error' => 'bootstrap_runtime_invalid']);
    }

    $sessionUser = $_SESSION['app_username'] ?? null;
    if (!is_string($sessionUser) || $sessionUser === '') {
        owner_bootstrap_respond(403, ['error' => 'authentication_required']);
    }
    $ownerId = ($runtime['resolve_owner_id'])($sessionUser);
    if (!is_string($ownerId) || !preg_match('/^[A-Za-z0-9._:-]{1,256}$/D', $ownerId)) {
        owner_bootstrap_respond(403, ['error' => 'owner_binding_unavailable']);
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

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['target'])) {
        // Do not serve targets unless the current signed anchor, trust bundle,
        // and complete TUF metadata set pass the same validation as a snapshot.
        $targetSnapshot = $api->snapshot(time());
        $targetPath = $_GET['target'];
        if (!is_string($targetPath) || strlen($targetPath) > 512
            || !preg_match('~^[A-Za-z0-9._/-]+$~D', $targetPath)
            || str_starts_with($targetPath, '/') || str_ends_with($targetPath, '/')
            || str_contains($targetPath, '//')
            || preg_match('~(^|/)\\.{1,2}($|/)~', $targetPath)) {
            owner_bootstrap_respond(400, ['error' => 'invalid_target_path']);
        }
        $resolved = ($runtime['resolve_target'])($targetPath, $targetSnapshot['validated_bundle'], $targetSnapshot['tuf_metadata']);
        if (!is_array($resolved) || !is_string($resolved['bytes'] ?? null)
            || !is_array($resolved['descriptor'] ?? null)) {
            owner_bootstrap_respond(404, ['error' => 'target_not_found']);
        }
        // The resolver must source the descriptor from the verified signed TUF
        // target/delegation metadata. Re-check exact byte length and digest here.
        $targetBytes = BootstrapTargetStore::verifyResolverBytes($resolved['bytes'], $resolved['descriptor']);
        owner_bootstrap_respond(200, [
            'protocol' => 'SENTRYIQ-OWNER-BOOTSTRAP-API-V1',
            'target_path' => $targetPath,
            'target' => owner_bootstrap_b64url($targetBytes),
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $snapshot = $api->snapshot(time());
        owner_bootstrap_respond(200, [
            'protocol' => 'SENTRYIQ-OWNER-BOOTSTRAP-API-V1',
            'owner_id' => $snapshot['owner_id'],
            'sequence' => $snapshot['sequence'],
            'bundle_sha256' => $snapshot['bundle_sha256'],
            'bundle' => owner_bootstrap_b64url($snapshot['canonical_bundle']),
            'registry_anchor_payload' => owner_bootstrap_b64url($snapshot['registry_anchor_payload']),
            'registry_anchor_signature' => owner_bootstrap_b64url($snapshot['registry_anchor_signature']),
            'tuf_metadata' => array_map('owner_bootstrap_b64url', $snapshot['tuf_metadata']),
            'csrf_token' => sentryiq_csrf_token(),
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: GET, POST');
        owner_bootstrap_respond(405, ['error' => 'method_not_allowed']);
    }
    sentryiq_require_csrf();

    $rawBody = file_get_contents('php://input');
    if (!is_string($rawBody) || $rawBody === '' || strlen($rawBody) > 16384) {
        owner_bootstrap_respond(413, ['error' => 'request_too_large']);
    }
    $request = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
    if (!is_array($request) || !is_string($request['action'] ?? null)) {
        owner_bootstrap_respond(400, ['error' => 'invalid_request']);
    }

    if ($request['action'] === 'challenge') {
        owner_bootstrap_respond(200, $api->issueChallenge(time()));
    }
    if ($request['action'] === 'approve') {
        $fields = ['challenge', 'bundle_sha256', 'root_role', 'root_key_id', 'root_fingerprint', 'device_keyset_digest', 'purpose', 'signature'];
        $proof = [];
        foreach ($fields as $field) {
            if (!is_string($request[$field] ?? null)) {
                owner_bootstrap_respond(400, ['error' => 'invalid_proof']);
            }
            $proof[$field] = $request[$field];
        }
        owner_bootstrap_respond(200, $api->approve($proof, time()));
    }
    owner_bootstrap_respond(400, ['error' => 'unknown_action']);
} catch (Throwable $error) {
    error_log('SentryIQ owner bootstrap API failure: ' . $error::class . ': ' . $error->getMessage());
    owner_bootstrap_respond(400, ['error' => 'bootstrap_validation_failed']);
}
