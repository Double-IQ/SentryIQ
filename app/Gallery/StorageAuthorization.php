<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/BackblazeB2Signer.php';
require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/GalleryObjectStore.php';
require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/GalleryKeyStore.php';

use SentryIQCloud\Gallery\Storage\BackblazeB2Signer;
use SentryIQCloud\Gallery\Storage\GalleryObjectStore;
use SentryIQCloud\Gallery\Storage\GalleryKeyStore;

function gallery_storage_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function gallery_storage_data_directory(): string
{
    $directory = sentryiq_data_dir();
    if ($directory === '' || !str_starts_with($directory, '/') || !is_dir($directory) || is_link($directory)) {
        throw new RuntimeException('SentryIQ secure runtime is unavailable.');
    }
    $runtime = realpath($directory);
    $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
    if ($runtime === false || (is_string($documentRoot) && $documentRoot !== ''
        && ($runtime === $documentRoot || str_starts_with($runtime . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)))) {
        throw new RuntimeException('SentryIQ secure runtime must be outside the public web root.');
    }
    return rtrim($runtime, '/');
}

function gallery_storage_request(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || strlen($raw) > 65536) throw new RuntimeException('Invalid Gallery storage request.');
    $request = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($request)) throw new RuntimeException('Invalid Gallery storage request.');
    $provided = (string)($request['csrf_token'] ?? '');
    $expected = (string)($_SESSION['csrf_token'] ?? '');
    if ($provided === '' || $expected === '' || !hash_equals($expected, $provided)) {
        throw new RuntimeException('Security validation failed.');
    }
    return $request;
}

try {
    $dataDirectory = gallery_storage_data_directory();
    $objectStore = new GalleryObjectStore($dataDirectory . '/gallery_objects.json');
    $galleryKeys = new GalleryKeyStore($dataDirectory . '/gallery_keys.json');
    $signer = BackblazeB2Signer::fromRuntimeDirectory($dataDirectory);

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && (string)($_GET['action'] ?? '') === 'cleanup_pending') {
        $cleanup = [];
        foreach ($objectStore->stalePending() as $photoId => $record) {
            $deleteUrls = [];
            foreach ((array)($record['objects'] ?? []) as $role => $object) {
                if (!is_array($object) || !is_string($object['key'] ?? null)) continue;
                $deleteUrls[$role] = $signer->presign('DELETE', $object['key'], 300);
            }
            $cleanup[$photoId] = $deleteUrls;
        }
        gallery_storage_json(['status' => 'ok', 'pending' => $cleanup]);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && (string)($_GET['action'] ?? '') === 'list') {
        gallery_storage_json(['status' => 'ok', 'photos' => $objectStore->all()]);
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: GET, POST');
        gallery_storage_json(['status' => 'error', 'message' => 'Unsupported request method.'], 405);
    }

    $request = gallery_storage_request();
    $action = (string)($request['action'] ?? '');

    if ($action === 'allocate') {
        if (!$galleryKeys->isInitialized()) gallery_storage_json(['status' => 'error', 'message' => 'Initialize secure Gallery before uploading photos.'], 409);
        $photoId = bin2hex(random_bytes(16));
        $objectKeys = [];
        $uploadUrls = [];
        foreach (['original', 'thumbnail', 'preview', 'metadata'] as $role) {
            $objectKeys[$role] = BackblazeB2Signer::newObjectKey($role);
        }
        $objectStore->createPending($photoId, $objectKeys);
        try {
            foreach ($objectKeys as $role => $objectKey) {
                $uploadUrls[$role] = $signer->presign('PUT', $objectKey, 300);
            }
        } catch (Throwable $exception) {
            $objectStore->remove($photoId);
            throw $exception;
        }
        gallery_storage_json(['status' => 'ok', 'photoId' => $photoId, 'uploadUrls' => $uploadUrls, 'expiresIn' => 300]);
    }

    if ($action === 'commit') {
        if (!$galleryKeys->isInitialized()) gallery_storage_json(['status' => 'error', 'message' => 'Secure Gallery identity is unavailable.'], 409);
        $photoId = (string)($request['photoId'] ?? '');
        $envelopes = is_array($request['envelopes'] ?? null) ? $request['envelopes'] : [];
        $sizes = is_array($request['sizes'] ?? null) ? $request['sizes'] : [];
        $objectStore->commit($photoId, $envelopes, $sizes);
        gallery_storage_json(['status' => 'ok', 'photoId' => $photoId]);
    }

    if ($action === 'download') {
        $photoId = (string)($request['photoId'] ?? '');
        $role = (string)($request['role'] ?? '');
        if (!in_array($role, ['original', 'thumbnail', 'preview', 'metadata'], true)) {
            throw new RuntimeException('Invalid Gallery object role.');
        }
        $record = $objectStore->find($photoId);
        if (!is_array($record) || ($record['status'] ?? '') !== 'active' || !isset($record['objects'][$role]['key'])) {
            gallery_storage_json(['status' => 'error', 'message' => 'Gallery object not found.'], 404);
        }
        $url = $signer->presign('GET', (string)$record['objects'][$role]['key'], 300);
        gallery_storage_json([
            'status' => 'ok',
            'url' => $url,
            'envelope' => $record['objects'][$role]['envelope'],
            'expiresIn' => 300,
        ]);
    }

    if ($action === 'delete_urls') {
        $photoId = (string)($request['photoId'] ?? '');
        $record = $objectStore->find($photoId);
        if (!is_array($record) || ($record['status'] ?? '') !== 'active' || !is_array($record['objects'] ?? null)) {
            gallery_storage_json(['status' => 'error', 'message' => 'Gallery photo not found.'], 404);
        }
        $deleteUrls = [];
        foreach ($record['objects'] as $role => $object) {
            if (!is_array($object) || !is_string($object['key'] ?? null)) continue;
            $deleteUrls[$role] = $signer->presign('DELETE', $object['key'], 300);
        }
        gallery_storage_json(['status' => 'ok', 'deleteUrls' => $deleteUrls, 'expiresIn' => 300]);
    }

    if ($action === 'confirm_delete') {
        $photoId = (string)($request['photoId'] ?? '');
        $record = $objectStore->remove($photoId);
        if ($record === null) gallery_storage_json(['status' => 'error', 'message' => 'Gallery photo not found.'], 404);
        gallery_storage_json(['status' => 'ok', 'photoId' => $photoId]);
    }

    if ($action === 'cancel') {
        $photoId = (string)($request['photoId'] ?? '');
        $record = $objectStore->find($photoId);
        if (!is_array($record) || ($record['status'] ?? '') !== 'pending') {
            gallery_storage_json(['status' => 'ok', 'deleteUrls' => []]);
        }
        $deleteUrls = [];
        foreach ((array)($record['objects'] ?? []) as $role => $object) {
            if (!is_array($object) || !is_string($object['key'] ?? null)) continue;
            $deleteUrls[$role] = $signer->presign('DELETE', $object['key'], 300);
        }
        gallery_storage_json(['status' => 'ok', 'deleteUrls' => $deleteUrls, 'expiresIn' => 300]);
    }

    if ($action === 'confirm_cancel') {
        $photoId = (string)($request['photoId'] ?? '');
        $record = $objectStore->find($photoId);
        if (is_array($record) && ($record['status'] ?? '') === 'pending') $objectStore->remove($photoId);
        gallery_storage_json(['status' => 'ok']);
    }

    gallery_storage_json(['status' => 'error', 'message' => 'Unknown Gallery storage operation.'], 400);
} catch (Throwable $exception) {
    error_log('SentryIQ Gallery storage operation failed: ' . $exception::class);
    gallery_storage_json(['status' => 'error', 'message' => $exception->getMessage()], 400);
}
