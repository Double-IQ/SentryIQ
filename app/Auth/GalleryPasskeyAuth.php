<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/GalleryKeyStore.php';

use SentryIQCloud\Gallery\Storage\GalleryKeyStore;

function gallery_passkey_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}

function gallery_passkey_b64(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function gallery_passkey_unb64(string $value): string|false
{
    if ($value === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) return false;
    $padding = strlen($value) % 4;
    if ($padding !== 0) $value .= str_repeat('=', 4 - $padding);
    return base64_decode(strtr($value, '-_', '+/'), true);
}

function gallery_passkey_data_directory(): string
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

function gallery_passkey_origin(): array
{
    $configFile = dirname(__DIR__, 2) . '/sentryiq_config.php';
    $config = is_file($configFile) ? require $configFile : [];
    $parts = is_array($config) ? parse_url(trim((string)($config['base_url'] ?? ''))) : false;
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https' || empty($parts['host'])) {
        throw new RuntimeException('SentryIQ HTTPS origin is unavailable.');
    }
    $host = strtolower((string)$parts['host']);
    if (!preg_match('/^[a-z0-9.-]+$/', $host)) throw new RuntimeException('Invalid relying party identifier.');
    $port = isset($parts['port']) ? ':' . (int)$parts['port'] : '';
    return ['origin' => 'https://' . $host . $port, 'rp_id' => $host];
}

function gallery_passkey_store(string $path): array
{
    if (!is_file($path) || is_link($path)) throw new RuntimeException('No registered passkeys are available.');
    $raw = @file_get_contents($path);
    $store = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($store) || !is_array($store['credentials'] ?? null)) throw new RuntimeException('Passkey storage is invalid.');
    return $store;
}

function gallery_passkey_save(string $path, array $store): void
{
    $json = json_encode($store, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    $temporary = $path . '.tmp-' . bin2hex(random_bytes(12));
    $handle = @fopen($temporary, 'xb');
    if ($handle === false) throw new RuntimeException('Unable to update passkey storage.');
    try {
        @chmod($temporary, 0600);
        if (fwrite($handle, $json) !== strlen($json)) throw new RuntimeException('Unable to update passkey storage.');
        fflush($handle);
        if (function_exists('fsync')) @fsync($handle);
    } finally {
        fclose($handle);
    }
    if (!@rename($temporary, $path)) {
        @unlink($temporary);
        throw new RuntimeException('Unable to update passkey storage.');
    }
    @chmod($path, 0600);
}

function gallery_passkey_verify_client(string $clientDataJson, string $challenge, string $origin): void
{
    try {
        $data = json_decode($clientDataJson, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        throw new RuntimeException('Invalid WebAuthn client data.');
    }
    if (!is_array($data) || ($data['type'] ?? '') !== 'webauthn.get' || ($data['origin'] ?? '') !== $origin
        || !is_string($data['challenge'] ?? null) || !hash_equals($challenge, $data['challenge'])
        || ($data['crossOrigin'] ?? false) === true) {
        throw new RuntimeException('WebAuthn assertion validation failed.');
    }
}

function gallery_passkey_verify_authenticator_data(string $authenticatorData, string $rpId): int
{
    if (strlen($authenticatorData) < 37 || !hash_equals(hash('sha256', $rpId, true), substr($authenticatorData, 0, 32))) {
        throw new RuntimeException('WebAuthn relying party validation failed.');
    }
    $flags = ord($authenticatorData[32]);
    if (($flags & 0x01) === 0 || ($flags & 0x04) === 0 || ($flags & 0x40) !== 0) {
        throw new RuntimeException('Passkey user verification failed.');
    }
    return (int)unpack('N', substr($authenticatorData, 33, 4))[1];
}

function gallery_passkey_csrf(array $request): void
{
    $provided = (string)($request['csrf_token'] ?? '');
    $expected = (string)($_SESSION['csrf_token'] ?? '');
    if ($provided === '' || $expected === '' || !hash_equals($expected, $provided)) {
        throw new RuntimeException('Security validation failed.');
    }
}

try {
    $dataDirectory = gallery_passkey_data_directory();
    $passkeyPath = $dataDirectory . '/passkeys.json';
    $galleryKeys = new GalleryKeyStore($dataDirectory . '/gallery_keys.json');
    $origin = gallery_passkey_origin();

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && (string)($_GET['action'] ?? '') === 'recovery-envelope') {
        if (!$galleryKeys->isInitialized()) gallery_passkey_json(['status' => 'error', 'message' => 'Secure Gallery has not been initialized.'], 404);
        gallery_passkey_json([
            'status' => 'ok',
            'identity' => [
                'publicKey' => $galleryKeys->publicKey(),
                'privateKeyEnvelope' => $galleryKeys->privateKeyEnvelope(),
                'recoveryEnvelope' => $galleryKeys->recoveryEnvelope(),
            ],
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'GET' && (string)($_GET['action'] ?? '') === 'options') {
        $store = gallery_passkey_store($passkeyPath);
        if ($galleryKeys->isInitialized()) {
            $accountSalt = gallery_passkey_unb64((string)$galleryKeys->accountSalt());
            if ($accountSalt === false || strlen($accountSalt) !== 32) throw new RuntimeException('Gallery PRF salt is invalid.');
        } else {
            $accountSalt = gallery_passkey_unb64((string)($_SESSION['gallery_prf_salt'] ?? ''));
            if ($accountSalt === false || strlen($accountSalt) !== 32) {
                $accountSalt = random_bytes(32);
                $_SESSION['gallery_prf_salt'] = gallery_passkey_b64($accountSalt);
            }
        }
        $challenge = random_bytes(32);
        $_SESSION['gallery_passkey_challenge'] = gallery_passkey_b64($challenge);
        $allowCredentials = [];
        foreach ($store['credentials'] as $record) {
            if (!is_array($record) || !is_string($record['credential_id'] ?? null)) continue;
            $credentialBytes = gallery_passkey_unb64($record['credential_id']);
            if ($credentialBytes === false || strlen($credentialBytes) < 16) continue;
            $allowCredentials[] = ['type' => 'public-key', 'id' => $record['credential_id']];
        }
        if ($allowCredentials === []) throw new RuntimeException('No usable passkeys are registered.');
        gallery_passkey_json([
            'status' => 'ok',
            'options' => [
                'challenge' => gallery_passkey_b64($challenge),
                'rpId' => $origin['rp_id'],
                'allowCredentials' => $allowCredentials,
                'userVerification' => 'required',
                'timeout' => 60000,
                'extensions' => [
                    'prf' => [
                        'eval' => ['first' => gallery_passkey_b64($accountSalt)],
                    ],
                ],
            ],
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: GET, POST');
        gallery_passkey_json(['status' => 'error', 'message' => 'Unsupported request method.'], 405);
    }

    $raw = file_get_contents('php://input');
    if (!is_string($raw) || strlen($raw) > 65536) throw new RuntimeException('Invalid Gallery passkey request.');
    $request = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($request)) throw new RuntimeException('Invalid Gallery passkey request.');
    gallery_passkey_csrf($request);

    $action = (string)($request['action'] ?? '');
    if ($action === 'verify') {
        if (array_key_exists('prf', $request) || array_key_exists('prf_output', $request)) {
            throw new RuntimeException('PRF output must remain in the browser.');
        }
        $store = gallery_passkey_store($passkeyPath);
        $challenge = gallery_passkey_unb64((string)($_SESSION['gallery_passkey_challenge'] ?? ''));
        if ($challenge === false || strlen($challenge) !== 32) throw new RuntimeException('Gallery passkey challenge expired.');

        $credentialIdBytes = gallery_passkey_unb64((string)($request['rawId'] ?? ''));
        $clientData = gallery_passkey_unb64((string)($request['clientDataJSON'] ?? ''));
        $authenticatorData = gallery_passkey_unb64((string)($request['authenticatorData'] ?? ''));
        $signature = gallery_passkey_unb64((string)($request['signature'] ?? ''));
        if ($credentialIdBytes === false || $clientData === false || $authenticatorData === false || $signature === false) {
            throw new RuntimeException('Incomplete Gallery passkey assertion.');
        }

        $credentialId = gallery_passkey_b64($credentialIdBytes);
        $foundIndex = null;
        $record = null;
        foreach ($store['credentials'] as $index => $candidate) {
            if (is_array($candidate) && is_string($candidate['credential_id'] ?? null)
                && hash_equals($candidate['credential_id'], $credentialId)) {
                $foundIndex = $index;
                $record = $candidate;
                break;
            }
        }
        if (!is_array($record) || $foundIndex === null) throw new RuntimeException('Unknown passkey.');

        gallery_passkey_verify_client($clientData, gallery_passkey_b64($challenge), $origin['origin']);
        $counter = gallery_passkey_verify_authenticator_data($authenticatorData, $origin['rp_id']);
        $publicKeyDer = gallery_passkey_unb64((string)($record['public_key'] ?? ''));
        if ($publicKeyDer === false) throw new RuntimeException('Stored passkey public key is invalid.');
        $publicKey = @openssl_pkey_get_public($publicKeyDer);
        if ($publicKey === false) throw new RuntimeException('Stored passkey public key is invalid.');
        $clientHash = hash('sha256', $clientData, true);
        if (openssl_verify($authenticatorData . $clientHash, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new RuntimeException('Passkey signature verification failed.');
        }

        $previousCounter = (int)($record['sign_count'] ?? 0);
        if ($counter !== 0 && $previousCounter !== 0 && $counter <= $previousCounter) {
            throw new RuntimeException('Passkey signature counter validation failed.');
        }
        $store['credentials'][$foundIndex]['sign_count'] = max($previousCounter, $counter);
        gallery_passkey_save($passkeyPath, $store);

        unset($_SESSION['gallery_passkey_challenge']);
        $_SESSION['gallery_passkey_verified_credential'] = $credentialId;
        $_SESSION['gallery_passkey_verified_at'] = time();

        $identity = null;
        if ($galleryKeys->isInitialized()) {
            $identity = [
                'publicKey' => $galleryKeys->publicKey(),
                'privateKeyEnvelope' => $galleryKeys->privateKeyEnvelope(),
                'credentialEnvelope' => $galleryKeys->credentialEnvelope($credentialId),
                'recoveryEnvelope' => $galleryKeys->recoveryEnvelope(),
            ];
        }
        gallery_passkey_json(['status' => 'ok', 'credentialId' => $credentialId, 'identity' => $identity]);
    }

    if ($action === 'initialize') {
        $credentialId = (string)($request['credentialId'] ?? '');
        $verifiedId = (string)($_SESSION['gallery_passkey_verified_credential'] ?? '');
        $verifiedAt = (int)($_SESSION['gallery_passkey_verified_at'] ?? 0);
        if ($credentialId === '' || $verifiedId === '' || !hash_equals($verifiedId, $credentialId)
            || $verifiedAt < time() - 300) throw new RuntimeException('Verify a passkey before initializing Gallery encryption.');
        $store = gallery_passkey_store($passkeyPath);
        $knownCredential = false;
        foreach ($store['credentials'] as $record) {
            if (is_array($record) && hash_equals((string)($record['credential_id'] ?? ''), $credentialId)) $knownCredential = true;
        }
        if (!$knownCredential) throw new RuntimeException('Unknown passkey.');
        $credentialEnvelope = (array)($request['credentialEnvelope'] ?? []);
        $expectedGallerySalt = (string)($_SESSION['gallery_prf_salt'] ?? '');
        if ($expectedGallerySalt === '' || !hash_equals($expectedGallerySalt, (string)($credentialEnvelope['salt'] ?? ''))) {
            throw new RuntimeException('Gallery passkey envelope does not match the active Gallery PRF salt.');
        }
        $galleryKeys->initialize(
            (array)($request['publicKey'] ?? []),
            (array)($request['privateKeyEnvelope'] ?? []),
            $credentialId,
            $credentialEnvelope,
            (array)($request['recoveryEnvelope'] ?? [])
        );
        unset($_SESSION['gallery_passkey_verified_credential'], $_SESSION['gallery_passkey_verified_at'], $_SESSION['gallery_prf_salt']);
        gallery_passkey_json(['status' => 'ok']);
    }

    if ($action === 'add_credential') {
        $credentialId = (string)($request['credentialId'] ?? '');
        $verifiedId = (string)($_SESSION['gallery_passkey_verified_credential'] ?? '');
        $verifiedAt = (int)($_SESSION['gallery_passkey_verified_at'] ?? 0);
        if ($credentialId === '' || $verifiedId === '' || !hash_equals($verifiedId, $credentialId)
            || $verifiedAt < time() - 300) throw new RuntimeException('Verify a passkey before adding its Gallery envelope.');
        $store = gallery_passkey_store($passkeyPath);
        $knownCredential = false;
        foreach ($store['credentials'] as $record) {
            if (is_array($record) && hash_equals((string)($record['credential_id'] ?? ''), $credentialId)) $knownCredential = true;
        }
        if (!$knownCredential) throw new RuntimeException('Unknown passkey.');
        $galleryKeys->addCredentialEnvelope($credentialId, (array)($request['credentialEnvelope'] ?? []));
        unset($_SESSION['gallery_passkey_verified_credential'], $_SESSION['gallery_passkey_verified_at']);
        gallery_passkey_json(['status' => 'ok']);
    }

    throw new RuntimeException('Unknown Gallery passkey operation.');
} catch (Throwable $exception) {
    error_log('SentryIQ Gallery passkey operation failed: ' . $exception::class);
    gallery_passkey_json(['status' => 'error', 'message' => $exception->getMessage()], 400);
}
