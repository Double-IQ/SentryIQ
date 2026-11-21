'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const endpoint = fs.readFileSync(
    path.join(__dirname, '../app/Gallery/StorageAuthorization.php'),
    'utf8'
);
const client = fs.readFileSync(
    path.join(__dirname, '../assets/js/gallery_storage.js'),
    'utf8'
);

test('stale-upload cleanup is a CSRF-protected POST, never a state-changing GET', () => {
    assert.doesNotMatch(endpoint, /REQUEST_METHOD\s*===\s*'GET'[\s\S]{0,100}cleanup_pending/);
    assert.match(endpoint, /\$request\s*=\s*gallery_storage_request\(\);[\s\S]*?\$action\s*=\s*\(string\)\(\$request\['action'\]\s*\?\?\s*''\);[\s\S]*?if\s*\(\$action\s*===\s*'cleanup_pending'\)/);
    assert.match(client, /await post\('cleanup_pending'\)/);
    assert.doesNotMatch(client, /gallery_storage\.php\?action=cleanup_pending/);
});

test('storage endpoint initializes the rotation journal before envelope migration uses it', () => {
    assert.match(endpoint, /\$rotationJournal\s*=\s*new\s+GalleryRotationStore\(\$dataDirectory\s*\.\s*'\/gallery_rotation\.json'\)/);
    assert.match(endpoint, /use\s*\(\$objectStore,\s*\$galleryKeys,\s*\$rotationJournal,/);
});

test('Gallery device removal is serialized with key rotation and rechecks enrollment under lock', () => {
    const passkeyEndpoint = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    assert.match(passkeyEndpoint, /if\s*\(\$action\s*===\s*'remove_credential'\)[\s\S]*?GalleryRotationLock::synchronized\(\$dataDirectory,[\s\S]*?\$rotationJournal->current\(\)/);
    assert.match(passkeyEndpoint, /Re-check both enrollments while holding the same transaction lock[\s\S]*?credentialEnvelope\(\$verifiedId\)[\s\S]*?credentialEnvelope\(\$targetId\)[\s\S]*?removeCredentialEnvelope\(\$targetId\)/);
    assert.match(passkeyEndpoint, /A Gallery device cannot be removed while key rotation is active or awaiting retirement/);
});

test('WebAuthn counters are re-read and updated under a dedicated lock', () => {
    const passkeyEndpoint = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    assert.match(passkeyEndpoint, /function gallery_passkey_save_counter\([\s\S]*?\.lock[\s\S]*?flock\(\$lock, LOCK_EX\)[\s\S]*?gallery_passkey_store\(\$path\)[\s\S]*?counter validation failed[\s\S]*?gallery_passkey_save\(\$path, \$store\)/);
    assert.match(passkeyEndpoint, /gallery_passkey_save_counter\(\$passkeyPath, \$credentialId, \$counter\)/);
});

test('Gallery and account passkey mutations share one locked store', () => {
    const galleryPasskeyEndpoint = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    const accountPasskeyEndpoint = fs.readFileSync(
        path.join(__dirname, '../app/Auth/PasskeyAuth.php'),
        'utf8'
    );
    assert.match(galleryPasskeyEndpoint, /\$lockPath\s*=\s*\$path\s*\.\s*'\.lock'/);
    assert.match(galleryPasskeyEndpoint, /gallery_passkey_save_counter\(\$passkeyPath, \$credentialId, \$counter\)/);
    assert.match(accountPasskeyEndpoint, /function pk_lock_store\([\s\S]*?pk_path\(\)\s*\.\s*'\.lock'[\s\S]*?flock\(\$handle, LOCK_EX\)/);
    assert.match(accountPasskeyEndpoint, /in_array\(\$action, \['register', 'delete', 'login'\], true\)[\s\S]*?\$passkeyStoreLock\s*=\s*pk_lock_store\(\)[\s\S]*?\$store\s*=\s*pk_store\(\)/);
    assert.match(accountPasskeyEndpoint, /GalleryRotationLock::synchronized\(\$dataDir,[\s\S]*?GalleryRotationStore\([\s\S]*?rotation is active or awaiting retirement[\s\S]*?removeCredentialEnvelope\(\$credentialId\)/);
    assert.match(galleryPasskeyEndpoint, /function \(\) use \(\$galleryKeys, \$rotationJournal, \$targetKeyId, \$verifiedId\)[\s\S]*?credentialEnvelope\(\$verifiedId\)/);
});

test('Gallery initialization and device enrollment serialize against passkey changes and rotation', () => {
    const passkeyEndpoint = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    assert.match(passkeyEndpoint, /function gallery_passkey_store_lock\(string \$path\)[\s\S]*?\$lockPath\s*=\s*\$path\s*\.\s*'\.lock'[\s\S]*?flock\(\$lock, LOCK_EX\)/);
    const initializeStart = passkeyEndpoint.indexOf("if ($action === 'initialize')");
    const addCredentialStart = passkeyEndpoint.indexOf("if ($action === 'add_credential')");
    const rotationStart = passkeyEndpoint.indexOf("if ($action === 'begin_rotation')");
    const initialize = passkeyEndpoint.slice(initializeStart, addCredentialStart);
    const addCredential = passkeyEndpoint.slice(addCredentialStart, rotationStart);
    assert.ok(initialize.indexOf('gallery_passkey_store_lock($passkeyPath)') < initialize.indexOf('GalleryRotationLock::synchronized($dataDirectory'));
    assert.ok(addCredential.indexOf('gallery_passkey_store_lock($passkeyPath)') < addCredential.indexOf('GalleryRotationLock::synchronized($dataDirectory'));
    assert.match(initialize, /\$galleryKeys->isInitialized\(\)/);
    assert.match(addCredential, /A Gallery device cannot be enrolled while key rotation is active or awaiting retirement/);
    assert.match(addCredential, /credentialEnvelope\(\$credentialId\) !== null/);
});

test('object envelope replacement is rejected outside the active rotation target', () => {
    const start = endpoint.indexOf("if ($action === 'replace_envelope')");
    const end = endpoint.indexOf("if ($action === 'key_inventory')", start);
    assert.ok(start >= 0 && end > start, 'Envelope replacement action should exist');
    const action = endpoint.slice(start, end);
    assert.match(action, /!is_array\(\$rotation\)/);
    assert.match(action, /\['running', 'ready_to_retire'\]/);
    assert.match(action, /\(\$envelope\['keyId'\]\s*\?\?\s*null\)\s*!==\s*\$rotation\['to_key_id'\]/);
    assert.match(action, /may only be replaced as part of the active key rotation/);
});

test('WebAuthn registration, login and Gallery assertion challenges are one-time', () => {
    const accountPasskey = fs.readFileSync(
        path.join(__dirname, '../app/Auth/PasskeyAuth.php'),
        'utf8'
    );
    const registerStart = accountPasskey.indexOf("if ($action==='register')");
    const loginStart = accountPasskey.indexOf("if ($action==='login')");
    const register = accountPasskey.slice(registerStart, loginStart);
    const login = accountPasskey.slice(loginStart);
    assert.ok(register.indexOf("WebAuthnChallenge::consume($_SESSION,'register',time())") >= 0);
    assert.ok(register.indexOf("WebAuthnChallenge::consume($_SESSION,'register',time())") < register.indexOf("pk_validate_client"));
    assert.ok(login.indexOf("WebAuthnChallenge::consume($_SESSION,'login',time())") >= 0);
    assert.ok(login.indexOf("WebAuthnChallenge::consume($_SESSION,'login',time())") < login.indexOf("pk_validate_client"));

    const galleryPasskey = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    const verifyStart = galleryPasskey.indexOf("if ($action === 'verify')");
    const verifyEnd = galleryPasskey.indexOf("if ($action === 'initialize')", verifyStart);
    const verify = galleryPasskey.slice(verifyStart, verifyEnd);
    assert.ok(verify.indexOf("unset($_SESSION['gallery_passkey_challenge']") > verify.indexOf("$challenge = gallery_passkey_unb64"));
    assert.ok(verify.indexOf("unset($_SESSION['gallery_passkey_challenge']") < verify.indexOf("gallery_passkey_verify_client"));
});

test('privileged Gallery passkey verification is consumed before every management attempt', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '../app/Auth/GalleryPasskeyAuth.php'),
        'utf8'
    );
    assert.match(source, /function gallery_passkey_consume_verified\(\): array[\s\S]*?unset\(\$_SESSION\['gallery_passkey_verified_credential'\], \$_SESSION\['gallery_passkey_verified_at'\]\)/);
    for (const action of [
        'initialize',
        'add_credential',
        'begin_rotation',
        'abort_rotation',
        'finalize_rotation',
        'add_wrapping_key',
        'remove_credential'
    ]) {
        const start = source.indexOf(`if ($action === '${action}')`);
        assert.ok(start >= 0, action + ' action should exist');
        const next = source.indexOf("if ($action === '", start + 1);
        const block = source.slice(start, next < 0 ? source.length : next);
        assert.ok(
            block.indexOf('gallery_passkey_consume_verified()') >= 0
            && block.indexOf('gallery_passkey_consume_verified()') < block.indexOf('throw new RuntimeException'),
            action + ' must consume verification before validation or mutation'
        );
        const withoutCleanup = block.replace(/unset\([^;]*gallery_passkey_verified_[^;]*\);/g, '');
        assert.doesNotMatch(withoutCleanup, /\$_SESSION\['gallery_passkey_verified_(?:credential|at)'\]/);
    }
});
