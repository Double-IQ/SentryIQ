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
    assert.match(passkeyEndpoint, /function gallery_passkey_save_counter\([\s\S]*?\.counter\.lock[\s\S]*?flock\(\$lock, LOCK_EX\)[\s\S]*?gallery_passkey_store\(\$path\)[\s\S]*?counter validation failed[\s\S]*?gallery_passkey_save\(\$path, \$store\)/);
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
});
