'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const storage = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_storage.js'), 'utf8');
const ui = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_secure_ui.js'), 'utf8');
const secure = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_secure.js'), 'utf8');


const originalWindow = globalThis.window;
globalThis.window = globalThis;
require('../assets/js/gallery_storage.js');
if (originalWindow === undefined) delete globalThis.window;
else globalThis.window = originalWindow;

test('decrypted metadata buffers are cleared after parsing', () => {
    assert.match(storage, /function decodePrivateMetadata\([\s\S]*?finally\s*\{[\s\S]*?metadataBytes\.fill\(0\)/);
});

test('decrypted image buffers are cleared after Blob creation', () => {
    assert.match(storage, /new Uint8Array\(thumbnailBytes\)\.fill\(0\)/);
    assert.match(storage, /new Uint8Array\(previewBytes\)\.fill\(0\)/);
});

test('transient ciphertext buffers are cleared after upload and download', () => {
    assert.match(storage, /encrypted\[role\]\.ciphertext\.fill\(0\)/);
    assert.match(storage, /new Uint8Array\(ciphertext\)\.fill\(0\)/);
});

test('an in-flight decrypt is discarded and zeroed if Gallery locks before it completes', async () => {
    const originalFetch = globalThis.fetch;
    const originalDocument = globalThis.document;
    const originalSecureGallery = globalThis.SentryIQSecureGallery;
    let unlocked = true;
    let finishDecrypt;
    let markDecryptStarted;
    const decryptStarted = new Promise((resolve) => { markDecryptStarted = resolve; });
    const plaintext = new Uint8Array([11, 22, 33, 44]).buffer;

    globalThis.document = {
        querySelector(selector) {
            return selector === 'meta[name="csrf-token"]' ? { content: 'test-csrf-token' } : null;
        }
    };
    globalThis.SentryIQSecureGallery = {
        isUnlocked: () => unlocked,
        lock() {
            unlocked = false;
            globalThis.SentryIQGalleryStorage.invalidatePendingDecrypts();
        },
        decryptObject() {
            return new Promise((resolve) => {
                finishDecrypt = resolve;
                markDecryptStarted();
            });
        }
    };
    globalThis.fetch = async (url) => {
        if (url === 'gallery_storage.php') {
            return {
                ok: true,
                json: async () => ({
                    status: 'ok',
                    url: 'https://b2.example.test/private-object',
                    envelope: { version: 1 }
                })
            };
        }
        if (url === 'https://b2.example.test/private-object') {
            return { ok: true, arrayBuffer: async () => new ArrayBuffer(16) };
        }
        throw new Error('Unexpected fetch destination: ' + url);
    };

    try {
        const pending = globalThis.SentryIQGalleryStorage.download('a'.repeat(32), 'thumbnail');
        await decryptStarted;
        globalThis.SentryIQGalleryStorage.lock();
        finishDecrypt(plaintext);
        await assert.rejects(pending, /locked while decrypting this object/);
        assert.deepEqual(Array.from(new Uint8Array(plaintext)), [0, 0, 0, 0]);
    } finally {
        globalThis.fetch = originalFetch;
        globalThis.document = originalDocument;
        globalThis.SentryIQSecureGallery = originalSecureGallery;
    }
});

test('locking invalidates photo refreshes and clears album metadata from the UI', () => {
    assert.match(ui, /function lockWorkspace\(reason\)\s*\{\s*workspaceGeneration\+\+/);
    assert.match(ui, /if \(generation !== workspaceGeneration \|\| !SentryIQSecureGallery\.isUnlocked\(\)\)/);
    assert.match(ui, /photoCards = \[\];\s*updateAlbumFilter\(\);\s*workspace\.hidden = true/);
    assert.match(ui, /byId\('secure-gallery-album'\)\.value = ''/);
});

test('photo metadata is cleared when loading fails or preview creation completes', () => {
    assert.match(storage, /function clearPrivateMetadata\([\s\S]*?metadata\[key\] = ''/);
    assert.match(storage, /async function loadPhoto\([\s\S]*?catch \(error\) \{\s*clearPrivateMetadata\(metadata\)/);
    assert.match(storage, /async function openPreview\([\s\S]*?finally \{\s*clearPrivateMetadata\(metadata\)/);
});

test('asynchronous key operations cannot restore Gallery keys after a lock', () => {
    assert.match(secure, /let sessionGeneration = 0/);
    assert.match(secure, /function lock\(\)\s*\{\s*sessionGeneration\+\+/);
    const guardedOperations = [
        'unlock', 'prepareIdentity', 'completeIdentitySetup', 'unlockWithRecovery',
        'enrollCurrentPasskey', 'addWrappingKey', 'ensureKeyAvailable',
        'syncKeyringState', 'startRotation', 'abortRotation', 'finalizeRotation', 'removeEnrolledDevice'
    ];
    guardedOperations.forEach(function (name) {
        const start = secure.indexOf('async function ' + name + '(');
        assert.notEqual(start, -1, name + ' should exist');
        const end = secure.indexOf('\n    }', start);
        assert.notEqual(end, -1, name + ' should have a function boundary');
        assert.match(
            secure.slice(start, end),
            /assertSessionGeneration\(generation/,
            name + ' must reject results from an earlier unlocked session'
        );
    });
});

test('identity unlock root-key copies and private-key references are cleared when no longer needed', () => {
    assert.match(secure, /async function completeIdentitySetup[\s\S]*?clearSecret\(activeKeys\.rootKey\)/);
    assert.match(secure, /async function addWrappingKey[\s\S]*?clearSecret\(refreshed\.rootKey\)/);
    assert.match(secure, /function assertSessionGeneration[\s\S]*?delete result\.privateKeys\[keyId\]/);
});
test('pagehide protection is active even before the unlock-time session guard starts', () => {
    assert.match(ui, /window\.addEventListener\('pagehide', function \(\) \{[\s\S]*?lockWorkspace\('pagehide'\)/);
    assert.match(ui, /secure-gallery-unlock'\)\.addEventListener\('click',[\s\S]*?startSessionGuard\(\);\s*const result = await SentryIQSecureGallery\.unlock\(\)/);
    assert.match(ui, /secure-gallery-recover'\)\.addEventListener\('click',[\s\S]*?startSessionGuard\(\);\s*await SentryIQSecureGallery\.unlockWithRecovery/);
});

test('transient passkey and recovery secrets are tracked and cleared immediately on lock', () => {
    assert.match(secure, /const transientSecrets = new Set\(\)/);
    assert.match(secure, /function trackSecret\(value\)/);
    assert.match(secure, /Array\.from\(transientSecrets\)\.forEach\(clearSecret\)/);
    assert.match(secure, /prfOutput = trackSecret\(new Uint8Array\(prfResult\)\)/);
    assert.match(secure, /pendingSetup\.recoveryCode = ''/);
    assert.match(secure, /async function verifyPasskey[\s\S]*?assertSessionGeneration\(generation\)[\s\S]*?const verified = await readJson\(verifiedResponse\);\s*assertSessionGeneration\(generation\)/);
});
