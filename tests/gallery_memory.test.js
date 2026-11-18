'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const storage = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_storage.js'), 'utf8');


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
        lock() { unlocked = false; },
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
