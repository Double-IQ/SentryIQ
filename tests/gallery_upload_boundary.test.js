'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

assert.equal(typeof File, 'function', 'Node.js File support is required for Gallery upload tests.');

const requests = [];
const documentStub = {
    querySelector(selector) {
        return selector === 'meta[name="csrf-token"]' ? { content: 'test-csrf-token' } : null;
    },
    createElement(name) {
        assert.equal(name, 'canvas');
        return {
            width: 0,
            height: 0,
            getContext() { return { drawImage() {} }; },
            toBlob(callback, type) {
                callback(new Blob([new TextEncoder().encode('DERIVATIVE-PLAINTEXT')], { type }));
            }
        };
    }
};

globalThis.window = globalThis;
globalThis.document = documentStub;
globalThis.createImageBitmap = async () => ({
    width: 640,
    height: 480,
    close() {}
});

globalThis.SentryIQSecureGallery = {
    isUnlocked: () => true,
    async encryptObject(plaintext, photoId, role) {
        const input = plaintext instanceof ArrayBuffer ? new Uint8Array(plaintext) : new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
        const ciphertext = Uint8Array.from(input, (value) => value ^ 0xff);
        return {
            ciphertext,
            envelope: { version: 1, role, photoId, keyId: 'gk_testkey01', wrappedDek: 'opaque-wrapped-key' }
        };
    }
};

const photoId = 'a'.repeat(32);
const roles = ['original', 'thumbnail', 'preview', 'metadata'];
globalThis.fetch = async (url, options) => {
    if (url === 'gallery_storage.php') {
        const body = JSON.parse(options.body);
        requests.push({ kind: 'php', body, options });
        if (body.action === 'allocate') {
            return { ok: true, json: async () => ({
                status: 'ok',
                photoId,
                uploadUrls: Object.fromEntries(roles.map((role) => [role, 'https://b2.example.test/' + role]))
            }) };
        }
        if (body.action === 'commit') return { ok: true, json: async () => ({ status: 'ok', photoId }) };
        throw new Error('Unexpected PHP action: ' + body.action);
    }

    if (String(url).startsWith('https://b2.example.test/')) {
        const bytes = options.body instanceof Uint8Array ? options.body : new Uint8Array(options.body);
        requests.push({ kind: 'b2', url, options, bytes: bytes.slice() });
        return { ok: true, status: 200 };
    }
    throw new Error('Unexpected fetch destination: ' + url);
};

require('../assets/js/gallery_storage.js');

test('Gallery upload sends encrypted objects to B2 and metadata-only commits to PHP', async () => {
    const file = new File(
        [new TextEncoder().encode('ORIGINAL-PLAINTEXT-PRIVATE-PHOTO')],
        'private-photo-name.jpg',
        { type: 'image/png' }
    );

    const result = await globalThis.SentryIQGalleryStorage.upload(file, 'Private Album');

    assert.equal(result.photoId, photoId);
    const phpRequests = requests.filter((item) => item.kind === 'php');
    const b2Requests = requests.filter((item) => item.kind === 'b2');
    assert.equal(phpRequests.length, 2, 'PHP should receive only allocation and envelope commit requests');
    assert.equal(b2Requests.length, 4, 'The browser should upload all four encrypted object roles directly to B2');

    const commit = phpRequests.find((item) => item.body.action === 'commit');
    assert.ok(commit, 'PHP should receive the encrypted object envelopes');
    const phpPayload = JSON.stringify(phpRequests.map((item) => item.body));
    assert.doesNotMatch(phpPayload, /ORIGINAL-PLAINTEXT|DERIVATIVE-PLAINTEXT|private-photo-name|Private Album/);

    for (const upload of b2Requests) {
        assert.equal(upload.options.method, 'PUT');
        assert.equal(upload.options.credentials, 'omit');
        assert.equal(upload.options.redirect, 'error');
        assert.equal(upload.options.headers['Content-Type'], 'application/octet-stream');
        const decoded = new TextDecoder().decode(upload.bytes);
        assert.doesNotMatch(decoded, /ORIGINAL-PLAINTEXT|DERIVATIVE-PLAINTEXT|private-photo-name|Private Album/);
    }
});
