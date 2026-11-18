'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const roles = ['original', 'thumbnail', 'preview', 'metadata'];
const photoId = 'a'.repeat(32);
const revision = 'a'.repeat(64);
const replacements = [];
const envelopeHashes = Object.fromEntries(roles.map(() => []));
const envelopes = Object.fromEntries(roles.map((role) => [role, {
    version: 1,
    algorithm: 'A256GCM',
    keyWrap: 'RSA-OAEP-256',
    nonce: 'N'.repeat(16),
    wrappedDek: 'W'.repeat(512),
    photoId,
    role
}]));

globalThis.window = globalThis;
globalThis.document = {
    querySelector(selector) {
        return selector === 'meta[name="csrf-token"]' ? { content: 'test-csrf-token' } : null;
    }
};
globalThis.SentryIQSecureGallery = {
    isUnlocked: () => true,
    async rewrapObjectEnvelope(envelope, id, role, targetKeyId) {
        assert.equal(id, photoId);
        assert.ok(roles.includes(role));
        return { ...envelope, keyId: targetKeyId, wrappedDek: 'R'.repeat(512) };
    }
};
globalThis.fetch = async (url, options = {}) => {
    if (url === 'gallery_storage.php?action=cleanup_pending') {
        return { ok: true, json: async () => ({ status: 'ok', pending: {} }) };
    }
    if (url === 'gallery_storage.php?action=list') {
        return {
            ok: true,
            json: async () => ({
                status: 'ok',
                photos: {
                    [photoId]: {
                        objects: Object.fromEntries(roles.map((role) => [role, {
                            envelope: envelopes[role],
                            envelope_hash: envelopeHashes[role].at(-1) || revision
                        }]))
                    }
                }
            })
        };
    }
    if (url === 'gallery_storage.php') {
        const body = JSON.parse(options.body);
        if (body.action === 'replace_envelope') {
            replacements.push(body);
            envelopes[body.role] = body.envelope;
            const nextHash = String.fromCharCode(97 + envelopeHashes[body.role].length + 1).repeat(64);
            envelopeHashes[body.role].push(nextHash);
            return { ok: true, json: async () => ({ status: 'ok', envelopeHash: nextHash }) };
        }
        if (body.action === 'key_inventory') {
            return { ok: true, json: async () => ({ status: 'ok', complete: true, references: { gk_target01: 4 } }) };
        }
        throw new Error('Unexpected Gallery storage action: ' + body.action);
    }
    throw new Error('Unexpected fetch URL: ' + url);
};

require('../assets/js/gallery_storage.js');

test('Gallery rotation rewraps every object envelope without uploading photo ciphertext', async () => {
    const result = await globalThis.SentryIQGalleryStorage.migrateEnvelopesToKey('gk_target01');
    assert.equal(result.updated, 4);
    assert.equal(result.skipped, 0);
    assert.equal(result.total, 4);
    assert.equal(replacements.length, 4);
    for (const item of replacements) {
        assert.equal(item.action, 'replace_envelope');
        assert.equal(item.photoId, photoId);
        assert.equal(item.expectedEnvelopeHash, revision);
        assert.equal(item.envelope.keyId, 'gk_target01');
        assert.equal(item.envelope.nonce, 'N'.repeat(16));
    }

    // Simulate a reload after all four CAS writes committed. A resumed scan
    // must recognise the target key and must not rewrap or rewrite envelopes.
    const resumed = await globalThis.SentryIQGalleryStorage.migrateEnvelopesToKey('gk_target01');
    assert.equal(resumed.updated, 0);
    assert.equal(resumed.skipped, 4);
    assert.equal(replacements.length, 4);
    assert.ok(roles.every((role) => envelopes[role].keyId === 'gk_target01'));
});
