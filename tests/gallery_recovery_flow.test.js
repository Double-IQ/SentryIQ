'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../assets/js/gallery_secure.js'), 'utf8');

function createHarness(options = {}) {
    const calls = [];
    const recoveryKey = new Uint8Array(options.invalidLength ? 31 : 32).fill(7);
    const rootKey = new Uint8Array(32).fill(9);
    let clearedRecoveryKey = false;
    let clearedRootKey = false;
    let decryptedIdentity = false;
    const identity = {
        publicKey: { kty: 'RSA' },
        privateKeyEnvelope: { version: 1 },
        recoveryEnvelope: { version: 1 }
    };
    const cryptoApi = {
        fromBase64Url(value) {
            assert.equal(value, 'saved-recovery-code');
            return recoveryKey;
        },
        clearSecret(value) {
            if (value === recoveryKey) {
                value.fill(0);
                clearedRecoveryKey = true;
            }
            if (value === rootKey) {
                value.fill(0);
                clearedRootKey = true;
            }
        },
        async unlockIdentityWithRecovery(privateEnvelope, recoveryEnvelope, suppliedKey) {
            assert.equal(privateEnvelope, identity.privateKeyEnvelope);
            assert.equal(recoveryEnvelope, identity.recoveryEnvelope);
            assert.equal(suppliedKey, recoveryKey);
            if (suppliedKey.byteLength !== 32) throw new Error('invalid Gallery recovery material');
            decryptedIdentity = true;
            return { privateKey: { algorithm: { name: 'RSA-OAEP' } }, rootKey };
        }
    };
    const response = {
        ok: true,
        async json() { return { status: 'ok', identity }; }
    };
    const context = {
        window: null,
        self: null,
        document: { querySelector() { return { content: 'csrf-test-token' }; } },
        navigator: {},
        fetch: async (url, init = {}) => {
            calls.push({ url, init });
            if (options.failFetch) throw new Error('network unavailable');
            return response;
        },
        SentryIQGalleryCrypto: cryptoApi,
        Uint8Array,
        ArrayBuffer,
        TextEncoder,
        TextDecoder,
        Error,
        Promise,
        Object,
        String
    };
    context.window = context;
    context.self = context;
    vm.runInNewContext(source, context, { filename: 'gallery_secure.js' });
    return {
        api: context.SentryIQSecureGallery,
        calls,
        recoveryKey,
        rootKey,
        state: () => ({ clearedRecoveryKey, clearedRootKey, decryptedIdentity })
    };
}

test('recovery retrieves only the encrypted envelope and decrypts locally', async () => {
    const harness = createHarness();
    const result = await harness.api.unlockWithRecovery('saved-recovery-code');

    assert.equal(result.status, 'unlocked');
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].url, 'gallery_passkey.php?action=recovery-envelope');
    assert.equal(harness.calls[0].init.method || 'GET', 'GET');
    assert.equal(harness.calls[0].init.credentials, 'same-origin');
    assert.equal(harness.calls[0].init.cache, 'no-store');
    assert.equal(JSON.stringify(harness.calls[0].init).includes('saved-recovery-code'), false);
    assert.equal(harness.state().decryptedIdentity, true);
    assert.equal(harness.state().clearedRecoveryKey, true);
    assert.equal(harness.api.isUnlocked(), true);

    harness.api.lock();
    assert.equal(harness.api.isUnlocked(), false);
    assert.equal(harness.state().clearedRootKey, true);
});

test('recovery code is rejected locally when it does not decode to 32 bytes', async () => {
    const harness = createHarness({ invalidLength: true });
    await assert.rejects(
        harness.api.unlockWithRecovery('saved-recovery-code'),
        /invalid Gallery recovery material/
    );
});

test('recovery endpoint failure does not submit the recovery code to the server', async () => {
    const harness = createHarness({ failFetch: true });
    await assert.rejects(harness.api.unlockWithRecovery('saved-recovery-code'), /network unavailable/);
    assert.equal(harness.calls.length, 1);
    assert.equal(harness.calls[0].url, 'gallery_passkey.php?action=recovery-envelope');
    assert.equal(harness.calls[0].init.method || 'GET', 'GET');
    assert.equal(JSON.stringify(harness.calls[0].init).includes('saved-recovery-code'), false);
});
