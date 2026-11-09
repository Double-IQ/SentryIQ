'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = globalThis.crypto;
if (!crypto || !crypto.subtle) throw new Error('Node.js Web Crypto is required for Gallery tests.');
globalThis.window = globalThis;
globalThis.self = globalThis;

require('../assets/js/gallery_crypto.js');
const gallery = globalThis.SentryIQGalleryCrypto;

function randomCredentialId() {
    return gallery.toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

test('Gallery identity supports passkey unlock, recovery and additional credentials', async () => {
    const accountSalt = gallery.createAccountSalt();
    const prfOne = crypto.getRandomValues(new Uint8Array(32));
    const credentialOne = randomCredentialId();
    const identity = await gallery.createIdentity(prfOne, accountSalt, credentialOne);

    assert.equal(identity.publicKey.kty, 'RSA');
    assert.equal(identity.publicKey.alg, 'RSA-OAEP-256');
    assert.equal(identity.privateKeyEnvelope.version, 1);
    assert.equal(identity.credentialEnvelope.credentialId, credentialOne);

    const unlocked = await gallery.unlockIdentity(
        identity.privateKeyEnvelope,
        identity.credentialEnvelope,
        prfOne,
        credentialOne
    );
    assert.equal(unlocked.privateKey.algorithm.name, 'RSA-OAEP');
    assert.equal(unlocked.rootKey.byteLength, 32);

    const incorrectPrf = crypto.getRandomValues(new Uint8Array(32));
    await assert.rejects(
        gallery.unlockIdentity(identity.privateKeyEnvelope, identity.credentialEnvelope, incorrectPrf, credentialOne),
        /Unable to unlock/
    );
    incorrectPrf.fill(0);

    const wrongCredential = randomCredentialId();
    await assert.rejects(
        gallery.unlockIdentity(identity.privateKeyEnvelope, identity.credentialEnvelope, prfOne, wrongCredential),
        /different passkey/
    );

    const recoveryKey = await gallery.createRecoveryKey();
    const recoverySalt = gallery.createAccountSalt();
    const recoveryEnvelope = await gallery.wrapRootKeyForRecovery(unlocked.rootKey, recoveryKey, recoverySalt);
    const recovered = await gallery.unlockIdentityWithRecovery(
        identity.privateKeyEnvelope,
        recoveryEnvelope,
        recoveryKey
    );

    const incorrectRecoveryKey = await gallery.createRecoveryKey();
    await assert.rejects(
        gallery.unlockIdentityWithRecovery(identity.privateKeyEnvelope, recoveryEnvelope, incorrectRecoveryKey),
        /recovery key is incorrect/
    );
    incorrectRecoveryKey.fill(0);

    const changedRecoveryEnvelope = {
        ...recoveryEnvelope,
        ciphertext: (recoveryEnvelope.ciphertext[0] === 'A' ? 'B' : 'A') + recoveryEnvelope.ciphertext.slice(1)
    };
    await assert.rejects(
        gallery.unlockIdentityWithRecovery(identity.privateKeyEnvelope, changedRecoveryEnvelope, recoveryKey),
        /recovery key is incorrect/
    );
    assert.equal(recovered.privateKey.algorithm.name, 'RSA-OAEP');

    const prfTwo = crypto.getRandomValues(new Uint8Array(32));
    const credentialTwo = randomCredentialId();
    const secondEnvelope = await gallery.wrapRootKeyForPasskey(
        unlocked.rootKey,
        prfTwo,
        accountSalt,
        credentialTwo
    );
    const unlockedOnSecondDevice = await gallery.unlockIdentity(
        identity.privateKeyEnvelope,
        secondEnvelope,
        prfTwo,
        credentialTwo
    );
    assert.equal(unlockedOnSecondDevice.privateKey.algorithm.name, 'RSA-OAEP');

    await assert.rejects(
        gallery.unlockIdentity(identity.privateKeyEnvelope, secondEnvelope, prfOne, credentialTwo),
        /Unable to unlock/
    );

    gallery.clearSecret(identity.rootKey);
    gallery.clearSecret(unlocked.rootKey);
    gallery.clearSecret(recovered.rootKey);
    gallery.clearSecret(unlockedOnSecondDevice.rootKey);
    gallery.clearSecret(recoveryKey);
    gallery.clearSecret(prfOne);
    gallery.clearSecret(prfTwo);
});

test('photo objects decrypt only with the correct key and authenticated context', async () => {
    const accountSalt = gallery.createAccountSalt();
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const credentialId = randomCredentialId();
    const identity = await gallery.createIdentity(prf, accountSalt, credentialId);
    const unlocked = await gallery.unlockIdentity(
        identity.privateKeyEnvelope,
        identity.credentialEnvelope,
        prf,
        credentialId
    );

    const photoId = 'a'.repeat(32);
    const plaintext = new TextEncoder().encode('private photo bytes');
    const encrypted = await gallery.encryptObject(plaintext, identity.publicKey, photoId, 'original');
    const decrypted = await gallery.decryptObject(encrypted.ciphertext, encrypted.envelope, unlocked.privateKey, photoId, 'original');
    assert.deepEqual(new Uint8Array(decrypted), plaintext);

    const tampered = encrypted.ciphertext.slice();
    tampered[0] ^= 1;
    await assert.rejects(
        gallery.decryptObject(tampered, encrypted.envelope, unlocked.privateKey, photoId, 'original'),
        /authentication failed/
    );
    await assert.rejects(
        gallery.decryptObject(encrypted.ciphertext, encrypted.envelope, unlocked.privateKey, photoId, 'thumbnail'),
        /metadata does not match/
    );

    await assert.rejects(
        gallery.decryptObject(encrypted.ciphertext, encrypted.envelope, unlocked.privateKey, 'b'.repeat(32), 'original'),
        /metadata does not match/
    );
    await assert.rejects(
        gallery.decryptObject(encrypted.ciphertext, { ...encrypted.envelope, nonce: 'AA' }, unlocked.privateKey, photoId, 'original'),
        /Invalid Gallery object envelope/
    );
    const changedWrappedKey = {
        ...encrypted.envelope,
        wrappedDek: (encrypted.envelope.wrappedDek[0] === 'A' ? 'B' : 'A') + encrypted.envelope.wrappedDek.slice(1)
    };
    await assert.rejects(
        gallery.decryptObject(encrypted.ciphertext, changedWrappedKey, unlocked.privateKey, photoId, 'original'),
        /Unable to unlock this Gallery object/
    );
    await assert.rejects(
        gallery.encryptObject(plaintext, identity.publicKey, 'not-an-opaque-id', 'original'),
        /Invalid Gallery object identifier/
    );
    await assert.rejects(
        gallery.encryptObject(plaintext, identity.publicKey, photoId, 'unknown-role'),
        /Invalid Gallery object role/
    );

    gallery.clearSecret(identity.rootKey);
    gallery.clearSecret(unlocked.rootKey);
    gallery.clearSecret(prf);
});
