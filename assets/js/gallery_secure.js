(function (root) {
    'use strict';

    const cryptoApi = function () {
        if (!root.SentryIQGalleryCrypto) throw new Error('Gallery cryptography is unavailable.');
        return root.SentryIQGalleryCrypto;
    };

    let unlockedPrivateKey = null;
    let unlockedRootKey = null;
    let unlockedPublicKey = null;
    let pendingSetup = null;
    let recoveryIdentity = null;

    function csrfToken() {
        const node = document.querySelector('meta[name="csrf-token"]');
        if (!node || !node.content) throw new Error('Security token is unavailable. Reload the Gallery and try again.');
        return node.content;
    }

    async function readJson(response) {
        let payload;
        try { payload = await response.json(); }
        catch (_) { throw new Error('The Gallery security endpoint returned an invalid response.'); }
        if (!response.ok || !payload || payload.status !== 'ok') {
            throw new Error(payload && payload.message ? payload.message : 'The Gallery security request failed.');
        }
        return payload;
    }

    async function requestOptions() {
        const response = await fetch('gallery_passkey.php?action=options', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });
        return readJson(response);
    }

    async function verifyPasskey(optionsPayload) {
        if (!root.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
            throw new Error('This browser does not support the passkey operation required by secure Gallery.');
        }
        const publicKey = optionsPayload.options;
        publicKey.challenge = cryptoApi().fromBase64Url(publicKey.challenge).buffer;
        if (publicKey.allowCredentials) {
            publicKey.allowCredentials = publicKey.allowCredentials.map(function (item) {
                return { type: 'public-key', id: cryptoApi().fromBase64Url(item.id).buffer };
            });
        }
        const prfInput = cryptoApi().fromBase64Url(publicKey.extensions.prf.eval.first);
        publicKey.extensions.prf.eval.first = prfInput.buffer;
        let prfOutput = null;
        try {
            const credential = await navigator.credentials.get({ publicKey: publicKey });
            if (!credential) throw new Error('Passkey authentication was cancelled.');
            const extensionResults = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
            const prfResult = extensionResults && extensionResults.prf && extensionResults.prf.results
                ? extensionResults.prf.results.first
                : null;
            if (!prfResult) throw new Error('This passkey does not support the PRF extension required by secure Gallery.');
            prfOutput = new Uint8Array(prfResult);
            if (prfOutput.byteLength !== 32) throw new Error('The passkey returned an invalid Gallery key result.');

            const response = credential.response;
            const body = {
                action: 'verify',
                csrf_token: csrfToken(),
                rawId: cryptoApi().toBase64Url(credential.rawId),
                clientDataJSON: cryptoApi().toBase64Url(response.clientDataJSON),
                authenticatorData: cryptoApi().toBase64Url(response.authenticatorData),
                signature: cryptoApi().toBase64Url(response.signature)
            };
            const verifiedResponse = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify(body)
            });
            const verified = await readJson(verifiedResponse);
            return {
                credentialId: verified.credentialId,
                identity: verified.identity,
                prfOutput: prfOutput,
                accountSalt: prfInput
            };
        } catch (error) {
            if (prfOutput) cryptoApi().clearSecret(prfOutput);
            cryptoApi().clearSecret(prfInput);
            throw error;
        }
    }
    async function verifyNewPasskey() {
        const options = await requestOptions();
        return verifyPasskey(options);
    }

    async function unlock() {
        lock();
        const verified = await verifyNewPasskey();
        if (!verified.identity) {
            pendingSetup = { credentialId: verified.credentialId, prfOutput: verified.prfOutput, accountSalt: verified.accountSalt };
            return { status: 'uninitialized' };
        }
        recoveryIdentity = verified.identity;
        try {
            if (!verified.identity.credentialEnvelope) {
                throw new Error('This passkey is not enrolled for Gallery. Unlock with your recovery code or another enrolled passkey.');
            }
            const unlocked = await cryptoApi().unlockIdentity(
                verified.identity.privateKeyEnvelope,
                verified.identity.credentialEnvelope,
                verified.prfOutput,
                verified.credentialId
            );
            unlockedPrivateKey = unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = verified.identity.publicKey;
            return { status: 'unlocked' };
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function prepareIdentity() {
        if (!pendingSetup) {
            const verified = await verifyNewPasskey();
            if (verified.identity) {
                cryptoApi().clearSecret(verified.prfOutput);
                cryptoApi().clearSecret(verified.accountSalt);
                throw new Error('Secure Gallery is already initialized.');
            }
            pendingSetup = { credentialId: verified.credentialId, prfOutput: verified.prfOutput, accountSalt: verified.accountSalt };
        }
        if (pendingSetup.identity) return { recoveryCode: pendingSetup.recoveryCode };
        const identity = await cryptoApi().createIdentity(
            pendingSetup.prfOutput,
            pendingSetup.accountSalt,
            pendingSetup.credentialId
        );
        const recoveryKey = await cryptoApi().createRecoveryKey();
        const recoverySalt = cryptoApi().createAccountSalt();
        const recoveryEnvelope = await cryptoApi().wrapRootKeyForRecovery(identity.rootKey, recoveryKey, recoverySalt);
        pendingSetup.identity = identity;
        pendingSetup.recoveryKey = recoveryKey;
        pendingSetup.recoverySalt = recoverySalt;
        pendingSetup.recoveryEnvelope = recoveryEnvelope;
        pendingSetup.recoveryCode = cryptoApi().toBase64Url(recoveryKey);
        return { recoveryCode: pendingSetup.recoveryCode };
    }

    async function completeIdentitySetup() {
        if (!pendingSetup || !pendingSetup.identity || !pendingSetup.recoveryEnvelope) {
            throw new Error('Prepare Gallery encryption and save the recovery code before continuing.');
        }
        const identity = pendingSetup.identity;
        const response = await fetch('gallery_passkey.php', {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({
                action: 'initialize',
                csrf_token: csrfToken(),
                credentialId: pendingSetup.credentialId,
                publicKey: identity.publicKey,
                privateKeyEnvelope: identity.privateKeyEnvelope,
                credentialEnvelope: identity.credentialEnvelope,
                recoveryEnvelope: pendingSetup.recoveryEnvelope
            })
        });
        await readJson(response);
        const activeKeys = await cryptoApi().unlockIdentity(
            identity.privateKeyEnvelope,
            identity.credentialEnvelope,
            pendingSetup.prfOutput,
            pendingSetup.credentialId
        );
        unlockedPrivateKey = activeKeys.privateKey;
        cryptoApi().clearSecret(activeKeys.rootKey);
        unlockedRootKey = identity.rootKey;
        unlockedPublicKey = identity.publicKey;
        cryptoApi().clearSecret(pendingSetup.prfOutput);
        cryptoApi().clearSecret(pendingSetup.accountSalt);
        cryptoApi().clearSecret(pendingSetup.recoveryKey);
        pendingSetup = null;
        recoveryIdentity = null;
        return { status: 'initialized' };
    }

    async function unlockWithRecovery(recoveryCode) {
        if (!recoveryIdentity || !recoveryIdentity.recoveryEnvelope) {
            throw new Error('Verify a registered passkey first, then enter the Gallery recovery code.');
        }
        const recoveryKey = cryptoApi().fromBase64Url(String(recoveryCode || '').trim());
        if (recoveryKey.byteLength !== 32) {
            recoveryKey.fill(0);
            throw new Error('The Gallery recovery code is invalid.');
        }
        try {
            const unlocked = await cryptoApi().unlockIdentityWithRecovery(
                recoveryIdentity.privateKeyEnvelope,
                recoveryIdentity.recoveryEnvelope,
                recoveryKey
            );
            unlockedPrivateKey = unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = recoveryIdentity.publicKey;
            return { status: 'unlocked' };
        } finally {
            cryptoApi().clearSecret(recoveryKey);
        }
    }

    async function enrollCurrentPasskey() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before adding another passkey.');
        const verified = await verifyNewPasskey();
        try {
            if (!verified.identity) throw new Error('Secure Gallery is not initialized on this installation.');
            if (verified.identity.credentialEnvelope) {
                throw new Error('This passkey already has a Gallery key envelope.');
            }
            const credentialEnvelope = await cryptoApi().wrapRootKeyForPasskey(
                unlockedRootKey,
                verified.prfOutput,
                verified.accountSalt,
                verified.credentialId
            );
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({
                    action: 'add_credential',
                    csrf_token: csrfToken(),
                    credentialId: verified.credentialId,
                    credentialEnvelope: credentialEnvelope
                })
            });
            await readJson(response);
            return { status: 'enrolled' };
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    function lock() {
        cryptoApi().clearSecret(unlockedRootKey);
        if (pendingSetup) {
            cryptoApi().clearSecret(pendingSetup.prfOutput);
            cryptoApi().clearSecret(pendingSetup.accountSalt);
            cryptoApi().clearSecret(pendingSetup.recoveryKey);
            cryptoApi().clearSecret(pendingSetup.recoverySalt);
            if (pendingSetup.identity) cryptoApi().clearSecret(pendingSetup.identity.rootKey);
        }
        unlockedPrivateKey = null;
        unlockedRootKey = null;
        unlockedPublicKey = null;
        pendingSetup = null;
        recoveryIdentity = null;
    }

    root.SentryIQSecureGallery = Object.freeze({
        unlock: unlock,
        prepareIdentity: prepareIdentity,
        completeIdentitySetup: completeIdentitySetup,
        unlockWithRecovery: unlockWithRecovery,
        enrollCurrentPasskey: enrollCurrentPasskey,
        lock: lock,
        isUnlocked: function () { return unlockedPrivateKey !== null && unlockedRootKey !== null; },
        getPublicKey: function () { if (!unlockedPublicKey) throw new Error('Secure Gallery is locked.'); return unlockedPublicKey; },
        encryptObject: function (data, photoId, role) {
            if (!unlockedPublicKey) throw new Error('Secure Gallery is locked.');
            return cryptoApi().encryptObject(data, unlockedPublicKey, photoId, role);
        },
        decryptObject: function (data, envelope, photoId, role) {
            if (!unlockedPrivateKey) throw new Error('Secure Gallery is locked.');
            return cryptoApi().decryptObject(data, envelope, unlockedPrivateKey, photoId, role);
        }
    });
}(typeof window !== 'undefined' ? window : self));
