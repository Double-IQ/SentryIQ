(function (root) {
    'use strict';

    const cryptoApi = function () {
        if (!root.SentryIQGalleryCrypto) throw new Error('Gallery cryptography is unavailable.');
        return root.SentryIQGalleryCrypto;
    };

    let unlockedPrivateKey = null;
    let unlockedRootKey = null;
    let unlockedPublicKey = null;
    let unlockedPrivateKeys = null;
    let unlockedPublicKeys = null;
    let activeKeyId = null;
    let legacyKeyId = null;
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
            const unlocked = verified.identity.keyring
                ? await cryptoApi().unlockKeyringIdentity(
                    verified.identity.keyring,
                    verified.identity.credentialEnvelope,
                    verified.prfOutput,
                    verified.credentialId
                )
                : await cryptoApi().unlockIdentity(
                    verified.identity.privateKeyEnvelope,
                    verified.identity.credentialEnvelope,
                    verified.prfOutput,
                    verified.credentialId
                );
            unlockedPrivateKeys = unlocked.privateKeys || null;
            unlockedPublicKeys = unlocked.publicKeys || null;
            activeKeyId = unlocked.activeKeyId || null;
            legacyKeyId = unlocked.legacyKeyId || null;
            unlockedPrivateKey = activeKeyId && unlockedPrivateKeys ? unlockedPrivateKeys[activeKeyId] : unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = activeKeyId && unlockedPublicKeys ? unlockedPublicKeys[activeKeyId] : verified.identity.publicKey;
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
            const response = await fetch('gallery_passkey.php?action=recovery-envelope', {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json' }
            });
            const payload = await readJson(response);
            recoveryIdentity = payload.identity;
        }
        if (!recoveryIdentity || !recoveryIdentity.recoveryEnvelope) {
            throw new Error('Gallery recovery is not available. Initialize secure Gallery first.');
        }
        const recoveryKey = cryptoApi().fromBase64Url(String(recoveryCode || '').trim());
        if (recoveryKey.byteLength !== 32) {
            recoveryKey.fill(0);
            throw new Error('The Gallery recovery code is invalid.');
        }
        try {
            const unlocked = recoveryIdentity.keyring
                ? await cryptoApi().unlockKeyringIdentityWithRecovery(
                    recoveryIdentity.keyring,
                    recoveryIdentity.recoveryEnvelope,
                    recoveryKey
                )
                : await cryptoApi().unlockIdentityWithRecovery(
                    recoveryIdentity.privateKeyEnvelope,
                    recoveryIdentity.recoveryEnvelope,
                    recoveryKey
                );
            unlockedPrivateKeys = unlocked.privateKeys || null;
            unlockedPublicKeys = unlocked.publicKeys || null;
            activeKeyId = unlocked.activeKeyId || null;
            legacyKeyId = unlocked.legacyKeyId || null;
            unlockedPrivateKey = activeKeyId && unlockedPrivateKeys ? unlockedPrivateKeys[activeKeyId] : unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = activeKeyId && unlockedPublicKeys ? unlockedPublicKeys[activeKeyId] : recoveryIdentity.publicKey;
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

    async function addWrappingKey() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before adding an encryption key.');
        const verified = await verifyNewPasskey();
        let keyIdBytes = null;
        try {
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('Confirm with a passkey already enrolled for Gallery.');
            }
            keyIdBytes = cryptoApi().createAccountSalt();
            const keyId = 'gk_' + cryptoApi().toBase64Url(keyIdBytes.subarray(0, 16));
            const wrappingKey = await cryptoApi().createAdditionalWrappingKey(unlockedRootKey);
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({
                    action: 'add_wrapping_key',
                    csrf_token: csrfToken(),
                    keyId: keyId,
                    publicKey: wrappingKey.publicKey,
                    privateKeyEnvelope: wrappingKey.privateKeyEnvelope
                })
            });
            const saved = await readJson(response);
            if (!saved.keyring || !verified.identity.credentialEnvelope) {
                throw new Error('The updated Gallery keyring could not be loaded.');
            }
            const refreshed = await cryptoApi().unlockKeyringIdentity(
                saved.keyring,
                verified.identity.credentialEnvelope,
                verified.prfOutput,
                verified.credentialId
            );
            unlockedPrivateKeys = refreshed.privateKeys;
            unlockedPublicKeys = refreshed.publicKeys;
            activeKeyId = refreshed.activeKeyId;
            legacyKeyId = refreshed.legacyKeyId || null;
            unlockedPrivateKey = unlockedPrivateKeys[activeKeyId];
            unlockedPublicKey = unlockedPublicKeys[activeKeyId];
            cryptoApi().clearSecret(refreshed.rootKey);
            return { status: 'added', keyId: keyId };
        } finally {
            if (keyIdBytes) cryptoApi().clearSecret(keyIdBytes);
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function ensureKeyAvailable(keyId) {
        if (!unlockedRootKey) throw new Error('Secure Gallery is locked.');
        if (unlockedPublicKeys && unlockedPrivateKeys
            && Object.prototype.hasOwnProperty.call(unlockedPublicKeys, keyId)
            && Object.prototype.hasOwnProperty.call(unlockedPrivateKeys, keyId)) return true;

        const response = await fetch('gallery_passkey.php?action=keyring', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });
        const payload = await readJson(response);
        if (!payload.keyring) throw new Error('The current Gallery keyring could not be refreshed.');
        const refreshed = await cryptoApi().unlockKeyringWithRoot(payload.keyring, unlockedRootKey);
        if (!Object.prototype.hasOwnProperty.call(refreshed.publicKeys, keyId)
            || !Object.prototype.hasOwnProperty.call(refreshed.privateKeys, keyId)) {
            throw new Error('The upload reservation key is no longer available in this Gallery keyring.');
        }
        unlockedPrivateKeys = refreshed.privateKeys;
        unlockedPublicKeys = refreshed.publicKeys;
        activeKeyId = refreshed.activeKeyId;
        legacyKeyId = refreshed.legacyKeyId || null;
        unlockedPrivateKey = unlockedPrivateKeys[activeKeyId];
        unlockedPublicKey = unlockedPublicKeys[activeKeyId];
        return true;
    }

    function getKeyInfo() {
        if (!unlockedPrivateKey) throw new Error('Secure Gallery is locked.');
        return {
            activeKeyId: activeKeyId,
            legacyKeyId: legacyKeyId,
            keyIds: unlockedPublicKeys ? Object.keys(unlockedPublicKeys) : []
        };
    }

    async function getRotationStatus() {
        const response = await fetch('gallery_passkey.php?action=rotation-status', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });
        return readJson(response);
    }

    async function startRotation(targetKeyId) {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before rotating encryption keys.');
        if (!unlockedPublicKeys || !Object.prototype.hasOwnProperty.call(unlockedPublicKeys, targetKeyId)) {
            throw new Error('The target Gallery encryption key is not unlocked in this browser.');
        }
        const verified = await verifyNewPasskey();
        try {
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('Confirm with a passkey already enrolled for Gallery.');
            }
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ action: 'begin_rotation', csrf_token: csrfToken(), targetKeyId: targetKeyId })
            });
            const payload = await readJson(response);
            activeKeyId = payload.rotation.to_key_id;
            unlockedPrivateKey = unlockedPrivateKeys[activeKeyId];
            unlockedPublicKey = unlockedPublicKeys[activeKeyId];
            return payload.rotation;
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function abortRotation() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before aborting key rotation.');
        const verified = await verifyNewPasskey();
        try {
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('Confirm with a passkey already enrolled for Gallery.');
            }
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ action: 'abort_rotation', csrf_token: csrfToken() })
            });
            const payload = await readJson(response);
            activeKeyId = payload.rotation.from_key_id;
            unlockedPrivateKey = unlockedPrivateKeys && unlockedPrivateKeys[activeKeyId] ? unlockedPrivateKeys[activeKeyId] : unlockedPrivateKey;
            unlockedPublicKey = unlockedPublicKeys && unlockedPublicKeys[activeKeyId] ? unlockedPublicKeys[activeKeyId] : unlockedPublicKey;
            return payload.rotation;
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function finalizeRotation() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before finalizing key rotation.');
        const verified = await verifyNewPasskey();
        try {
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('Confirm with a passkey already enrolled for Gallery.');
            }
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ action: 'finalize_rotation', csrf_token: csrfToken() })
            });
            const payload = await readJson(response);
            if (payload.rotation.status === 'completed') {
                const retiredKeyId = payload.rotation.from_key_id;
                if (unlockedPrivateKeys) delete unlockedPrivateKeys[retiredKeyId];
                if (unlockedPublicKeys) delete unlockedPublicKeys[retiredKeyId];
                if (legacyKeyId === retiredKeyId) legacyKeyId = null;
            }
            return payload.rotation;
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    function rewrapObjectEnvelope(envelope, photoId, role, targetKeyId) {
        if (!unlockedPrivateKey || !unlockedPublicKey) throw new Error('Secure Gallery is locked.');
        if (!unlockedPublicKeys || !Object.prototype.hasOwnProperty.call(unlockedPublicKeys, targetKeyId)) {
            throw new Error('The target Gallery encryption key is not unlocked in this browser.');
        }
        return cryptoApi().rewrapObjectEnvelope(
            envelope,
            unlockedPrivateKeys || unlockedPrivateKey,
            unlockedPublicKeys[targetKeyId],
            targetKeyId,
            photoId,
            role,
            legacyKeyId
        );
    }

    async function removeEnrolledDevice(targetCredentialId) {
        if (!targetCredentialId) throw new Error('Select a Gallery device to remove.');
        const verified = await verifyNewPasskey();
        try {
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('The confirmed passkey is not enrolled for Gallery management.');
            }
            if (verified.credentialId === targetCredentialId) {
                throw new Error('Confirm a different enrolled passkey to remove this device.');
            }
            const response = await fetch('gallery_passkey.php', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({
                    action: 'remove_credential',
                    csrf_token: csrfToken(),
                    credentialId: targetCredentialId
                })
            });
            await readJson(response);
            return { status: 'removed' };
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
        unlockedPrivateKeys = null;
        unlockedPublicKeys = null;
        activeKeyId = null;
        legacyKeyId = null;
        pendingSetup = null;
        recoveryIdentity = null;
    }

    root.SentryIQSecureGallery = Object.freeze({
        unlock: unlock,
        prepareIdentity: prepareIdentity,
        completeIdentitySetup: completeIdentitySetup,
        unlockWithRecovery: unlockWithRecovery,
        enrollCurrentPasskey: enrollCurrentPasskey,
        addWrappingKey: addWrappingKey,
        rewrapObjectEnvelope: rewrapObjectEnvelope,
        getKeyInfo: getKeyInfo,
        ensureKeyAvailable: ensureKeyAvailable,
        getRotationStatus: getRotationStatus,
        startRotation: startRotation,
        abortRotation: abortRotation,
        finalizeRotation: finalizeRotation,
        removeEnrolledDevice: removeEnrolledDevice,
        lock: lock,
        isUnlocked: function () { return unlockedPrivateKey !== null && unlockedRootKey !== null; },
        getPublicKey: function () { if (!unlockedPublicKey) throw new Error('Secure Gallery is locked.'); return unlockedPublicKey; },
        encryptObject: function (data, photoId, role, keyId) {
            if (!unlockedPublicKey) throw new Error('Secure Gallery is locked.');
            let publicKey = unlockedPublicKey;
            if (keyId) {
                if (!unlockedPublicKeys || !Object.prototype.hasOwnProperty.call(unlockedPublicKeys, keyId)) {
                    throw new Error('The reservation encryption key has not been loaded into this browser.');
                }
                publicKey = unlockedPublicKeys[keyId];
            }
            return cryptoApi().encryptObject(data, publicKey, photoId, role, keyId);
        },
        decryptObject: function (data, envelope, photoId, role) {
            if (!unlockedPrivateKey) throw new Error('Secure Gallery is locked.');
            const privateKeys = unlockedPrivateKeys || unlockedPrivateKey;
            return cryptoApi().decryptObject(data, envelope, privateKeys, photoId, role, legacyKeyId);
        }
    });
}(typeof window !== 'undefined' ? window : self));
