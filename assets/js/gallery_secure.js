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
    let sessionGeneration = 0;
    const transientSecrets = new Set();

    function trackSecret(value) {
        if (value instanceof Uint8Array) transientSecrets.add(value);
        return value;
    }

    function clearSecret(value) {
        if (!(value instanceof Uint8Array)) return;
        try { cryptoApi().clearSecret(value); } catch (_) {}
        transientSecrets.delete(value);
    }

    function assertSessionGeneration(generation, result) {
        if (generation !== sessionGeneration) {
            if (result && result.rootKey) clearSecret(result.rootKey);
            if (result && result.privateKeys) {
                Object.keys(result.privateKeys).forEach(function (keyId) { delete result.privateKeys[keyId]; });
            }
            if (result && Object.prototype.hasOwnProperty.call(result, 'privateKey')) result.privateKey = null;
            throw new Error('Secure Gallery was locked while this operation was in progress.');
        }
    }

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
        const generation = sessionGeneration;
        const publicKey = optionsPayload.options;
        publicKey.challenge = cryptoApi().fromBase64Url(publicKey.challenge).buffer;
        if (publicKey.allowCredentials) {
            publicKey.allowCredentials = publicKey.allowCredentials.map(function (item) {
                return { type: 'public-key', id: cryptoApi().fromBase64Url(item.id).buffer };
            });
        }
        const prfInput = trackSecret(cryptoApi().fromBase64Url(publicKey.extensions.prf.eval.first));
        publicKey.extensions.prf.eval.first = prfInput.buffer;
        let prfOutput = null;
        try {
            const credential = await navigator.credentials.get({ publicKey: publicKey });
            assertSessionGeneration(generation);
            if (!credential) throw new Error('Passkey authentication was cancelled.');
            const extensionResults = credential.getClientExtensionResults ? credential.getClientExtensionResults() : {};
            const prfResult = extensionResults && extensionResults.prf && extensionResults.prf.results
                ? extensionResults.prf.results.first
                : null;
            if (!prfResult) throw new Error('This passkey does not support the PRF extension required by secure Gallery.');
            prfOutput = trackSecret(new Uint8Array(prfResult));
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
            assertSessionGeneration(generation);
            return {
                credentialId: verified.credentialId,
                identity: verified.identity,
                prfOutput: prfOutput,
                accountSalt: prfInput
            };
        } catch (error) {
            if (prfOutput) clearSecret(prfOutput);
            clearSecret(prfInput);
            throw error;
        }
    }
    async function verifyNewPasskey() {
        const options = await requestOptions();
        return verifyPasskey(options);
    }

    async function unlock() {
        lock();
        const generation = sessionGeneration;
        const verified = await verifyNewPasskey();
        let retainPendingSetup = false;
        try {
            assertSessionGeneration(generation);
            if (!verified.identity) {
                pendingSetup = {
                    credentialId: verified.credentialId,
                    prfOutput: verified.prfOutput,
                    accountSalt: verified.accountSalt
                };
                retainPendingSetup = true;
                return { status: 'uninitialized' };
            }
            recoveryIdentity = verified.identity;
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
            trackSecret(unlocked.rootKey);
            assertSessionGeneration(generation, unlocked);
            unlockedPrivateKeys = unlocked.privateKeys || null;
            unlockedPublicKeys = unlocked.publicKeys || null;
            activeKeyId = unlocked.activeKeyId || null;
            legacyKeyId = unlocked.legacyKeyId || null;
            unlockedPrivateKey = activeKeyId && unlockedPrivateKeys ? unlockedPrivateKeys[activeKeyId] : unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = activeKeyId && unlockedPublicKeys ? unlockedPublicKeys[activeKeyId] : verified.identity.publicKey;
            return { status: 'unlocked' };
        } finally {
            if (!retainPendingSetup) {
                clearSecret(verified.prfOutput);
                clearSecret(verified.accountSalt);
            }
        }
    }

    async function prepareIdentity() {
        const generation = sessionGeneration;
        if (!pendingSetup) {
            const verified = await verifyNewPasskey();
            let retained = false;
            try {
                assertSessionGeneration(generation);
                if (verified.identity) throw new Error('Secure Gallery is already initialized.');
                pendingSetup = {
                    credentialId: verified.credentialId,
                    prfOutput: verified.prfOutput,
                    accountSalt: verified.accountSalt
                };
                retained = true;
            } finally {
                if (!retained) {
                    cryptoApi().clearSecret(verified.prfOutput);
                    cryptoApi().clearSecret(verified.accountSalt);
                }
            }
        }
        assertSessionGeneration(generation);
        if (pendingSetup.identity) return { recoveryCode: pendingSetup.recoveryCode };

        let identity = null;
        let recoveryKey = null;
        let recoverySalt = null;
        let retainedIdentity = false;
        try {
            identity = await cryptoApi().createIdentity(
                pendingSetup.prfOutput,
                pendingSetup.accountSalt,
                pendingSetup.credentialId
            );
            trackSecret(identity.rootKey);
            assertSessionGeneration(generation, identity);
            recoveryKey = trackSecret(await cryptoApi().createRecoveryKey());
            assertSessionGeneration(generation);
            recoverySalt = trackSecret(cryptoApi().createAccountSalt());
            const recoveryEnvelope = await cryptoApi().wrapRootKeyForRecovery(identity.rootKey, recoveryKey, recoverySalt);
            assertSessionGeneration(generation);
            if (!pendingSetup) throw new Error('Secure Gallery was locked during setup.');
            pendingSetup.identity = identity;
            pendingSetup.recoveryKey = recoveryKey;
            pendingSetup.recoverySalt = recoverySalt;
            pendingSetup.recoveryEnvelope = recoveryEnvelope;
            pendingSetup.recoveryCode = cryptoApi().toBase64Url(recoveryKey);
            retainedIdentity = true;
            return { recoveryCode: pendingSetup.recoveryCode };
        } finally {
            if (!retainedIdentity) {
                if (identity) clearSecret(identity.rootKey);
                if (recoveryKey) clearSecret(recoveryKey);
                if (recoverySalt) clearSecret(recoverySalt);
            }
        }
    }

    async function completeIdentitySetup() {
        if (!pendingSetup || !pendingSetup.identity || !pendingSetup.recoveryEnvelope) {
            throw new Error('Prepare Gallery encryption and save the recovery code before continuing.');
        }
        const generation = sessionGeneration;
        const setup = pendingSetup;
        const identity = setup.identity;
        const response = await fetch('gallery_passkey.php', {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({
                action: 'initialize',
                csrf_token: csrfToken(),
                credentialId: setup.credentialId,
                publicKey: identity.publicKey,
                privateKeyEnvelope: identity.privateKeyEnvelope,
                credentialEnvelope: identity.credentialEnvelope,
                recoveryEnvelope: setup.recoveryEnvelope
            })
        });
        await readJson(response);
        assertSessionGeneration(generation);
        const activeKeys = await cryptoApi().unlockIdentity(
            identity.privateKeyEnvelope,
            identity.credentialEnvelope,
            setup.prfOutput,
            setup.credentialId
        );
        trackSecret(activeKeys.rootKey);
        assertSessionGeneration(generation, activeKeys);
        unlockedPrivateKey = activeKeys.privateKey;
        clearSecret(activeKeys.rootKey);
        unlockedRootKey = identity.rootKey;
        unlockedPublicKey = identity.publicKey;
        clearSecret(setup.prfOutput);
        clearSecret(setup.accountSalt);
        clearSecret(setup.recoveryKey);
        pendingSetup = null;
        recoveryIdentity = null;
        return { status: 'initialized' };
    }

    async function unlockWithRecovery(recoveryCode) {
        const generation = sessionGeneration;
        let recoveryKey = null;
        try {
            if (!recoveryIdentity || !recoveryIdentity.recoveryEnvelope) {
                const response = await fetch('gallery_passkey.php?action=recovery-envelope', {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: { Accept: 'application/json' }
                });
                const payload = await readJson(response);
                assertSessionGeneration(generation);
                recoveryIdentity = payload.identity;
            }
            assertSessionGeneration(generation);
            if (!recoveryIdentity || !recoveryIdentity.recoveryEnvelope) {
                throw new Error('Gallery recovery is not available. Initialize secure Gallery first.');
            }
            recoveryKey = trackSecret(cryptoApi().fromBase64Url(String(recoveryCode || '').trim()));
            if (recoveryKey.byteLength !== 32) {
                recoveryKey.fill(0);
                throw new Error('The Gallery recovery code is invalid.');
            }
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
            trackSecret(unlocked.rootKey);
            assertSessionGeneration(generation, unlocked);
            unlockedPrivateKeys = unlocked.privateKeys || null;
            unlockedPublicKeys = unlocked.publicKeys || null;
            activeKeyId = unlocked.activeKeyId || null;
            legacyKeyId = unlocked.legacyKeyId || null;
            unlockedPrivateKey = activeKeyId && unlockedPrivateKeys ? unlockedPrivateKeys[activeKeyId] : unlocked.privateKey;
            unlockedRootKey = unlocked.rootKey;
            unlockedPublicKey = activeKeyId && unlockedPublicKeys ? unlockedPublicKeys[activeKeyId] : recoveryIdentity.publicKey;
            return { status: 'unlocked' };
        } finally {
            if (recoveryKey) cryptoApi().clearSecret(recoveryKey);
        }
    }

    async function enrollCurrentPasskey() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before adding another passkey.');
        const generation = sessionGeneration;
        const rootKey = unlockedRootKey;
        const verified = await verifyNewPasskey();
        try {
            assertSessionGeneration(generation);
            if (!verified.identity) throw new Error('Secure Gallery is not initialized on this installation.');
            if (verified.identity.credentialEnvelope) {
                throw new Error('This passkey already has a Gallery key envelope.');
            }
            const credentialEnvelope = await cryptoApi().wrapRootKeyForPasskey(
                rootKey,
                verified.prfOutput,
                verified.accountSalt,
                verified.credentialId
            );
            assertSessionGeneration(generation);
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
            assertSessionGeneration(generation);
            return { status: 'enrolled' };
        } finally {
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function addWrappingKey() {
        if (!unlockedRootKey) throw new Error('Unlock secure Gallery before adding an encryption key.');
        const generation = sessionGeneration;
        const rootKey = unlockedRootKey;
        const verified = await verifyNewPasskey();
        let keyIdBytes = null;
        let refreshed = null;
        try {
            assertSessionGeneration(generation);
            if (!verified.identity || !verified.identity.credentialEnvelope) {
                throw new Error('Confirm with a passkey already enrolled for Gallery.');
            }
            keyIdBytes = cryptoApi().createAccountSalt();
            const keyId = 'gk_' + cryptoApi().toBase64Url(keyIdBytes.subarray(0, 16));
            const wrappingKey = await cryptoApi().createAdditionalWrappingKey(rootKey);
            assertSessionGeneration(generation);
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
            assertSessionGeneration(generation);
            if (!saved.keyring || !verified.identity.credentialEnvelope) {
                throw new Error('The updated Gallery keyring could not be loaded.');
            }
            refreshed = await cryptoApi().unlockKeyringIdentity(
                saved.keyring,
                verified.identity.credentialEnvelope,
                verified.prfOutput,
                verified.credentialId
            );
            trackSecret(refreshed.rootKey);
            assertSessionGeneration(generation, refreshed);
            unlockedPrivateKeys = refreshed.privateKeys;
            unlockedPublicKeys = refreshed.publicKeys;
            activeKeyId = refreshed.activeKeyId;
            legacyKeyId = refreshed.legacyKeyId || null;
            unlockedPrivateKey = unlockedPrivateKeys[activeKeyId];
            unlockedPublicKey = unlockedPublicKeys[activeKeyId];
            clearSecret(refreshed.rootKey);
            refreshed = null;
            return { status: 'added', keyId: keyId };
        } finally {
            if (refreshed) cryptoApi().clearSecret(refreshed.rootKey);
            if (keyIdBytes) clearSecret(keyIdBytes);
            cryptoApi().clearSecret(verified.prfOutput);
            cryptoApi().clearSecret(verified.accountSalt);
        }
    }

    async function ensureKeyAvailable(keyId) {
        if (!unlockedRootKey) throw new Error('Secure Gallery is locked.');
        const generation = sessionGeneration;
        const rootKey = unlockedRootKey;
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
        assertSessionGeneration(generation);
        if (!payload.keyring) throw new Error('The current Gallery keyring could not be refreshed.');
        const refreshed = await cryptoApi().unlockKeyringWithRoot(payload.keyring, rootKey);
        try {
            assertSessionGeneration(generation, refreshed);
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
        } finally {
            cryptoApi().clearSecret(refreshed.rootKey);
        }
    }

    async function syncKeyringState(serverActiveKeyId, serverKeyIds, serverLegacyKeyId) {
        if (!unlockedRootKey || !serverActiveKeyId) return false;
        const generation = sessionGeneration;
        const rootKey = unlockedRootKey;
        const ids = Array.isArray(serverKeyIds) ? serverKeyIds : [];
        const needsRefresh = !unlockedPrivateKeys || !unlockedPublicKeys || ids.some(function (keyId) {
            return !Object.prototype.hasOwnProperty.call(unlockedPrivateKeys, keyId)
                || !Object.prototype.hasOwnProperty.call(unlockedPublicKeys, keyId);
        });
        if (needsRefresh) {
            const response = await fetch('gallery_passkey.php?action=keyring', {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json' }
            });
            const payload = await readJson(response);
            assertSessionGeneration(generation);
            if (!payload.keyring) throw new Error('The current Gallery keyring could not be refreshed.');
            const refreshed = await cryptoApi().unlockKeyringWithRoot(payload.keyring, rootKey);
            try {
                assertSessionGeneration(generation, refreshed);
                unlockedPrivateKeys = refreshed.privateKeys;
                unlockedPublicKeys = refreshed.publicKeys;
            } finally {
                cryptoApi().clearSecret(refreshed.rootKey);
            }
        }
        assertSessionGeneration(generation);
        for (const keyId of Object.keys(unlockedPrivateKeys || {})) {
            if (!ids.includes(keyId)) delete unlockedPrivateKeys[keyId];
        }
        for (const keyId of Object.keys(unlockedPublicKeys || {})) {
            if (!ids.includes(keyId)) delete unlockedPublicKeys[keyId];
        }
        if (!Object.prototype.hasOwnProperty.call(unlockedPrivateKeys || {}, serverActiveKeyId)
            || !Object.prototype.hasOwnProperty.call(unlockedPublicKeys || {}, serverActiveKeyId)) {
            throw new Error('The active Gallery encryption key is unavailable in this browser.');
        }
        activeKeyId = serverActiveKeyId;
        legacyKeyId = serverLegacyKeyId || null;
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
        const generation = sessionGeneration;
        const verified = await verifyNewPasskey();
        try {
            assertSessionGeneration(generation);
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
            assertSessionGeneration(generation);
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
        const generation = sessionGeneration;
        const verified = await verifyNewPasskey();
        try {
            assertSessionGeneration(generation);
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
            assertSessionGeneration(generation);
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
        const generation = sessionGeneration;
        const verified = await verifyNewPasskey();
        try {
            assertSessionGeneration(generation);
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
            assertSessionGeneration(generation);
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
        sessionGeneration++;
        Array.from(transientSecrets).forEach(clearSecret);
        if (root.SentryIQGalleryStorage
            && typeof root.SentryIQGalleryStorage.invalidatePendingDecrypts === 'function') {
            root.SentryIQGalleryStorage.invalidatePendingDecrypts();
        }
        clearSecret(unlockedRootKey);
        if (pendingSetup) {
            pendingSetup.recoveryCode = '';
            clearSecret(pendingSetup.prfOutput);
            clearSecret(pendingSetup.accountSalt);
            clearSecret(pendingSetup.recoveryKey);
            clearSecret(pendingSetup.recoverySalt);
            if (pendingSetup.identity) clearSecret(pendingSetup.identity.rootKey);
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
        syncKeyringState: syncKeyringState,
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
        decryptObject: async function (data, envelope, photoId, role) {
            if (!unlockedPrivateKey) throw new Error('Secure Gallery is locked.');
            const requiredKeyId = envelope && envelope.keyId ? envelope.keyId : legacyKeyId;
            if (requiredKeyId) await ensureKeyAvailable(requiredKeyId);
            const privateKeys = unlockedPrivateKeys || unlockedPrivateKey;
            return cryptoApi().decryptObject(data, envelope, privateKeys, photoId, role, legacyKeyId);
        }
    });
}(typeof window !== 'undefined' ? window : self));
