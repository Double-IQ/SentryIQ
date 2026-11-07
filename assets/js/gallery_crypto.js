(function (root) {
    'use strict';

    const VERSION = 1;
    const RSA_ALGORITHM = { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
    const PRIVATE_KEY_INFO = 'SentryIQ Gallery private-key envelope v1';
    const CREDENTIAL_KEY_INFO = 'SentryIQ Gallery credential wrapper v1';
    const RECOVERY_KEY_INFO = 'SentryIQ Gallery recovery wrapper v1';
    const OBJECT_INFO = 'SentryIQ Gallery object v1';
    const encoder = new TextEncoder();

    function requireCrypto() {
        if (!root.crypto || !root.crypto.subtle || !root.crypto.getRandomValues) {
            throw new Error('This browser does not provide the cryptography required by SentryIQ Gallery.');
        }
        return root.crypto;
    }

    function bytes(value) {
        if (value instanceof Uint8Array) return value;
        if (value instanceof ArrayBuffer) return new Uint8Array(value);
        if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        throw new TypeError('Expected binary data.');
    }

    function toBase64Url(value) {
        const input = bytes(value);
        let binary = '';
        for (let offset = 0; offset < input.length; offset += 0x8000) {
            binary += String.fromCharCode.apply(null, input.subarray(offset, offset + 0x8000));
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    }

    function fromBase64Url(value) {
        if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid encoded cryptographic data.');
        const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
        const binary = atob(base64);
        const output = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) output[i] = binary.charCodeAt(i);
        return output;
    }

    function randomBytes(length) {
        return requireCrypto().getRandomValues(new Uint8Array(length));
    }

    function validateCredentialId(credentialId) {
        if (typeof credentialId !== 'string' || credentialId.length < 16 || credentialId.length > 2048 || !/^[A-Za-z0-9_-]+$/.test(credentialId)) {
            throw new Error('Invalid passkey credential identifier.');
        }
    }

    function validatePhotoId(photoId) {
        if (typeof photoId !== 'string' || !/^[a-f0-9]{32}$/.test(photoId)) throw new Error('Invalid Gallery object identifier.');
    }

    function validateRole(role) {
        if (!['original', 'thumbnail', 'preview', 'metadata'].includes(role)) throw new Error('Invalid Gallery object role.');
    }

    async function derivePrfWrappingKey(prfOutput, salt, credentialId) {
        const subtle = requireCrypto().subtle;
        const prf = bytes(prfOutput);
        const saltBytes = bytes(salt);
        validateCredentialId(credentialId);
        if (prf.byteLength !== 32 || saltBytes.byteLength !== 32) throw new Error('Invalid passkey key material.');
        const material = await subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
        return subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: encoder.encode(CREDENTIAL_KEY_INFO + '|' + credentialId) },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function wrapRootKeyForPasskey(rootKey, prfOutput, accountSalt, credentialId) {
        const subtle = requireCrypto().subtle;
        const root = bytes(rootKey);
        const salt = bytes(accountSalt);
        validateCredentialId(credentialId);
        if (root.byteLength !== 32 || salt.byteLength !== 32) throw new Error('Invalid Gallery key material.');
        const wrappingKey = await derivePrfWrappingKey(prfOutput, salt, credentialId);
        const iv = randomBytes(12);
        const aad = encoder.encode(CREDENTIAL_KEY_INFO + '|' + credentialId);
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, wrappingKey, root);
        return {
            version: VERSION,
            algorithm: 'A256GCM',
            kdf: 'HKDF-SHA-256',
            salt: toBase64Url(salt),
            iv: toBase64Url(iv),
            ciphertext: toBase64Url(ciphertext),
            credentialId: credentialId
        };
    }

    async function unwrapRootKeyFromPasskey(envelope, prfOutput, credentialId) {
        const subtle = requireCrypto().subtle;
        if (!envelope || envelope.version !== VERSION || envelope.algorithm !== 'A256GCM' || envelope.kdf !== 'HKDF-SHA-256') {
            throw new Error('Unsupported Gallery passkey envelope.');
        }
        validateCredentialId(credentialId);
        if (envelope.credentialId !== credentialId) throw new Error('This Gallery key envelope belongs to a different passkey.');
        const salt = fromBase64Url(envelope.salt);
        const iv = fromBase64Url(envelope.iv);
        const ciphertext = fromBase64Url(envelope.ciphertext);
        if (salt.byteLength !== 32 || iv.byteLength !== 12 || ciphertext.byteLength !== 48) throw new Error('Invalid Gallery passkey envelope.');
        const wrappingKey = await derivePrfWrappingKey(prfOutput, salt, credentialId);
        const aad = encoder.encode(CREDENTIAL_KEY_INFO + '|' + credentialId);
        try {
            const rootKey = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, wrappingKey, ciphertext);
            if (rootKey.byteLength !== 32) throw new Error('Invalid Gallery root key.');
            return new Uint8Array(rootKey);
        } catch (_) {
            throw new Error('Unable to unlock the Gallery with this passkey.');
        }
    }

    async function encryptPrivateKey(privateKeyJwk, rootKey) {
        const subtle = requireCrypto().subtle;
        const key = await subtle.importKey('raw', bytes(rootKey), { name: 'AES-GCM' }, false, ['encrypt']);
        const iv = randomBytes(12);
        const aad = encoder.encode(PRIVATE_KEY_INFO);
        const plaintext = encoder.encode(JSON.stringify(privateKeyJwk));
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext);
        return { version: VERSION, algorithm: 'A256GCM', iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) };
    }

    async function decryptPrivateKey(envelope, rootKey) {
        const subtle = requireCrypto().subtle;
        if (!envelope || envelope.version !== VERSION || envelope.algorithm !== 'A256GCM') throw new Error('Unsupported Gallery private-key envelope.');
        const iv = fromBase64Url(envelope.iv);
        const ciphertext = fromBase64Url(envelope.ciphertext);
        if (iv.byteLength !== 12 || ciphertext.byteLength < 17) throw new Error('Invalid Gallery private-key envelope.');
        const key = await subtle.importKey('raw', bytes(rootKey), { name: 'AES-GCM' }, false, ['decrypt']);
        let plaintext;
        try {
            plaintext = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(PRIVATE_KEY_INFO), tagLength: 128 }, key, ciphertext);
        } catch (_) {
            throw new Error('Unable to unlock the Gallery private key.');
        }
        let jwk;
        try {
            jwk = JSON.parse(new TextDecoder().decode(plaintext));
        } catch (_) {
            throw new Error('The Gallery private-key envelope is invalid.');
        }
        return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    async function createIdentity(prfOutput, accountSalt, credentialId) {
        const subtle = requireCrypto().subtle;
        validateCredentialId(credentialId);
        if (bytes(accountSalt).byteLength !== 32) throw new Error('Gallery account salt must be 32 bytes.');

        const pair = await subtle.generateKey(RSA_ALGORITHM, true, ['encrypt', 'decrypt']);
        const publicKey = await subtle.exportKey('jwk', pair.publicKey);
        const privateKeyJwk = await subtle.exportKey('jwk', pair.privateKey);
        const rootKey = randomBytes(32);
        const privateKeyEnvelope = await encryptPrivateKey(privateKeyJwk, rootKey);
        const credentialEnvelope = await wrapRootKeyForPasskey(rootKey, prfOutput, accountSalt, credentialId);
        return { publicKey, privateKeyEnvelope, credentialEnvelope, rootKey };
    }

    async function unlockIdentity(privateKeyEnvelope, credentialEnvelope, prfOutput, credentialId) {
        const rootKey = await unwrapRootKeyFromPasskey(credentialEnvelope, prfOutput, credentialId);
        try {
            const privateKey = await decryptPrivateKey(privateKeyEnvelope, rootKey);
            return { privateKey, rootKey };
        } catch (error) {
            rootKey.fill(0);
            throw error;
        }
    }

    async function createRecoveryKey() {
        return randomBytes(32);
    }

    async function wrapRootKeyForRecovery(rootKey, recoveryKey, recoverySalt) {
        const subtle = requireCrypto().subtle;
        const root = bytes(rootKey);
        const recovery = bytes(recoveryKey);
        const salt = bytes(recoverySalt);
        if (root.byteLength !== 32 || recovery.byteLength !== 32 || salt.byteLength !== 32) throw new Error('Invalid Gallery recovery material.');
        const material = await subtle.importKey('raw', recovery, 'HKDF', false, ['deriveKey']);
        const wrappingKey = await subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(RECOVERY_KEY_INFO) },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        const iv = randomBytes(12);
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(RECOVERY_KEY_INFO), tagLength: 128 }, wrappingKey, root);
        return { version: VERSION, algorithm: 'A256GCM', kdf: 'HKDF-SHA-256', salt: toBase64Url(salt), iv: toBase64Url(iv), ciphertext: toBase64Url(ciphertext) };
    }

    async function unwrapRootKeyFromRecovery(envelope, recoveryKey) {
        const subtle = requireCrypto().subtle;
        if (!envelope || envelope.version !== VERSION || envelope.algorithm !== 'A256GCM' || envelope.kdf !== 'HKDF-SHA-256') throw new Error('Unsupported Gallery recovery envelope.');
        const salt = fromBase64Url(envelope.salt);
        const iv = fromBase64Url(envelope.iv);
        const ciphertext = fromBase64Url(envelope.ciphertext);
        const recovery = bytes(recoveryKey);
        if (salt.byteLength !== 32 || iv.byteLength !== 12 || ciphertext.byteLength !== 48 || recovery.byteLength !== 32) throw new Error('Invalid Gallery recovery material.');
        const material = await subtle.importKey('raw', recovery, 'HKDF', false, ['deriveKey']);
        const wrappingKey = await subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(RECOVERY_KEY_INFO) },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        try {
            return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(RECOVERY_KEY_INFO), tagLength: 128 }, wrappingKey, ciphertext));
        } catch (_) {
            throw new Error('The Gallery recovery key is incorrect.');
        }
    }

    async function unlockIdentityWithRecovery(privateKeyEnvelope, recoveryEnvelope, recoveryKey) {
        const rootKey = await unwrapRootKeyFromRecovery(recoveryEnvelope, recoveryKey);
        try {
            const privateKey = await decryptPrivateKey(privateKeyEnvelope, rootKey);
            return { privateKey, rootKey };
        } catch (error) {
            rootKey.fill(0);
            throw error;
        }
    }

    async function importGalleryPublicKey(jwk) {
        if (!jwk || jwk.kty !== 'RSA' || (jwk.alg && jwk.alg !== 'RSA-OAEP-256')) throw new Error('Invalid Gallery public key.');
        return requireCrypto().subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    }

    function objectAad(photoId, role) {
        validatePhotoId(photoId);
        validateRole(role);
        return encoder.encode(OBJECT_INFO + '|' + photoId + '|' + role);
    }

    async function encryptObject(plaintext, publicKeyJwk, photoId, role) {
        const subtle = requireCrypto().subtle;
        const publicKey = await importGalleryPublicKey(publicKeyJwk);
        const aad = objectAad(photoId, role);
        const dekRaw = randomBytes(32);
        const nonce = randomBytes(12);
        try {
            const dek = await subtle.importKey('raw', dekRaw, { name: 'AES-GCM' }, false, ['encrypt']);
            const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, bytes(plaintext));
            const wrappedDek = await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, dekRaw);
            return {
                ciphertext: new Uint8Array(ciphertext),
                envelope: {
                    version: VERSION,
                    algorithm: 'A256GCM',
                    keyWrap: 'RSA-OAEP-256',
                    nonce: toBase64Url(nonce),
                    wrappedDek: toBase64Url(wrappedDek),
                    photoId: photoId,
                    role: role
                }
            };
        } finally {
            dekRaw.fill(0);
        }
    }

    async function decryptObject(ciphertext, envelope, privateKey, expectedPhotoId, expectedRole) {
        const subtle = requireCrypto().subtle;
        if (!envelope || envelope.version !== VERSION || envelope.algorithm !== 'A256GCM' || envelope.keyWrap !== 'RSA-OAEP-256') {
            throw new Error('Unsupported Gallery object envelope.');
        }
        if (envelope.photoId !== expectedPhotoId || envelope.role !== expectedRole) throw new Error('Gallery object metadata does not match the requested object.');
        const aad = objectAad(expectedPhotoId, expectedRole);
        const nonce = fromBase64Url(envelope.nonce);
        const wrappedDek = fromBase64Url(envelope.wrappedDek);
        if (nonce.byteLength !== 12 || wrappedDek.byteLength !== 384) throw new Error('Invalid Gallery object envelope.');
        let dekRaw;
        try {
            dekRaw = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, wrappedDek);
        } catch (_) {
            throw new Error('Unable to unlock this Gallery object.');
        }
        if (dekRaw.byteLength !== 32) throw new Error('Invalid Gallery object key.');
        try {
            const dek = await subtle.importKey('raw', dekRaw, { name: 'AES-GCM' }, false, ['decrypt']);
            try {
                return await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, bytes(ciphertext));
            } catch (_) {
                throw new Error('Gallery object authentication failed. The data may have been changed.');
            }
        } finally {
            new Uint8Array(dekRaw).fill(0);
        }
    }

    root.SentryIQGalleryCrypto = Object.freeze({
        createAccountSalt: function () { return randomBytes(32); },
        createRecoveryKey: createRecoveryKey,
        createIdentity: createIdentity,
        unlockIdentity: unlockIdentity,
        wrapRootKeyForPasskey: wrapRootKeyForPasskey,
        wrapRootKeyForRecovery: wrapRootKeyForRecovery,
        unlockIdentityWithRecovery: unlockIdentityWithRecovery,
        clearSecret: function (secret) { if (secret instanceof Uint8Array) secret.fill(0); },
        encryptObject: encryptObject,
        decryptObject: decryptObject,
        toBase64Url: toBase64Url,
        fromBase64Url: fromBase64Url
    });
}(typeof window !== 'undefined' ? window : self));
