(function (root) {
    'use strict';

    const VERSION = 1;
    const RSA_ALGORITHM = { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
    const PRIVATE_KEY_INFO = 'SentryIQ Gallery private-key envelope v1';
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
        if (!['original', 'thumbnail', 'preview'].includes(role)) throw new Error('Invalid Gallery object role.');
    }

    async function derivePasskeyWrappingKey(prfOutput, salt, credentialId) {
        const subtle = requireCrypto().subtle;
        const prf = bytes(prfOutput);
        const saltBytes = bytes(salt);
        validateCredentialId(credentialId);
        if (prf.byteLength !== 32 || saltBytes.byteLength !== 32) throw new Error('Invalid passkey key material.');
        const material = await subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey']);
        return subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: encoder.encode(PRIVATE_KEY_INFO + '|' + credentialId) },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function createIdentity(prfOutput, accountSalt, credentialId) {
        const subtle = requireCrypto().subtle;
        validateCredentialId(credentialId);
        if (bytes(accountSalt).byteLength !== 32) throw new Error('Gallery account salt must be 32 bytes.');

        const pair = await subtle.generateKey(RSA_ALGORITHM, true, ['encrypt', 'decrypt']);
        const publicKey = await subtle.exportKey('jwk', pair.publicKey);
        const privateKey = await subtle.exportKey('jwk', pair.privateKey);
        const wrappingKey = await derivePasskeyWrappingKey(prfOutput, accountSalt, credentialId);
        const iv = randomBytes(12);
        const aad = encoder.encode(PRIVATE_KEY_INFO + '|' + credentialId);
        const plaintext = encoder.encode(JSON.stringify(privateKey));
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, wrappingKey, plaintext);

        return {
            publicKey,
            privateKeyEnvelope: {
                version: VERSION,
                algorithm: 'A256GCM',
                kdf: 'HKDF-SHA-256',
                salt: toBase64Url(accountSalt),
                iv: toBase64Url(iv),
                ciphertext: toBase64Url(ciphertext),
                credentialId: credentialId
            }
        };
    }

    async function unlockIdentity(envelope, prfOutput, credentialId) {
        const subtle = requireCrypto().subtle;
        if (!envelope || envelope.version !== VERSION || envelope.algorithm !== 'A256GCM' || envelope.kdf !== 'HKDF-SHA-256') {
            throw new Error('Unsupported Gallery key envelope.');
        }
        validateCredentialId(credentialId);
        if (envelope.credentialId !== credentialId) throw new Error('This Gallery key envelope belongs to a different passkey.');
        const salt = fromBase64Url(envelope.salt);
        const iv = fromBase64Url(envelope.iv);
        const ciphertext = fromBase64Url(envelope.ciphertext);
        if (salt.byteLength !== 32 || iv.byteLength !== 12 || ciphertext.byteLength < 17) throw new Error('Invalid Gallery key envelope.');
        const wrappingKey = await derivePasskeyWrappingKey(prfOutput, salt, credentialId);
        const aad = encoder.encode(PRIVATE_KEY_INFO + '|' + credentialId);
        let plaintext;
        try {
            plaintext = await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, wrappingKey, ciphertext);
        } catch (_) {
            throw new Error('Unable to unlock the Gallery with this passkey.');
        }
        let jwk;
        try {
            jwk = JSON.parse(new TextDecoder().decode(plaintext));
        } catch (_) {
            throw new Error('The Gallery private-key envelope is invalid.');
        }
        return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    async function importGalleryPublicKey(jwk) {
        if (!jwk || jwk.kty !== 'RSA' || jwk.alg && jwk.alg !== 'RSA-OAEP-256') throw new Error('Invalid Gallery public key.');
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
        const dek = await subtle.importKey('raw', dekRaw, { name: 'AES-GCM' }, false, ['encrypt']);
        const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, bytes(plaintext));
        const wrappedDek = await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, dekRaw);
        dekRaw.fill(0);
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
        if (nonce.byteLength !== 12 || wrappedDek.byteLength < 256) throw new Error('Invalid Gallery object envelope.');
        let dekRaw;
        try {
            dekRaw = await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, wrappedDek);
        } catch (_) {
            throw new Error('Unable to unlock this Gallery object.');
        }
        if (dekRaw.byteLength !== 32) throw new Error('Invalid Gallery object key.');
        const dek = await subtle.importKey('raw', dekRaw, { name: 'AES-GCM' }, false, ['decrypt']);
        new Uint8Array(dekRaw).fill(0);
        try {
            return await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, dek, bytes(ciphertext));
        } catch (_) {
            throw new Error('Gallery object authentication failed. The data may have been changed.');
        }
    }

    root.SentryIQGalleryCrypto = Object.freeze({
        createAccountSalt: function () { return randomBytes(32); },
        createIdentity: createIdentity,
        unlockIdentity: unlockIdentity,
        encryptObject: encryptObject,
        decryptObject: decryptObject,
        toBase64Url: toBase64Url,
        fromBase64Url: fromBase64Url
    });
}(typeof window !== 'undefined' ? window : self));
