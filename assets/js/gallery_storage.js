(function (root) {
    'use strict';

    const roles = ['original', 'thumbnail', 'preview', 'metadata'];
    const objectUrls = new Set();

    function secureApi() {
        if (!root.SentryIQSecureGallery || !root.SentryIQSecureGallery.isUnlocked()) {
            throw new Error('Unlock secure Gallery before using photos.');
        }
        return root.SentryIQSecureGallery;
    }

    function csrfToken() {
        const node = document.querySelector('meta[name="csrf-token"]');
        if (!node || !node.content) throw new Error('Security token is unavailable. Reload the Gallery and try again.');
        return node.content;
    }

    async function jsonResponse(response) {
        let payload;
        try { payload = await response.json(); }
        catch (_) { throw new Error('The Gallery storage endpoint returned an invalid response.'); }
        if (!response.ok || !payload || payload.status !== 'ok') {
            throw new Error(payload && payload.message ? payload.message : 'The Gallery storage request failed.');
        }
        return payload;
    }

    async function post(action, values) {
        const response = await fetch('gallery_storage.php', {
            method: 'POST',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(Object.assign({ action: action, csrf_token: csrfToken() }, values || {}))
        });
        return jsonResponse(response);
    }

    function canvasBlob(canvas, quality) {
        return new Promise(function (resolve, reject) {
            canvas.toBlob(function (blob) {
                if (blob && blob.type === 'image/webp') resolve(blob);
                else reject(new Error('This browser could not create a WebP image.'));
            }, 'image/webp', quality);
        });
    }

    async function makeWebp(bitmap, maxDimension, quality) {
        const scale = Math.min(1, maxDimension / Math.max(bitmap.width, bitmap.height));
        const width = Math.max(1, Math.round(bitmap.width * scale));
        const height = Math.max(1, Math.round(bitmap.height * scale));
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const context = canvas.getContext('2d', { alpha: true });
        if (!context) throw new Error('Image processing is unavailable in this browser.');
        context.drawImage(bitmap, 0, 0, width, height);
        const blob = await canvasBlob(canvas, quality);
        canvas.width = 1;
        canvas.height = 1;
        return { blob: blob, width: width, height: height };
    }

    async function prepareImage(file) {
        if (!(file instanceof File) || !/^image\/(jpeg|png|webp|gif|bmp|avif|heic|heif)$/i.test(file.type || '')) {
            throw new Error('Choose a supported image file.');
        }
        if (file.size < 1 || file.size > 52428800) throw new Error('Each image must be 50 MB or smaller.');
        if (typeof createImageBitmap !== 'function') throw new Error('This browser cannot decode images locally for secure upload.');
        let bitmap;
        try {
            bitmap = await createImageBitmap(file);
            if (!bitmap.width || !bitmap.height || bitmap.width > 20000 || bitmap.height > 20000 || bitmap.width * bitmap.height > 40000000) {
                throw new Error('The image dimensions are invalid or too large.');
            }
            const saved = await makeWebp(bitmap, 8000, 0.90);
            const preview = await makeWebp(bitmap, 1800, 0.84);
            const thumbnail = await makeWebp(bitmap, 520, 0.80);
            return {
                saved: saved,
                preview: preview,
                thumbnail: thumbnail,
                sourceWidth: bitmap.width,
                sourceHeight: bitmap.height
            };
        } finally {
            if (bitmap && typeof bitmap.close === 'function') bitmap.close();
        }
    }

    async function uploadCiphertext(url, ciphertext) {
        const response = await fetch(url, {
            method: 'PUT',
            mode: 'cors',
            credentials: 'omit',
            cache: 'no-store',
            redirect: 'error',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: ciphertext
        });
        if (!response.ok) throw new Error('Backblaze rejected an encrypted Gallery object upload (' + response.status + ').');
    }

    async function deleteCiphertext(url) {
        const response = await fetch(url, {
            method: 'DELETE',
            mode: 'cors',
            credentials: 'omit',
            cache: 'no-store',
            redirect: 'error'
        });
        if (!response.ok && response.status !== 404) throw new Error('Backblaze could not remove an encrypted Gallery object (' + response.status + ').');
    }

    async function cancelPending(photoId) {
        const result = await post('cancel', { photoId: photoId });
        const urls = result.deleteUrls || {};
        const outcomes = await Promise.allSettled(Object.keys(urls).map(function (role) {
            return deleteCiphertext(urls[role]);
        }));
        if (outcomes.some(function (item) { return item.status === 'rejected'; })) {
            throw new Error('The upload failed and some temporary encrypted objects could not be cleaned up. Retry cleanup before continuing.');
        }
        await post('confirm_cancel', { photoId: photoId });
    }

    async function upload(file, albumName) {
        const secure = secureApi();
        const prepared = await prepareImage(file);
        const reservation = await post('allocate');
        const photoId = reservation.photoId;
        let committed = false;
        try {
            const metadata = {
                filename: String(file.name || 'photo').slice(0, 255),
                sourceType: String(file.type || 'application/octet-stream').slice(0, 100),
                album: String(albumName || 'Unassigned').slice(0, 80),
                width: prepared.sourceWidth,
                height: prepared.sourceHeight,
                storedWidth: prepared.saved.width,
                storedHeight: prepared.saved.height,
                createdAt: Date.now()
            };
            const plainObjects = {
                original: await prepared.saved.blob.arrayBuffer(),
                thumbnail: await prepared.thumbnail.blob.arrayBuffer(),
                preview: await prepared.preview.blob.arrayBuffer(),
                metadata: new TextEncoder().encode(JSON.stringify(metadata))
            };
            const encrypted = {};
            const sizes = {};
            for (const role of roles) {
                encrypted[role] = await secure.encryptObject(plainObjects[role], photoId, role);
                sizes[role] = encrypted[role].ciphertext.byteLength;
            }
            for (const role of roles) {
                await uploadCiphertext(reservation.uploadUrls[role], encrypted[role].ciphertext);
            }
            const envelopes = {};
            for (const role of roles) envelopes[role] = encrypted[role].envelope;
            await post('commit', { photoId: photoId, envelopes: envelopes, sizes: sizes });
            committed = true;
            return { photoId: photoId, metadata: metadata };
        } finally {
            if (!committed) {
                try { await cancelPending(photoId); }
                catch (cleanupError) { /* Keep the pending record so a later cleanup can retry. */ }
            }
        }
    }

    async function list() {
        secureApi();
        const response = await fetch('gallery_storage.php?action=list', {
            method: 'GET',
            credentials: 'same-origin',
            cache: 'no-store',
            headers: { Accept: 'application/json' }
        });
        const payload = await jsonResponse(response);
        return payload.photos || {};
    }

    async function download(photoId, role) {
        const secure = secureApi();
        if (!roles.includes(role)) throw new Error('Invalid Gallery object role.');
        const signed = await post('download', { photoId: photoId, role: role });
        const response = await fetch(signed.url, {
            method: 'GET',
            mode: 'cors',
            credentials: 'omit',
            cache: 'no-store',
            redirect: 'error'
        });
        if (!response.ok) throw new Error('Unable to download encrypted Gallery data (' + response.status + ').');
        const ciphertext = await response.arrayBuffer();
        return secure.decryptObject(ciphertext, signed.envelope, photoId, role);
    }

    async function loadPhoto(photoId) {
        const metadataBytes = await download(photoId, 'metadata');
        let metadata;
        try { metadata = JSON.parse(new TextDecoder().decode(metadataBytes)); }
        catch (_) { throw new Error('The encrypted Gallery photo metadata is invalid.'); }
        const thumbnailBytes = await download(photoId, 'thumbnail');
        const thumbnailBlob = new Blob([thumbnailBytes], { type: 'image/webp' });
        const thumbnailUrl = URL.createObjectURL(thumbnailBlob);
        objectUrls.add(thumbnailUrl);
        return { photoId: photoId, metadata: metadata, thumbnailUrl: thumbnailUrl };
    }

    async function openPreview(photoId) {
        const bytes = await download(photoId, 'preview');
        const url = URL.createObjectURL(new Blob([bytes], { type: 'image/webp' }));
        objectUrls.add(url);
        return url;
    }

    async function deletePhoto(photoId) {
        secureApi();
        const result = await post('delete_urls', { photoId: photoId });
        const urls = result.deleteUrls || {};
        const outcomes = await Promise.allSettled(Object.keys(urls).map(function (role) {
            return deleteCiphertext(urls[role]);
        }));
        if (outcomes.some(function (item) { return item.status === 'rejected'; })) {
            throw new Error('Some encrypted objects could not be deleted. The Gallery record has been kept so deletion can be retried.');
        }
        await post('confirm_delete', { photoId: photoId });
        return { status: 'deleted' };
    }

    function revokeObjectUrl(url) {
        if (objectUrls.has(url)) {
            URL.revokeObjectURL(url);
            objectUrls.delete(url);
        }
    }

    function lock() {
        objectUrls.forEach(function (url) { URL.revokeObjectURL(url); });
        objectUrls.clear();
        if (root.SentryIQSecureGallery) root.SentryIQSecureGallery.lock();
    }

    root.SentryIQGalleryStorage = Object.freeze({
        upload: upload,
        list: list,
        download: download,
        loadPhoto: loadPhoto,
        openPreview: openPreview,
        deletePhoto: deletePhoto,
        revokeObjectUrl: revokeObjectUrl,
        lock: lock
    });
}(typeof window !== 'undefined' ? window : self));
