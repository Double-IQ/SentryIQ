(function () {
    'use strict';

    const byId = function (id) { return document.getElementById(id); };
    const unlockPanel = byId('secure-gallery-unlock-panel');
    const setupPanel = byId('secure-gallery-setup');
    const recoveryPanel = byId('secure-gallery-recovery-panel');
    const workspace = byId('secure-gallery-workspace');
    const grid = byId('secure-gallery-grid');
    let viewerUrl = null;
    let photoCards = [];

    function setStatus(id, message, type) {
        const node = byId(id);
        if (!node) return;
        node.textContent = message || '';
        node.className = 'secure-gallery-status' + (type ? ' ' + type : '');
    }

    function showWorkspace() {
        unlockPanel.hidden = true;
        setupPanel.hidden = true;
        recoveryPanel.hidden = true;
        workspace.hidden = false;
        setStatus('secure-gallery-workspace-status', 'Gallery unlocked in this browser.', 'success');
    }

    function showRecovery(message) {
        recoveryPanel.hidden = false;
        setStatus('secure-gallery-recovery-status', message || 'Enter your saved recovery code.', 'error');
    }

    async function refreshPhotos() {
        photoCards.forEach(function (item) { SentryIQGalleryStorage.revokeObjectUrl(item.thumbnailUrl); });
        grid.replaceChildren();
        photoCards = [];
        updateAlbumFilter();
        const page = document.querySelector('main[data-b2-configured]');
        if (page && page.dataset.b2Configured !== '1') {
            setStatus('secure-gallery-workspace-status', 'Gallery keys are ready, but Backblaze B2 is not configured yet. Follow the setup guide before uploading or listing photos.', 'error');
            return;
        }
        setStatus('secure-gallery-workspace-status', 'Loading encrypted photos…');
        try {
            const records = await SentryIQGalleryStorage.list();
            const ids = Object.keys(records);
            const results = await Promise.allSettled(ids.map(function (id) {
                return SentryIQGalleryStorage.loadPhoto(id);
            }));
            results.forEach(function (result) {
                if (result.status === 'fulfilled') addPhotoCard(result.value);
            });
            const failures = results.filter(function (result) { return result.status === 'rejected'; }).length;
            if (ids.length === 0) setStatus('secure-gallery-workspace-status', 'No photos yet. Choose a photo to encrypt and upload.', 'success');
            else setStatus('secure-gallery-workspace-status', failures ? (ids.length - failures) + ' photos loaded; ' + failures + ' could not be decrypted.' : ids.length + ' private photo(s) loaded.', failures ? 'error' : 'success');
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Unable to load the Gallery. Check the Backblaze configuration.', 'error');
        }
    }

    function updateAlbumFilter() {
        const select = byId('secure-gallery-album-filter');
        const current = select.value;
        const albums = Array.from(new Set(photoCards.map(function (item) { return item.album; }).filter(Boolean))).sort();
        select.replaceChildren();
        const all = document.createElement('option');
        all.value = '';
        all.textContent = 'All albums';
        select.appendChild(all);
        albums.forEach(function (album) {
            const option = document.createElement('option');
            option.value = album;
            option.textContent = album;
            select.appendChild(option);
        });
        select.value = albums.includes(current) ? current : '';
        filterCards();
    }

    function filterCards() {
        const selected = byId('secure-gallery-album-filter').value;
        photoCards.forEach(function (item) {
            item.card.hidden = selected !== '' && item.album !== selected;
        });
    }

    function addPhotoCard(photo) {
        const card = document.createElement('article');
        card.className = 'secure-gallery-card';
        const image = document.createElement('img');
        image.src = photo.thumbnailUrl;
        image.alt = photo.metadata.filename || 'Private photo';
        image.loading = 'lazy';
        image.addEventListener('click', function () { openViewer(photo.photoId); });
        const title = document.createElement('strong');
        title.textContent = photo.metadata.filename || 'Private photo';
        const album = document.createElement('small');
        album.textContent = photo.metadata.album || 'Unassigned';
        const preview = document.createElement('button');
        preview.type = 'button';
        preview.className = 'btn';
        preview.textContent = 'View';
        preview.addEventListener('click', function () { openViewer(photo.photoId); });
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'btn';
        remove.textContent = 'Delete';
        remove.addEventListener('click', async function () {
            if (!window.confirm('Permanently delete this encrypted photo and its B2 objects?')) return;
            remove.disabled = true;
            try {
                await SentryIQGalleryStorage.deletePhoto(photo.photoId);
                SentryIQGalleryStorage.revokeObjectUrl(photo.thumbnailUrl);
                card.remove();
                photoCards = photoCards.filter(function (item) { return item.card !== card; });
                updateAlbumFilter();
                setStatus('secure-gallery-workspace-status', 'Photo deleted.', 'success');
            } catch (error) {
                setStatus('secure-gallery-workspace-status', error.message || 'Unable to delete this photo.', 'error');
                remove.disabled = false;
            }
        });
        card.append(image, title, album, preview, remove);
        grid.appendChild(card);
        photoCards.push({ card: card, album: album.textContent, thumbnailUrl: photo.thumbnailUrl });
        updateAlbumFilter();
    }

    async function openViewer(photoId) {
        try {
            if (viewerUrl) SentryIQGalleryStorage.revokeObjectUrl(viewerUrl);
            viewerUrl = await SentryIQGalleryStorage.openPreview(photoId);
            byId('secure-gallery-viewer-image').src = viewerUrl;
            byId('secure-gallery-viewer').hidden = false;
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Unable to decrypt this photo.', 'error');
        }
    }

    function closeViewer() {
        byId('secure-gallery-viewer').hidden = true;
        byId('secure-gallery-viewer-image').removeAttribute('src');
        if (viewerUrl) SentryIQGalleryStorage.revokeObjectUrl(viewerUrl);
        viewerUrl = null;
    }

    byId('secure-gallery-album-filter').addEventListener('change', filterCards);

    byId('secure-gallery-unlock').addEventListener('click', async function () {
        this.disabled = true;
        setStatus('secure-gallery-unlock-status', 'Waiting for passkey confirmation…');
        try {
            const result = await SentryIQSecureGallery.unlock();
            if (result.status === 'uninitialized') {
                const prepared = await SentryIQSecureGallery.prepareIdentity();
                byId('secure-gallery-recovery-code').value = prepared.recoveryCode;
                setupPanel.hidden = false;
                setStatus('secure-gallery-unlock-status', 'Secure Gallery needs its first-time setup. Save the recovery code below.', 'success');
            } else {
                showWorkspace();
                await refreshPhotos();
            }
        } catch (error) {
            setStatus('secure-gallery-unlock-status', error.message || 'Passkey unlock failed.', 'error');
            showRecovery('If this passkey is unavailable or not enrolled, use your saved recovery code.');
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-copy-recovery').addEventListener('click', async function () {
        const code = byId('secure-gallery-recovery-code').value;
        try {
            await navigator.clipboard.writeText(code);
            setStatus('secure-gallery-setup-status', 'Recovery code copied. Save it in a secure password manager or offline location.', 'success');
        } catch (_) {
            const input = byId('secure-gallery-recovery-code');
            input.focus();
            input.select();
            setStatus('secure-gallery-setup-status', 'Copy the selected recovery code and store it securely.', 'error');
        }
    });

    byId('secure-gallery-recovery-saved').addEventListener('change', function () {
        byId('secure-gallery-finish-setup').disabled = !this.checked;
    });

    byId('secure-gallery-finish-setup').addEventListener('click', async function () {
        if (!byId('secure-gallery-recovery-saved').checked) return;
        this.disabled = true;
        setStatus('secure-gallery-setup-status', 'Creating your encrypted Gallery identity…');
        try {
            await SentryIQSecureGallery.completeIdentitySetup();
            showWorkspace();
            await refreshPhotos();
        } catch (error) {
            setStatus('secure-gallery-setup-status', error.message || 'Unable to initialize secure Gallery.', 'error');
            this.disabled = false;
        }
    });

    byId('secure-gallery-recover').addEventListener('click', async function () {
        this.disabled = true;
        setStatus('secure-gallery-recovery-status', 'Unlocking with your recovery code…');
        try {
            await SentryIQSecureGallery.unlockWithRecovery(byId('secure-gallery-recovery-input').value);
            byId('secure-gallery-recovery-input').value = '';
            showWorkspace();
            await refreshPhotos();
        } catch (error) {
            setStatus('secure-gallery-recovery-status', error.message || 'Recovery failed.', 'error');
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-add-passkey').addEventListener('click', async function () {
        this.disabled = true;
        setStatus('secure-gallery-workspace-status', 'Confirm the passkey you want to enroll for Gallery…');
        try {
            await SentryIQSecureGallery.enrollCurrentPasskey();
            setStatus('secure-gallery-workspace-status', 'This passkey can now unlock secure Gallery.', 'success');
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Unable to enroll this passkey.', 'error');
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-upload').addEventListener('click', async function () {
        const file = byId('secure-gallery-file').files[0];
        if (!file) {
            setStatus('secure-gallery-workspace-status', 'Choose a photo first.', 'error');
            return;
        }
        this.disabled = true;
        setStatus('secure-gallery-workspace-status', 'Preparing, encrypting and uploading photo directly to Backblaze…');
        try {
            await SentryIQGalleryStorage.upload(file, byId('secure-gallery-album').value);
            byId('secure-gallery-file').value = '';
            setStatus('secure-gallery-workspace-status', 'Encrypted photo uploaded successfully.', 'success');
            await refreshPhotos();
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Photo upload failed.', 'error');
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-lock').addEventListener('click', function () {
        closeViewer();
        SentryIQGalleryStorage.lock();
        grid.replaceChildren();
        photoCards = [];
        workspace.hidden = true;
        setupPanel.hidden = true;
        recoveryPanel.hidden = true;
        unlockPanel.hidden = false;
        setStatus('secure-gallery-unlock-status', 'Gallery locked. Decrypted browser object URLs were revoked.', 'success');
    });

    byId('secure-gallery-viewer-close').addEventListener('click', closeViewer);
    byId('secure-gallery-viewer').addEventListener('click', function (event) {
        if (event.target === this) closeViewer();
    });
    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') closeViewer();
    });
    window.addEventListener('pagehide', function () {
        if (viewerUrl) SentryIQGalleryStorage.revokeObjectUrl(viewerUrl);
        SentryIQGalleryStorage.lock();
    });
}());
