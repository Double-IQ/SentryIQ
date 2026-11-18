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
    let sessionGuard = null;

    function setStatus(id, message, type) {
        const node = byId(id);
        if (!node) return;
        node.textContent = message || '';
        node.className = 'secure-gallery-status' + (type ? ' ' + type : '');
    }

    function stopSessionGuard() {
        if (sessionGuard) sessionGuard.stop();
        sessionGuard = null;
    }

    function lockWorkspace(reason) {
        stopSessionGuard();
        closeViewer();
        SentryIQGalleryStorage.lock();
        byId('secure-gallery-file').value = '';
        byId('secure-gallery-recovery-code').value = '';
        byId('secure-gallery-recovery-input').value = '';
        byId('secure-gallery-recovery-saved').checked = false;
        byId('secure-gallery-finish-setup').disabled = true;
        grid.replaceChildren();
        photoCards = [];
        workspace.hidden = true;
        setupPanel.hidden = true;
        recoveryPanel.hidden = true;
        unlockPanel.hidden = false;
        const message = reason === 'idle'
            ? 'Gallery locked after 15 minutes of inactivity.'
            : reason === 'background'
                ? 'Gallery locked after remaining in the background for 60 seconds.'
                : 'Gallery locked. Decrypted browser object URLs were revoked.';
        setStatus('secure-gallery-unlock-status', message, 'success');
    }

    function startSessionGuard() {
        stopSessionGuard();
        try {
            if (!window.SentryIQGallerySessionGuard) throw new Error('Gallery session protection is unavailable. Reload the page before unlocking.');
            sessionGuard = window.SentryIQGallerySessionGuard.start(function (reason) {
                sessionGuard = null;
                lockWorkspace(reason);
            });
        } catch (error) {
            SentryIQGalleryStorage.lock();
            throw error;
        }
    }

    async function refreshDevices() {
        const container = byId('secure-gallery-devices');
        if (!container) return;
        container.textContent = 'Loading enrolled devices…';
        try {
            const response = await fetch('gallery_passkey.php?action=devices', {
                method: 'GET',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: { Accept: 'application/json' }
            });
            const payload = await response.json();
            if (!response.ok || !payload || payload.status !== 'ok' || !Array.isArray(payload.devices)) {
                throw new Error(payload && payload.message ? payload.message : 'Unable to load enrolled devices.');
            }
            container.replaceChildren();
            if (payload.devices.length === 0) {
                container.textContent = 'No Gallery devices are enrolled.';
                return;
            }
            payload.devices.forEach(function (device, index) {
                const row = document.createElement('div');
                row.className = 'secure-gallery-device';
                const description = document.createElement('div');
                const title = document.createElement('strong');
                title.textContent = 'Gallery device ' + (index + 1);
                const date = document.createElement('small');
                date.textContent = device.createdAt > 0
                    ? 'Enrolled ' + new Date(device.createdAt * 1000).toLocaleString()
                    : 'Enrollment date unavailable';
                description.append(title, date);
                const remove = document.createElement('button');
                remove.type = 'button';
                remove.className = 'btn';
                remove.textContent = 'Remove';
                remove.addEventListener('click', async function () {
                    if (!window.confirm('Remove this device from Secure Gallery? It will no longer be able to unlock Gallery. Its SentryIQ sign-in passkey will remain registered.')) return;
                    remove.disabled = true;
                    setStatus('secure-gallery-workspace-status', 'Confirm a different enrolled passkey to remove this device…');
                    try {
                        await SentryIQSecureGallery.removeEnrolledDevice(device.credentialId);
                        setStatus('secure-gallery-workspace-status', 'Gallery device removed. Its SentryIQ sign-in passkey was not deleted.', 'success');
                        await refreshDevices();
                    } catch (error) {
                        setStatus('secure-gallery-workspace-status', error.message || 'Unable to remove this Gallery device.', 'error');
                        remove.disabled = false;
                    }
                });
                row.append(description, remove);
                container.appendChild(row);
            });
        } catch (error) {
            container.textContent = error.message || 'Unable to load enrolled devices.';
        }
    }

    function showWorkspace() {
        startSessionGuard();
        unlockPanel.hidden = true;
        setupPanel.hidden = true;
        recoveryPanel.hidden = true;
        workspace.hidden = false;
        refreshDevices();
        refreshRotationControls();
        setStatus('secure-gallery-workspace-status', 'Gallery unlocked in this browser. It will lock after 15 minutes of inactivity or 60 seconds in the background.', 'success');
    }

    function showRecovery(message) {
        recoveryPanel.hidden = false;
        setStatus('secure-gallery-recovery-status', message || 'Enter your saved recovery code.', 'error');
    }

    async function refreshRotationControls() {
        const select = byId('secure-gallery-rotation-target');
        if (!select) return;
        try {
            const status = await SentryIQSecureGallery.getRotationStatus();
            if (status.activeKeyId) {
                await SentryIQSecureGallery.syncKeyringState(status.activeKeyId, status.keyIds, status.legacyKeyId);
            }
            const info = SentryIQSecureGallery.getKeyInfo();
            const current = status.rotation;
            select.replaceChildren();
            const placeholder = document.createElement('option');
            placeholder.value = '';
            placeholder.textContent = 'Select an inactive key';
            select.appendChild(placeholder);
            info.keyIds.filter(function (keyId) {
                return keyId !== status.activeKeyId || (current && ['running', 'ready_to_retire'].includes(current.status) && keyId === current.to_key_id);
            }).forEach(function (keyId) {
                const option = document.createElement('option');
                option.value = keyId;
                option.textContent = 'Key ' + keyId.slice(-8);
                select.appendChild(option);
            });
            const abort = byId('secure-gallery-abort-rotation');
            byId('secure-gallery-rotate').disabled = false;
            const rotationActive = current && ['running', 'ready_to_retire'].includes(current.status);
            select.disabled = !!rotationActive;
            byId('secure-gallery-add-key').disabled = !!rotationActive;
            if (current && current.status === 'running') {
                select.value = current.to_key_id;
                byId('secure-gallery-rotate').textContent = 'Resume rotation';
                abort.disabled = false;
                const remaining = Number(status.references && status.references[current.from_key_id] || 0);
                setStatus('secure-gallery-rotation-status',
                    'Rotation in progress. ' + remaining + ' object or pending-upload reference(s) still use the previous key.',
                    'success');
            } else if (current && current.status === 'ready_to_retire') {
                select.value = current.to_key_id;
                byId('secure-gallery-rotate').textContent = 'Finalize key retirement';
                abort.disabled = false;
                const retireAfter = new Date(current.retire_after * 1000).toLocaleString();
                setStatus('secure-gallery-rotation-status',
                    'All objects have migrated. The old key is retained for rollback until ' + retireAfter + '. You can abort during this period or finalize after it expires.',
                    'success');
            } else {
                byId('secure-gallery-rotate').textContent = 'Start rotation';
                abort.disabled = true;
                if (current && current.status === 'completed') {
                    setStatus('secure-gallery-rotation-status', 'Last key rotation completed. The previous key was retired after the server verified that no objects referenced it.', 'success');
                } else if (current && current.status === 'aborted') {
                    setStatus('secure-gallery-rotation-status', 'Last rotation was aborted. Both keys were retained and existing photos remain readable.', 'success');
                } else if (info.keyIds.length < 2) {
                    setStatus('secure-gallery-rotation-status', 'Add an inactive encryption key before starting rotation.');
                } else {
                    setStatus('secure-gallery-rotation-status', 'An inactive encryption key is ready for rotation.');
                }
            }
        } catch (error) {
            setStatus('secure-gallery-rotation-status', error.message || 'Unable to read Gallery rotation status.', 'error');
        }
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

    document.querySelectorAll('[data-gallery-navigation]').forEach(function (button) {
        button.addEventListener('click', function () {
            const destination = button.getAttribute('data-gallery-navigation');
            if (destination) window.location.assign(destination);
        });
    });

    byId('secure-gallery-album-filter').addEventListener('change', filterCards);

    byId('secure-gallery-unlock').addEventListener('click', async function () {
        this.disabled = true;
        setStatus('secure-gallery-unlock-status', 'Waiting for passkey confirmation…');
        try {
            const result = await SentryIQSecureGallery.unlock();
            if (result.status === 'uninitialized') {
                const prepared = await SentryIQSecureGallery.prepareIdentity();
                startSessionGuard();
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
            byId('secure-gallery-recovery-code').value = '';
            byId('secure-gallery-recovery-saved').checked = false;
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

    byId('secure-gallery-add-key').addEventListener('click', async function () {
        if (!window.confirm('Add another inactive Gallery encryption key? Existing photos will remain encrypted with their current keys.')) return;
        this.disabled = true;
        setStatus('secure-gallery-workspace-status', 'Confirm an enrolled Gallery passkey to add an encryption key…');
        try {
            const result = await SentryIQSecureGallery.addWrappingKey();
            setStatus('secure-gallery-workspace-status', 'A new inactive encryption key was added (' + result.keyId + '). Existing uploads continue using the current active key.', 'success');
            await refreshRotationControls();
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Unable to add an encryption key.', 'error');
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-rotate').addEventListener('click', async function () {
        const targetKeyId = byId('secure-gallery-rotation-target').value;
        if (!targetKeyId) {
            setStatus('secure-gallery-rotation-status', 'Select an inactive encryption key first.', 'error');
            return;
        }
        if (!window.confirm('Switch new uploads to this key and rewrap existing photo keys? Photos stay encrypted; this operation changes only their encrypted key envelopes.')) return;
        this.disabled = true;
        byId('secure-gallery-abort-rotation').disabled = true;
        try {
            const currentStatus = await SentryIQSecureGallery.getRotationStatus();
            if (currentStatus.rotation && currentStatus.rotation.status === 'ready_to_retire') {
                const finalized = await SentryIQSecureGallery.finalizeRotation();
                setStatus('secure-gallery-rotation-status',
                    finalized.status === 'completed'
                        ? 'Key rotation completed. The old key was retired after its rollback period.'
                        : 'Migration is complete. The old key remains available until the rollback period expires.',
                    'success');
                await refreshRotationControls();
                return;
            }
            const rotation = await SentryIQSecureGallery.startRotation(targetKeyId);
            setStatus('secure-gallery-rotation-status', 'Migrating encrypted photo-key envelopes…');
            const result = await SentryIQGalleryStorage.migrateEnvelopesToKey(targetKeyId, function (progress) {
                setStatus('secure-gallery-rotation-status',
                    'Processed ' + (progress.updated + progress.skipped) + ' of ' + progress.total + ' photo-key envelope(s)…');
            });
            const remaining = Number(result.references && result.references[rotation.from_key_id] || 0);
            if (remaining > 0) {
                setStatus('secure-gallery-rotation-status',
                    'Migration paused safely. ' + result.updated + ' envelope(s) updated; ' + remaining +
                    ' reference(s) still use the old key, including any in-flight uploads. Press Resume after they finish or are cleaned up.',
                    'success');
            } else {
                const finalized = await SentryIQSecureGallery.finalizeRotation();
                setStatus('secure-gallery-rotation-status',
                    finalized.status === 'completed'
                        ? 'Key rotation completed. All photo envelopes use the new key and the old key was retired.'
                        : 'All photo envelopes migrated. The old key is retained for a 24-hour rollback period.',
                    'success');
            }
            await refreshRotationControls();
        } catch (error) {
            setStatus('secure-gallery-rotation-status', error.message || 'Key rotation stopped safely. You can resume it later.', 'error');
            await refreshRotationControls();
        } finally {
            this.disabled = false;
        }
    });

    byId('secure-gallery-abort-rotation').addEventListener('click', async function () {
        if (!window.confirm('Abort this rotation? The previous key will become active again. Both keys will be kept, and already migrated photos will remain readable.')) return;
        this.disabled = true;
        byId('secure-gallery-rotate').disabled = true;
        try {
            await SentryIQSecureGallery.abortRotation();
            setStatus('secure-gallery-rotation-status', 'Rotation aborted. The previous key is active again and both keys were retained.', 'success');
            await refreshRotationControls();
        } catch (error) {
            setStatus('secure-gallery-rotation-status', error.message || 'Unable to abort key rotation.', 'error');
        } finally {
            await refreshRotationControls();
        }
    });

    byId('secure-gallery-upload').addEventListener('click', async function () {
        const file = byId('secure-gallery-file').files[0];
        if (!file) {
            setStatus('secure-gallery-workspace-status', 'Choose a photo first.', 'error');
            return;
        }
        this.disabled = true;
        byId('secure-gallery-lock').disabled = true;
        setStatus('secure-gallery-workspace-status', 'Preparing, encrypting and uploading photo directly to Backblaze…');
        try {
            await SentryIQGalleryStorage.upload(file, byId('secure-gallery-album').value);
            setStatus('secure-gallery-workspace-status', 'Encrypted photo uploaded successfully.', 'success');
            await refreshPhotos();
        } catch (error) {
            setStatus('secure-gallery-workspace-status', error.message || 'Photo upload failed.', 'error');
        } finally {
            byId('secure-gallery-file').value = '';
            this.disabled = false;
            byId('secure-gallery-lock').disabled = false;
        }
    });

    byId('secure-gallery-lock').addEventListener('click', function () {
        lockWorkspace('manual');
    });

    byId('secure-gallery-viewer-close').addEventListener('click', closeViewer);
    byId('secure-gallery-viewer').addEventListener('click', function (event) {
        if (event.target === this) closeViewer();
    });
    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') closeViewer();
    });
    window.addEventListener('pagehide', function () {
        stopSessionGuard();
        if (viewerUrl) SentryIQGalleryStorage.revokeObjectUrl(viewerUrl);
        byId('secure-gallery-file').value = '';
        byId('secure-gallery-recovery-code').value = '';
        byId('secure-gallery-recovery-input').value = '';
        SentryIQGalleryStorage.lock();
    });
}());
