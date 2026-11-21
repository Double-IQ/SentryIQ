<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$csrf = sentryiq_csrf_token();
$dataDirectory = sentryiq_data_dir();
$b2Configured = false;
$b2Host = '';
if (is_string($dataDirectory) && $dataDirectory !== '') {
    require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/BackblazeB2Signer.php';
    try {
        $b2Signer = \SentryIQCloud\Gallery\Storage\BackblazeB2Signer::fromRuntimeDirectory($dataDirectory);
        $b2Host = $b2Signer->endpointHost();
        $b2Configured = true;
    } catch (Throwable) {
        $b2Configured = false;
        $b2Host = '';
    }
}
$csp = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: blob:; style-src 'self'; script-src 'self'; connect-src 'self'";
if ($b2Configured && preg_match('/^[a-z0-9.-]+$/', $b2Host)) {
    $csp .= ' https://' . $b2Host;
}
header('Content-Security-Policy: ' . $csp);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="csrf-token" content="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
<meta name="robots" content="noindex,nofollow">
<title>SentryIQ — Secure Gallery</title>
<link rel="stylesheet" href="assets/css/sentryiq.css">
<link rel="stylesheet" href="assets/css/gallery_secure.css">
</head>
<body>
<div class="box">
    <div class="sentryiq-page-header">
        <div class="sentryiq-vault-brand-wrap">
            <img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ">
            <span class="sentryiq-vault-status">Secure Gallery</span>
        </div>
        <div class="sentryiq-mobile-header-actions">
            <form method="POST" class="sentryiq-lock-form">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="lock_vault" value="1">
                <button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button>
            </form>
        </div>
    </div>
    <div class="vault-tabs">
        <button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view" data-gallery-navigation="index.php?pane=view">📋 Vault</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="documents.php" data-gallery-navigation="documents.php">📄 Docs</button>
        <button class="tab-btn active" type="button">🖼️ Gallery</button>
        <button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=settings" data-gallery-navigation="index.php?pane=settings">⚙️ System</button>
    </div>

    <main class="secure-gallery" data-b2-configured="<?php echo $b2Configured ? 1 : 0; ?>">
        <p class="secure-gallery-inline-1"><a class="btn" href="gallery_b2_settings.php">☁️ Backblaze Storage Settings</a></p>
        <section id="secure-gallery-unlock-panel" class="secure-gallery-panel">
            <h2>🔐 Unlock your private photos</h2>
            <p>Photos are encrypted in this browser before they are sent directly to your private Backblaze B2 bucket. The server stores encrypted key envelopes and photo metadata, not readable images.</p>
            <button id="secure-gallery-unlock" class="btn btn-primary" type="button">Unlock Secure Gallery with Passkey</button>
            <div id="secure-gallery-unlock-status" class="secure-gallery-status" role="status" aria-live="polite"></div>
        </section>

        <section id="secure-gallery-setup" class="secure-gallery-panel" hidden>
            <h2>Save your Gallery recovery code</h2>
            <p>This recovery code is generated in your browser and is never sent to SentryIQ. Save it somewhere secure before continuing. If you lose every passkey and this code, your photos cannot be recovered.</p>
            <textarea id="secure-gallery-recovery-code" class="secure-gallery-recovery" readonly spellcheck="false"></textarea>
            <div class="secure-gallery-actions secure-gallery-inline-2">
                <button id="secure-gallery-copy-recovery" class="btn" type="button">Copy recovery code</button>
                <label><input id="secure-gallery-recovery-saved" type="checkbox"> I have saved this recovery code securely</label>
            </div>
            <button id="secure-gallery-finish-setup" class="btn btn-primary" type="button" disabled>Finish secure setup</button>
            <div id="secure-gallery-setup-status" class="secure-gallery-status" role="status" aria-live="polite"></div>
        </section>

        <section id="secure-gallery-recovery-panel" class="secure-gallery-panel" hidden>
            <h2>Use your Gallery recovery code</h2>
            <p>This passkey has no Gallery key envelope. Enter the recovery code you saved when secure Gallery was initialized.</p>
            <input id="secure-gallery-recovery-input" type="password" autocomplete="off" spellcheck="false" placeholder="Paste your 256-bit recovery code">
            <button id="secure-gallery-recover" class="btn btn-primary" type="button">Unlock with recovery code</button>
            <div id="secure-gallery-recovery-status" class="secure-gallery-status" role="status" aria-live="polite"></div>
        </section>

        <section id="secure-gallery-workspace" class="secure-gallery-panel" hidden>
            <div class="secure-gallery-row secure-gallery-inline-3">
                <h2 class="secure-gallery-inline-4">Your private photos</h2>
                <div class="secure-gallery-actions">
                    <button id="secure-gallery-add-passkey" class="btn" type="button">Add this passkey</button>
                    <button id="secure-gallery-add-key" class="btn" type="button">Add encryption key</button>
                    <button id="secure-gallery-lock" class="btn" type="button">Lock Gallery</button>
                </div>
            </div>
            <p>Image resizing, thumbnails, previews and encryption happen locally in your browser. Only encrypted objects are uploaded to Backblaze.</p>
            <section class="secure-gallery-device-panel" aria-labelledby="secure-gallery-rotation-heading">
                <h3 id="secure-gallery-rotation-heading">Encryption key rotation</h3>
                <p>Add a new inactive key, then rotate existing photo envelopes. Photo ciphertext stays in Backblaze and is not re-uploaded. Keep this page open until migration finishes; an interrupted migration can be resumed after unlocking again.</p>
                <div class="secure-gallery-row">
                    <select id="secure-gallery-rotation-target" aria-label="Target encryption key">
                        <option value="">Select an inactive key</option>
                    </select>
                    <button id="secure-gallery-rotate" class="btn" type="button">Start / resume rotation</button>
                    <button id="secure-gallery-abort-rotation" class="btn" type="button" disabled>Abort rotation</button>
                </div>
                <div id="secure-gallery-rotation-status" class="secure-gallery-status" role="status" aria-live="polite"></div>
            </section>
            <section class="secure-gallery-device-panel" aria-labelledby="secure-gallery-devices-heading">
                <h3 id="secure-gallery-devices-heading">Enrolled Gallery devices</h3>
                <p>Remove a device's ability to unlock Gallery without deleting its SentryIQ sign-in passkey. Removal requires confirmation with a different enrolled passkey.</p>
                <div id="secure-gallery-devices" class="secure-gallery-device-list" aria-live="polite">Loading enrolled devices…</div>
            </section>
            <div id="secure-gallery-b2-warning" class="secure-gallery-status error" <?php if ($b2Configured) echo 'hidden'; ?>>Backblaze B2 is not configured. Follow docs/operations/backblaze-b2-gallery-setup.md to add the protected runtime credentials file before uploading photos.</div>
            <div class="secure-gallery-row">
                <select id="secure-gallery-album-filter" aria-label="Filter by album">
                    <option value="">All albums</option>
                </select>
            </div>
            <div class="secure-gallery-row">
                <input id="secure-gallery-file" type="file" accept="image/jpeg,image/png,image/webp,image/gif,image/bmp,image/avif,image/heic,image/heif">
                <input id="secure-gallery-album" type="text" maxlength="80" placeholder="Album name (optional)">
                <button id="secure-gallery-upload" class="btn btn-primary" type="button" <?php if (!$b2Configured) echo 'disabled'; ?>>Encrypt &amp; upload</button>
            </div>
            <div id="secure-gallery-workspace-status" class="secure-gallery-status" role="status" aria-live="polite"></div>
            <div id="secure-gallery-grid" class="secure-gallery-grid"></div>
        </section>
    </main>
</div>

<div id="secure-gallery-viewer" class="secure-gallery-viewer" hidden>
    <button id="secure-gallery-viewer-close" class="btn" type="button">Close</button>
    <img id="secure-gallery-viewer-image" alt="Decrypted private photo">
</div>

<script src="assets/js/gallery_crypto.js"></script>
<script src="assets/js/gallery_secure.js"></script>
<script src="assets/js/gallery_storage.js"></script>
<script src="assets/js/gallery_session_guard.js"></script>
<script src="assets/js/gallery_secure_ui.js"></script>
</body>
</html>
