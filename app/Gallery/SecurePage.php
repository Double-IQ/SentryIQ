<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();

$csrf = sentryiq_csrf_token();
$dataDirectory = sentryiq_data_dir();
$b2Configured = false;
if (is_string($dataDirectory) && $dataDirectory !== '') {
    require_once dirname(__DIR__, 2) . '/cloud/Gallery/Storage/BackblazeB2Signer.php';
    try {
        \SentryIQCloud\Gallery\Storage\BackblazeB2Signer::fromRuntimeDirectory($dataDirectory);
        $b2Configured = true;
    } catch (Throwable) {
        $b2Configured = false;
    }
}
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
<style>
.secure-gallery{max-width:1040px;margin:22px auto;font-family:Arial,sans-serif}
.secure-gallery-panel{padding:18px;margin:16px 0;border:1px solid #e3e6f0;border-radius:12px;background:#fff}
.secure-gallery-panel h2,.secure-gallery-panel h3{margin-top:0}
.secure-gallery-status{min-height:22px;margin:12px 0;color:#555;font-size:14px}
.secure-gallery-status.error{color:#b02a37}
.secure-gallery-status.success{color:#176b3a}
.secure-gallery-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.secure-gallery-row input[type=file]{max-width:100%}
.secure-gallery-row input[type=text]{flex:1;min-width:180px}
.secure-gallery-recovery{width:100%;min-height:100px;padding:12px;border:1px solid #d9dee5;border-radius:8px;font-family:monospace;overflow-wrap:anywhere}
.secure-gallery-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;margin-top:16px}
.secure-gallery-card{min-width:0;padding:8px;border:1px solid #e9ecef;border-radius:10px;background:#fff}
.secure-gallery-card img{display:block;width:100%;aspect-ratio:1/1;object-fit:cover;border-radius:6px;background:#f4f5f7;cursor:pointer}
.secure-gallery-card strong{display:block;margin-top:8px;font-size:13px;overflow-wrap:anywhere}
.secure-gallery-card small{display:block;margin-top:3px;color:#6c757d;overflow-wrap:anywhere}
.secure-gallery-card button{width:100%;margin-top:8px}
.secure-gallery-viewer{position:fixed;inset:0;z-index:3000;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,.9)}
.secure-gallery-viewer[hidden]{display:none}
.secure-gallery-viewer img{max-width:100%;max-height:calc(100vh - 90px);object-fit:contain}
.secure-gallery-viewer button{position:absolute;top:14px;right:14px}
.secure-gallery-actions{display:flex;gap:8px;flex-wrap:wrap}
@media(max-width:600px){.secure-gallery-grid{grid-template-columns:repeat(3,minmax(0,1fr));gap:5px}.secure-gallery-card{padding:3px;border:0}.secure-gallery-card small{font-size:10px}.secure-gallery-card strong{font-size:11px}.secure-gallery-card button{font-size:11px;padding:6px 4px}}
</style>
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
        <button class="tab-btn" type="button" onclick="window.location.href='index.php?pane=view'">📋 Vault</button>
        <button class="tab-btn" type="button" onclick="window.location.href='documents.php'">📄 Docs</button>
        <button class="tab-btn active" type="button">🖼️ Gallery</button>
        <button class="tab-btn" type="button" onclick="window.location.href='index.php?pane=settings'">⚙️ System</button>
    </div>

    <main class="secure-gallery" data-b2-configured="<?php echo $b2Configured ? 1 : 0; ?>">
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
            <div class="secure-gallery-actions" style="margin-top:10px;">
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
            <div class="secure-gallery-row" style="justify-content:space-between;">
                <h2 style="margin-bottom:0;">Your private photos</h2>
                <div class="secure-gallery-actions">
                    <button id="secure-gallery-add-passkey" class="btn" type="button">Add this passkey</button>
                    <button id="secure-gallery-lock" class="btn" type="button">Lock Gallery</button>
                </div>
            </div>
            <p>Image resizing, thumbnails, previews and encryption happen locally in your browser. Only encrypted objects are uploaded to Backblaze.</p>
            <div id="secure-gallery-b2-warning" class="secure-gallery-status error" <?php if ($b2Configured) echo 'hidden'; ?>>Backblaze B2 is not configured. Follow docs/operations/backblaze-b2-gallery-setup.md to add the protected runtime credentials file before uploading photos.</div>
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
<script src="assets/js/gallery_secure_ui.js"></script>
</body>
</html>
