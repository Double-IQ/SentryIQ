<!-- PANEL SECTION 2: DETAIL INSPECTOR -->
<div id="details-panel" class="vault-panel">
    <div class="detail-card">
        <h3 id="det-title" class="vault-actions-inline-1">Vault Record Profile</h3>
        <div class="vault-actions-inline-2"><img id="det-icon" src="" alt="Stored website icon" class="vault-actions-inline-3"></div>
        <div class="detail-row"><span class="detail-label">Resource Label:</span><span id="det-label" class="detail-value"></span></div>
        <div class="detail-row"><span class="detail-label">Stored Username / User ID:</span><span id="det-username" class="detail-value"></span></div>
        <div class="detail-row"><span class="detail-label">Encrypted Password String:</span><span id="det-password" class="detail-value secret-badge" class="vault-actions-inline-4" title="Click to copy to clipboard" data-vault-action="copy-secret"></span></div>
        <div class="detail-row"><span class="detail-label">Destination Web URL Link:</span><a id="det-url" href="#" target="_blank" class="detail-value" class="vault-actions-inline-5"></a></div>
        <div class="detail-row"><span class="detail-label">Folder:</span><span id="det-folder" class="detail-value"></span></div><div class="detail-row"><span class="detail-label">Notes:</span><span id="det-notes" class="detail-value" class="vault-actions-inline-6"></span></div>
        <div class="vault-actions-inline-7"><button type="button" id="det-back-list" class="btn" class="vault-actions-inline-8" data-vault-action="return-to-list">← Back to List</button><button type="button" class="btn" class="vault-actions-inline-9" data-vault-action="prepare-edit">✏️ Edit Record</button><form method="POST" action="record_actions.php" data-confirm-submit="Are you sure you want to delete this record completely out of your secure database?" class="vault-actions-inline-10"><input type="hidden" name="action" value="delete"><input type="hidden" name="entry_id" id="det-delete-id" value=""><button type="submit" class="btn btn-danger">🗑️ Delete</button></form></div>
    </div>
</div>

<!-- PANEL SECTION 3: ADD NEW RECORD PANEL -->
<div id="add-panel" class="vault-panel <?php echo ($active_pane === 'add') ? 'active' : ''; ?>"><div class="form-box"><h3>Create New Vault Entry</h3><form method="POST" action="vault_actions.php"><input type="hidden" name="action" value="add"><input type="hidden" name="category" value="<?php echo htmlspecialchars($activeVaultView !== 'records' ? $activeVaultView : '', ENT_QUOTES, 'UTF-8'); ?>"><input type="hidden" name="vault_folder_context" value="<?php echo htmlspecialchars($activeVaultFolder, ENT_QUOTES, 'UTF-8'); ?>"><?php if ($activeVaultFolder !== ''): ?><input type="hidden" name="folder" value="<?php echo htmlspecialchars($activeVaultFolder, ENT_QUOTES, 'UTF-8'); ?>"><?php elseif ($activeVaultView !== 'records' && $activeCategoryFolders !== []): ?><div class="form-group"><label>Folder:</label><select name="folder" class="input-field"><option value="">Category level (no folder)</option><?php foreach ($activeCategoryFolders as $folderOption): ?><option value="<?php echo htmlspecialchars($folderOption, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($folderOption, ENT_QUOTES, 'UTF-8'); ?></option><?php endforeach; ?></select></div><?php else: ?><input type="hidden" name="folder" value=""><?php endif; ?><div class="form-group"><label>Resource Label:</label><input type="text" name="label" placeholder="e.g. Personal Email" class="input-field" required></div><div class="form-group"><label>Username / Login ID:</label><input type="text" name="username" class="input-field"></div><div class="form-group"><label>Resource Password:</label><input type="text" name="password" class="input-field" required></div><div class="form-group"><label>Destination Web URL Address:</label><input type="url" name="url" placeholder="https://..." class="input-field"><small class="field-hint" class="vault-actions-inline-11">HTTPS only. Leave blank if this entry has no web address.</small></div><div class="form-group"><label>Notes:</label><textarea name="notes" class="input-field" rows="5" placeholder="Optional notes about this resource"></textarea></div><button type="submit" name="add_entry" class="btn btn-primary" class="vault-actions-inline-12">💾 Save Secure Entry</button></form></div></div>

<!-- PANEL SECTION 4: SYSTEM PANEL -->
<div id="settings-panel" class="vault-panel <?php echo ($active_pane === 'settings') ? 'active' : ''; ?>">
    <?php if (($_GET['tool'] ?? '') === 'application'): ?>
    <div class="application-settings-back" class="vault-actions-inline-13">
        <a href="index.php?pane=settings" class="btn" class="vault-actions-inline-14">← System Settings</a>
    </div>
    <?php endif; ?>
    <div class="form-box">
        <div class="vault-actions-inline-15">
            <h3 class="vault-actions-inline-16">⚙️ Application Settings</h3>
        </div>
        <form method="POST">
            <div class="form-group"><label>Application Username:</label><input type="text" name="app_username" class="input-field" value="<?php echo htmlspecialchars($sys_user); ?>" required></div>
            <div class="form-group"><label>2FA Target Email Delivery Address:</label><input type="email" name="two_fa_email_field" class="input-field" value="<?php echo htmlspecialchars($sys_email); ?>" required></div>
            <div class="form-group"><label>IMAP Password (Optional Update):</label><input type="password" name="imap_password_field" class="input-field" placeholder="Leave blank to preserve current settings"></div>
            <div class="form-group"><label>Application HTTPS URL:</label><input type="url" name="base_url_field" class="input-field" value="<?php echo htmlspecialchars((string)($config['base_url'] ?? '')); ?>" required><small class="vault-actions-inline-11">Trusted HTTPS URL used for security-sensitive 2FA links.</small></div>
            <div class="form-group"><label>Vault Data Directory:</label><input type="text" name="data_directory" class="input-field" value="<?php echo htmlspecialchars(SENTRYIQ_DATA_DIR); ?>" required><small class="vault-actions-inline-11">Must be an absolute directory outside the public web root. Existing vault data is copied before the new location is activated.</small></div>
            <button type="submit" name="save_vault_settings" class="btn btn-primary" class="vault-actions-inline-12">🔄 Save System Settings</button>
        </form>
    </div>

    <div class="form-box" class="vault-actions-inline-17">
        <h3>🔑 Passkeys</h3>
        <p class="vault-actions-inline-18">Manage the devices that can unlock your SentryIQ vault with Face ID, Touch ID, or passkey authentication.</p>
        <?php
        $passkeyStore = [];
        $passkeyDataDir = sentryiq_data_dir();
        if ($passkeyDataDir !== '') {
            $passkeyPath = $passkeyDataDir . '/passkeys.json';
            if (is_file($passkeyPath) && !is_link($passkeyPath)) {
                $passkeyRaw = @file_get_contents($passkeyPath);
                $passkeyDecoded = is_string($passkeyRaw) ? json_decode($passkeyRaw, true) : null;
                if (is_array($passkeyDecoded)) $passkeyStore = $passkeyDecoded;
            }
        }
        $passkeyCredentials = is_array($passkeyStore['credentials'] ?? null) ? $passkeyStore['credentials'] : [];
        ?>
        <div id="passkey-message" class="vault-actions-inline-19"></div>
        <?php if (empty($passkeyCredentials)): ?>
            <div class="vault-actions-inline-20">No passkeys are registered yet.</div>
        <?php else: ?>
            <?php foreach ($passkeyCredentials as $index => $credential): $created = (int)($credential['created_at'] ?? 0); $label = 'Passkey ' . ($index + 1); $credentialId = (string)($credential['credential_id'] ?? ''); ?>
                <div class="vault-actions-inline-21"><div class="vault-actions-inline-22"><strong><?php echo htmlspecialchars($label, ENT_QUOTES, 'UTF-8'); ?></strong><div class="vault-actions-inline-23">Added <?php echo $created > 0 ? htmlspecialchars(date('j M Y, H:i', $created), ENT_QUOTES, 'UTF-8') : 'date unavailable'; ?></div><div class="vault-actions-inline-24">Credential: <?php echo htmlspecialchars(substr($credentialId, 0, 18) . (strlen($credentialId) > 18 ? '…' : ''), ENT_QUOTES, 'UTF-8'); ?></div></div><button type="button" class="btn btn-primary remove-passkey" data-credential="<?php echo htmlspecialchars($credentialId, ENT_QUOTES, 'UTF-8'); ?>" <?php echo count($passkeyCredentials) <= 1 ? 'disabled title="Keep at least one passkey registered"' : ''; ?>>Remove</button></div>
            <?php endforeach; ?>
        <?php endif; ?>
        <div class="vault-actions-inline-25"><h4 class="vault-actions-inline-26">Add another device</h4><p class="vault-actions-inline-27">Register another passkey on your phone, Mac, tablet, or another trusted device. Each passkey gets its own protected copy of your existing vault key.</p><a href="passkey_setup.php?add=1" class="btn btn-primary" class="vault-actions-inline-28">＋ Add Another Passkey</a></div>
        <p class="vault-actions-inline-29">SentryIQ will not let you remove the last registered passkey. If you lose access to a device, use the password recovery route to regain access and register a replacement passkey.</p>
    </div>

    <div class="form-box" class="vault-actions-inline-17"><div class="vault-actions-inline-30"><h3 class="vault-actions-inline-16">🔐 System Log</h3><span class="vault-actions-inline-31"><?php echo count(read_security_log()); ?> events</span></div><?php $securityEvents = read_security_log(); ?><?php if (empty($securityEvents)): ?><p class="vault-actions-inline-32">No security events have been recorded yet.</p><?php else: ?><div class="security-log-table" class="vault-actions-inline-33"><table class="vault-actions-inline-34"><thead><tr class="vault-actions-inline-35"><th class="vault-actions-inline-36">Date / Time</th><th class="vault-actions-inline-36">Event</th><th class="vault-actions-inline-36">User</th><th class="vault-actions-inline-36">IP Address</th><th class="vault-actions-inline-36">User Agent</th></tr></thead><tbody><?php foreach ($securityEvents as $event): ?><tr class="vault-actions-inline-37"><td class="vault-actions-inline-38"><?php echo htmlspecialchars($event['timestamp'] ?? ''); ?></td><td class="vault-actions-inline-39"><?php echo htmlspecialchars($event['event'] ?? ''); ?></td><td class="vault-actions-inline-36"><?php echo htmlspecialchars($event['username'] ?? 'unknown'); ?></td><td class="vault-actions-inline-36"><?php echo htmlspecialchars($event['ip'] ?? 'unknown'); ?></td><td class="vault-actions-inline-40"><?php echo htmlspecialchars($event['user_agent'] ?? 'unknown'); ?></td></tr><?php endforeach; ?></tbody></table></div><div class="security-log-list"><?php foreach ($securityEvents as $event): ?><div class="security-log-card"><div class="security-log-card-header"><span class="security-log-event"><?php echo htmlspecialchars($event['event'] ?? ''); ?></span><span class="security-log-time"><?php echo htmlspecialchars($event['timestamp'] ?? ''); ?></span></div><div class="security-log-field"><span class="security-log-label">User</span><span class="security-log-value"><?php echo htmlspecialchars($event['username'] ?? 'unknown'); ?></span></div><div class="security-log-field"><span class="security-log-label">IP Address</span><span class="security-log-value"><?php echo htmlspecialchars($event['ip'] ?? 'unknown'); ?></span></div><div class="security-log-field"><span class="security-log-label">User Agent</span><span class="security-log-value"><?php echo htmlspecialchars($event['user_agent'] ?? 'unknown'); ?></span></div></div><?php endforeach; ?></div><?php endif; ?></div>
</div>

<!-- PANEL SECTION 5: EDIT RECORD -->
<div id="edit-panel" class="vault-panel"><div class="form-box"><h3>📝 Modify Vault Entry Data</h3><form method="POST" action="record_actions.php"><input type="hidden" name="action" value="edit"><input type="hidden" name="entry_id" id="edit-entry-id"><div class="form-group"><label>Resource Label:</label><input type="text" name="label" id="edit-label" class="input-field" required></div><input type="hidden" name="category" id="edit-category" value="<?php echo htmlspecialchars($activeVaultView !== 'records' ? $activeVaultView : '', ENT_QUOTES, 'UTF-8'); ?>"><div class="form-group"><label>Folder:</label><select name="folder" id="edit-folder" class="input-field"><option value="">Category level (no folder)</option><?php foreach ($activeCategoryFolders as $folderOption): ?><option value="<?php echo htmlspecialchars($folderOption, ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($folderOption, ENT_QUOTES, 'UTF-8'); ?></option><?php endforeach; ?></select></div><div class="form-group"><label>Username / Login ID:</label><input type="text" name="username" id="edit-username" class="input-field"></div><div class="form-group"><label>Resource Password:</label><input type="text" name="password" id="edit-password" class="input-field" required></div><div class="form-group"><label>Destination Web URL Address:</label><input type="url" name="url" id="edit-url" class="input-field" placeholder="https://..."><small class="vault-actions-inline-11">HTTPS only. Leave blank if this entry has no web address.</small></div><div class="form-group"><label>Notes:</label><textarea name="notes" id="edit-notes" class="input-field" rows="5" placeholder="Optional notes about this resource"></textarea></div><div class="vault-actions-inline-41"><button type="submit" class="btn btn-primary">🔄 Update Record</button><button type="button" class="btn" class="vault-actions-inline-8" data-vault-action="cancel-edit">Cancel</button></div></form></div></div>

<script src="assets/js/vault_dashboard_actions.js" defer></script>