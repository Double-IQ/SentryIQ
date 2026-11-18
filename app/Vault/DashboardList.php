<?php
// Categories and folders live in the encrypted system_config record. Read the vault once
// before normalizing records, because normalization removes system_config rows.
$vaultCategories = [];
$vaultFolders = [];
$rawVaultRecords = is_array($passwords ?? null) ? $passwords : [];

foreach ($rawVaultRecords as $vaultConfigRow) {
    if (($vaultConfigRow['type'] ?? '') !== 'system_config') continue;
    if (is_array($vaultConfigRow['categories'] ?? null)) {
        $vaultCategories = array_values(array_unique(array_filter(array_map(static fn($value): string => trim((string)$value), $vaultConfigRow['categories']), static fn(string $value): bool => $value !== '')));
    }
    if (is_array($vaultConfigRow['folders'] ?? null)) {
        foreach ($vaultConfigRow['folders'] as $folderCategory => $folderList) {
            if (!is_string($folderCategory) || !is_array($folderList)) continue;
            $cleanFolders = array_values(array_unique(array_filter(array_map(static fn($value): string => trim((string)$value), $folderList), static fn(string $value): bool => $value !== '')));
            if ($cleanFolders !== []) $vaultFolders[$folderCategory] = $cleanFolders;
        }
    }
    break;
}
if ($vaultCategories === [] && is_array($systemConfig ?? null) && is_array($systemConfig['categories'] ?? null)) {
    $vaultCategories = array_values(array_unique(array_filter(array_map(static fn($value): string => trim((string)$value), $systemConfig['categories']), static fn(string $value): bool => $value !== '')));
}
if ($vaultFolders === [] && is_array($systemConfig ?? null) && is_array($systemConfig['folders'] ?? null)) {
    foreach ($systemConfig['folders'] as $folderCategory => $folderList) {
        if (!is_string($folderCategory) || !is_array($folderList)) continue;
        $cleanFolders = array_values(array_unique(array_filter(array_map(static fn($value): string => trim((string)$value), $folderList), static fn(string $value): bool => $value !== '')));
        if ($cleanFolders !== []) $vaultFolders[$folderCategory] = $cleanFolders;
    }
}
$passwords = normalize_vault_records($rawVaultRecords);
// Preserve the authoritative category/folder metadata from the decrypted records.
// The normalizer may omit folder metadata from its presentation shape.
$rawLocationById = [];
$rawLocationByIdentity = [];
foreach ($rawVaultRecords as $rawRow) {
    if (($rawRow['type'] ?? '') === 'system_config') continue;
    $rawId = trim((string)($rawRow['id'] ?? ''));
    $location = [
        'category' => trim((string)($rawRow['category'] ?? '')),
        'folder' => trim((string)($rawRow['folder'] ?? '')),
    ];
    if ($rawId !== '') $rawLocationById[$rawId] = $location;
    // Some legacy normalization paths do not carry the record id through.
    $identity = implode("\x1f", [
        trim((string)($rawRow['label'] ?? '')),
        trim((string)($rawRow['username'] ?? '')),
        trim((string)($rawRow['url'] ?? '')),
    ]);
    if ($identity !== "\x1f\x1f") $rawLocationByIdentity[$identity] = $location;
}
foreach ($passwords as $normalizedIndex => $normalizedRow) {
    $normalizedId = trim((string)($normalizedRow['id'] ?? ''));
    $location = $normalizedId !== '' && isset($rawLocationById[$normalizedId]) ? $rawLocationById[$normalizedId] : null;
    if ($location === null) {
        $identity = implode("\x1f", [
            trim((string)($normalizedRow['label'] ?? '')),
            trim((string)($normalizedRow['username'] ?? '')),
            trim((string)($normalizedRow['url'] ?? '')),
        ]);
        $location = $rawLocationByIdentity[$identity] ?? null;
    }
    if ($location !== null) {
        $passwords[$normalizedIndex]['category'] = $location['category'];
        $passwords[$normalizedIndex]['folder'] = $location['folder'];
    }
}
$passwords = array_values(array_filter($passwords, static fn(array $row): bool => ($row['type'] ?? '') !== 'system_config'));
$activeVaultView = trim((string)($_GET['vault_view'] ?? 'records'));
$activeVaultFolder = trim((string)($_GET['vault_folder'] ?? ''));
if ($activeVaultView !== 'records' && !in_array($activeVaultView, $vaultCategories, true)) $activeVaultView = 'records';
$activeCategoryFolders = [];
if ($activeVaultView !== 'records') {
    foreach ($vaultFolders as $folderCategory => $folderList) {
        $folderCategoryKey = function_exists('mb_strtolower') ? mb_strtolower($folderCategory, 'UTF-8') : strtolower($folderCategory);
        $activeCategoryKey = function_exists('mb_strtolower') ? mb_strtolower($activeVaultView, 'UTF-8') : strtolower($activeVaultView);
        if ($folderCategoryKey === $activeCategoryKey) {
            $activeCategoryFolders = $folderList;
            break;
        }
    }
}
?>
<!-- Location: /home/bicheveb/public_html/pm/dashboard_list.php -->
<div class="sentryiq-page-header">
    <div class="sentryiq-vault-brand-wrap"><img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ"><span class="sentryiq-vault-status" data-vault-status><?php echo htmlspecialchars($activeVaultView === 'records' ? 'Records' : $activeVaultView, ENT_QUOTES, 'UTF-8'); ?></span></div>
    <div class="sentryiq-mobile-header-actions">
        <form method="POST" class="sentryiq-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf ?? '', ENT_QUOTES, 'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button></form>
        <div class="vault-mobile-menu-bar"><button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu"><span class="vault-mobile-menu-icon" aria-hidden="true">☰</span><span id="vault-mobile-menu-label" class="visually-hidden">Menu</span></button></div>
    </div>
</div>
<?php if (isset($_GET['status']) && $_GET['status'] == 'saved') echo "<p class='success'>Entry stored successfully!</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] == 'updated') echo "<p class='success'>Entry updated successfully!</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] == 'deleted') echo "<p class='success'>Entry deleted safely from disk.</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] == 'category_added') echo "<p class='success'>Category added successfully.</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] == 'folder_added') echo "<p class='success'>Folder added successfully.</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] == 'error') echo "<p class='error'>The requested vault operation could not be completed.</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] === 'validation' && ($_GET['field'] ?? '') === 'url') echo "<p class='error'>Please enter a valid HTTPS URL, or leave the URL field blank.</p>"; ?>
<?php if (isset($_GET['status']) && $_GET['status'] === 'validation' && ($_GET['field'] ?? '') === 'required') echo "<p class='error'>Please complete the required fields before saving.</p>"; ?>

<div id="vault-mobile-menu" class="vault-tabs">
    <button id="view-btn" class="tab-btn active" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button>
    <button id="docs-btn" class="tab-btn" type="button" data-sentryiq-nav="documents.php">📄 Docs</button>
    <button id="gallery-btn" class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button>
    <button id="settings-btn" class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button>
    <form method="POST" class="vault-menu-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf ?? '', ENT_QUOTES, 'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button></form>
    <button id="details-btn" class="tab-btn" style="display:none;" data-vault-tab="details">👁️ Entry Inspection</button>
</div>

<?php if ($active_pane === 'view'): ?>
<div id="view-panel" class="vault-panel active">
    <div class="vault-category-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:8px;">
        <?php foreach ($vaultCategories as $category): ?>
            <a href="index.php?pane=records&amp;vault_view=<?php echo rawurlencode($category); ?>" class="btn" style="display:flex;align-items:center;justify-content:center;min-height:58px;text-decoration:none;background:#f1f3f5;color:#212529;border:1px solid #dee2e6;font-size:16px;">📁 <?php echo htmlspecialchars($category, ENT_QUOTES, 'UTF-8'); ?></a>
        <?php endforeach; ?>
        <div class="vault-add-category-wrap" style="display:flex;align-items:center;min-height:58px;">
            <button type="button" id="show-add-category" class="btn" data-vault-action="show-add-category" style="width:100%;min-height:42px;background:#f1f3f5;color:#212529;border:1px solid #dee2e6;font-size:16px;">＋ Add Category</button>
            <form id="add-category-form" method="POST" action="vault_category_actions.php" style="display:none;width:100%;flex-direction:column;align-items:stretch;gap:8px;margin:0;">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                <input type="hidden" name="action" value="add_category">
                <input type="text" id="new-category-name" name="category" class="input-field" placeholder="Category name" maxlength="50" required style="width:100%;min-width:0;flex:0 0 auto;margin:0;">
                <div class="vault-add-category-actions" style="display:flex;gap:8px;width:100%;">
                    <button type="submit" class="btn" style="height:42px;flex:1;white-space:nowrap;background:#f1f3f5;color:#212529;border:1px solid #dee2e6;font-size:16px;">Add</button>
                    <button type="button" class="btn" data-vault-action="hide-add-category" style="height:42px;flex:1;white-space:nowrap;background:#fff;color:#495057;border:1px solid #dee2e6;font-size:16px;">Cancel</button>
                </div>
            </form>
        </div>
    </div>
</div>
<?php endif; ?>

<?php if ($active_pane === 'records'): ?>
<div id="records-panel" class="vault-panel active" data-vault-title="<?php echo htmlspecialchars($activeVaultView === 'records' ? 'Records' : $activeVaultView, ENT_QUOTES, 'UTF-8'); ?>">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
        <a href="index.php?pane=view" class="btn" style="background:#f1f3f5;color:#212529;border:1px solid #dee2e6;text-decoration:none;">← Vault</a>
        <h3 style="margin:0;color:#212529;">📁 <?php echo htmlspecialchars($activeVaultView === 'records' ? 'Records' : $activeVaultView, ENT_QUOTES, 'UTF-8'); ?></h3>
        <?php if ($activeVaultView !== 'records'): ?>
            <button type="button" class="btn" data-vault-action="show-create-folder" style="background:#f1f3f5;color:#212529;border:1px solid #dee2e6;">📁 Create Folder</button>
        <?php endif; ?>
        <a href="index.php?pane=add&amp;vault_view=<?php echo rawurlencode($activeVaultView); ?><?php echo $activeVaultFolder !== '' ? '&amp;vault_folder=' . rawurlencode($activeVaultFolder) : ''; ?>" class="btn btn-primary vault-add-record-button" style="text-decoration:none;"><span class="vault-add-record-icon" aria-hidden="true">+</span> Add Vault Record</a>
    </div>
    <?php if ($activeVaultView !== 'records' && $activeVaultFolder === ''): ?>
        <form id="create-folder-form" method="POST" action="vault_category_actions.php" style="display:none;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 16px;padding:12px;background:#f8f9fa;border:1px solid #e3e6f0;border-radius:8px;">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf ?? '', ENT_QUOTES, 'UTF-8'); ?>">
            <input type="hidden" name="action" value="create_folder">
            <input type="hidden" name="category" value="<?php echo htmlspecialchars($activeVaultView, ENT_QUOTES, 'UTF-8'); ?>">
            <input type="text" id="new-folder-name" name="folder" class="input-field" placeholder="Folder name" maxlength="50" required style="flex:1 1 220px;width:auto;min-width:0;margin:0;">
            <button type="submit" class="btn btn-primary" style="white-space:nowrap;">Create Folder</button>
            <button type="button" class="btn" data-vault-action="hide-create-folder" style="background:#fff;color:#495057;border:1px solid #dee2e6;white-space:nowrap;">Cancel</button>
        </form>
        <?php if ($activeVaultFolder === '' && $activeCategoryFolders !== []): ?>
            <div class="vault-folder-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;margin:0 0 18px;">
                <?php foreach ($activeCategoryFolders as $folder): ?>
                    <a href="index.php?pane=records&amp;vault_view=<?php echo rawurlencode($activeVaultView); ?>&amp;vault_folder=<?php echo rawurlencode($folder); ?>" class="vault-folder-card" style="display:flex;align-items:center;gap:10px;padding:14px 16px;background:#fff;border:1px solid #e3e6f0;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.03);text-decoration:none;"><span aria-hidden="true" style="font-size:22px;">📁</span><span style="font-weight:600;color:#212529;overflow-wrap:anywhere;"><?php echo htmlspecialchars($folder, ENT_QUOTES, 'UTF-8'); ?></span></a>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
    <?php $visiblePasswords = $activeVaultView === 'records' ? [] : array_values(array_filter($passwords, static function (array $row) use ($activeVaultView, $activeVaultFolder): bool {
        if (trim((string)($row['category'] ?? '')) !== $activeVaultView) return false;
        $rowFolder = trim((string)($row['folder'] ?? ''));
        if ($activeVaultFolder !== '') {
            if ($rowFolder !== $activeVaultFolder) return false;
        } elseif ($rowFolder !== '') {
            // Folder records belong to their folder view, not the category-level record list.
            return false;
        }
        return true;
    })); ?>
    <?php if (empty($visiblePasswords)): ?>
        <p id="vault-empty-message" style="text-align:center;padding:20px;color:#777;"><?php echo $activeVaultView === 'records' ? 'Select a category from the Vault.' : 'No records in this category yet.'; ?></p>
    <?php else: ?>
        <div id="vault-record-grid" class="vault-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px;margin-top:15px;">
            <?php foreach ($visiblePasswords as $row):
                $label = $row['label'] ?? 'Vault';
                $category = trim((string)($row['category'] ?? ''));
                $hash = md5($label);
                $cardGradient = "linear-gradient(to bottom right, hsla(214.47, 42.86%, 39.85%, 1) 4.62%, hsla(229.79, 18.54%, 43.26%, 0.7))";
                $words = explode(' ', trim(preg_replace('/[^a-zA-Z0-9 ]/', '', $label)));
                $initials = strtoupper(substr($words[0] ?? 'V', 0, 1) . (isset($words[1]) ? substr($words[1], 0, 1) : ''));
                $hasStoredIcon = !empty($row['icon_path']) && !empty($row['id']);
                $inspectArgs = [$label,$row['username'] ?? '',$row['password'] ?? '',$row['url'] ?? '',$row['notes'] ?? '',(string)($row['id'] ?? ''),$category,trim((string)($row['folder'] ?? ''))];
                $inspectJson = htmlspecialchars(json_encode($inspectArgs, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8');
            ?>
                <div class="entry-card vault-record-card" data-vault-category="<?php echo htmlspecialchars($category, ENT_QUOTES, 'UTF-8'); ?>" tabindex="0" role="button" aria-label="Inspect <?php echo htmlspecialchars($label); ?>" data-vault-record="<?php echo $inspectJson; ?>" style="background:#fff;border:1px solid #e9ecef;border-radius:12px;overflow:hidden;display:flex;flex-direction:column;justify-content:space-between;box-shadow:0 4px 6px rgba(0,0,0,.02);position:relative;">
                    <div class="og-preview-holder" style="height:100px;background:<?php echo $cardGradient; ?>;display:flex;align-items:center;justify-content:center;overflow:hidden;position:relative;">
                        <?php if ($hasStoredIcon): ?><img src="vault-icon.php?id=<?php echo rawurlencode((string)$row['id']); ?>" style="width:36px;height:36px;object-fit:contain;position:relative;z-index:2;filter:drop-shadow(0 4px 6px rgba(0,0,0,.15));" alt="Stored website icon" data-icon-fallback="1"><span style="display:none;color:#fff;font-size:28px;font-weight:700;font-family:monospace;opacity:.3;" aria-hidden="true"><?php echo htmlspecialchars($initials); ?></span>
                        <?php else: ?><span style="color:#fff;font-size:28px;font-weight:700;font-family:monospace;opacity:.3;" aria-hidden="true"><?php echo htmlspecialchars($initials); ?></span><?php endif; ?>
                    </div>
                    <div class="entry-card-identity" style="padding:12px 15px 4px;"><span class="entry-label" style="font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;color:#212529;"><?php echo htmlspecialchars($label); ?></span><small style="color:#868e96;font-size:11px;display:block;overflow:hidden;text-overflow:ellipsis;"><?php echo htmlspecialchars($row['username'] ?? '[No Username]'); ?></small></div>
                    <div class="entry-card-actions" style="padding:12px;"><button type="button" class="btn btn-primary inspect-button" style="width:100%;padding:8px 0;font-size:12px;border-radius:6px;background:#0066cc;">👁️ Inspect</button></div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>
<?php endif; ?>

<script src="assets/js/vault_dashboard.js" defer></script>