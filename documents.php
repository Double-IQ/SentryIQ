<?php

declare(strict_types=1);

require_once __DIR__ . '/security_bootstrap.php';
sentryiq_security_bootstrap();
sentryiq_require_auth();
require_once __DIR__ . '/cloud/Documents/DocumentStore.php';
use SentryIQCloud\Documents\DocumentStore;

$config = is_file(__DIR__ . '/sentryiq_config.php') ? require __DIR__ . '/sentryiq_config.php' : null;
if (!is_array($config)) { http_response_code(503); exit('SentryIQ configuration is unavailable.'); }
$dataDir = rtrim((string)($config['data_dir'] ?? ''), '/');
if ($dataDir === '' || !str_starts_with($dataDir, '/') || !is_dir($dataDir) || is_link($dataDir)) { http_response_code(503); exit('SentryIQ secure runtime is unavailable.'); }

$store = new DocumentStore($dataDir . '/documents/metadata.json');
$documents = [];
foreach ($store->all() as $id => $item) {
    if (!preg_match('/^[a-f0-9]{32}$/', (string)$id) || !is_array($item)) continue;
    $filename = (string)($item['filename'] ?? '');
    if (!preg_match('/^[a-f0-9]{32}\.[a-z0-9]+$/', $filename)) continue;
    $path = $dataDir . '/documents/files/' . $filename;
    if (!is_file($path) || is_link($path)) continue;
    $documents[] = ['id'=>$id, 'name'=>(string)($item['original_name'] ?? 'Document'), 'mime'=>(string)($item['mime'] ?? 'application/octet-stream'), 'extension'=>(string)($item['extension'] ?? ''), 'size'=>(int)($item['size'] ?? filesize($path)), 'created_at'=>(int)($item['created_at'] ?? filemtime($path))];
}
usort($documents, static fn(array $a,array $b): int => $b['created_at'] <=> $a['created_at']);
$csrf = sentryiq_csrf_token();

function docs_icon(string $extension): string {
    return match (strtolower($extension)) {
        'pdf' => '📕', 'doc','docx','odt','rtf' => '📘', 'xls','xlsx','ods','csv' => '📗', 'ppt','pptx','odp' => '📙', 'txt' => '📄', default => '📎'
    };
}
function docs_size(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return number_format($bytes / 1024, 1) . ' KB';
    if ($bytes < 1073741824) return number_format($bytes / 1048576, 1) . ' MB';
    return number_format($bytes / 1073741824, 2) . ' GB';
}
?>
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="icon" type="image/png" sizes="32x32" href="sentryiq-icon.php?size=32">
<link rel="icon" type="image/png" sizes="16x16" href="sentryiq-icon.php?size=16">
<link rel="apple-touch-icon" sizes="180x180" href="sentryiq-icon.php?size=180">
<meta property="og:site_name" content="SentryIQ">
<meta property="og:type" content="website">
<meta property="og:title" content="SentryIQ Documents">
<meta property="og:description" content="SentryIQ Documents — private personal document storage.">
<meta property="og:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php">
<meta property="og:image:type" content="image/png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="1200">
<meta property="og:image:alt" content="SentryIQ">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="SentryIQ Documents">
<meta name="twitter:description" content="SentryIQ Documents — private personal document storage.">
<meta name="twitter:image" content="https://bichet.co.za/SentryIQ/sentryiq-og.php"><meta name="csrf-token" content="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><title>SentryIQ Documents</title><link rel="stylesheet" href="assets/css/sentryiq.css"><style>
.docs-upload{margin-top:24px;padding:18px;border:1px solid #e9ecef;border-radius:12px;background:#fafbfc}.docs-file-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:8px 0 12px}.docs-file-input{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.docs-file-label{display:inline-flex;align-items:center;justify-content:center;padding:9px 14px;border:1px solid #0066cc;border-radius:8px;background:#0066cc;color:#fff;font-size:14px;font-weight:600;cursor:pointer}.docs-file-name{font-size:13px;color:#6c757d;min-width:0;word-break:break-word}.docs-list{margin-top:20px;border:1px solid #e9ecef;border-radius:12px;overflow:hidden;background:#fff}.docs-row{display:grid;grid-template-columns:48px minmax(0,1fr) auto;gap:14px;align-items:center;padding:14px 16px;border-bottom:1px solid #eef0f2}.docs-row:last-child{border-bottom:0}.docs-icon{font-size:28px;text-align:center}.docs-name{font-size:14px;font-weight:600;color:#212529;word-break:break-word}.docs-meta{margin-top:3px;font-size:12px;color:#777}.docs-actions{display:flex;align-items:center;gap:7px}.docs-action{display:inline-flex;align-items:center;justify-content:center;padding:7px 10px;border:1px solid #d9dee5;border-radius:7px;background:#fff;color:#212529;text-decoration:none;font-size:13px;cursor:pointer}.docs-delete{border-color:#dc3545;color:#dc3545}.docs-empty{text-align:center;padding:44px 20px;color:#777}.docs-message{margin-top:12px}.docs-note{margin:0;color:#6c757d;font-size:13px;line-height:1.5}@media(max-width:600px){.docs-file-row{flex-direction:column;align-items:stretch}.docs-file-label,.docs-upload .btn{width:100%;box-sizing:border-box}.docs-file-name{text-align:center}.docs-list{border-radius:10px}.docs-row{grid-template-columns:38px minmax(0,1fr);gap:10px;padding:13px 12px}.docs-actions{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:7px}.docs-action{min-height:36px;box-sizing:border-box}.docs-icon{font-size:24px}}
</style></head><body><div class="box">
<div class="sentryiq-page-header"><div class="sentryiq-vault-brand-wrap"><img class="sentryiq-vault-banner" src="assets/images/sentryiq-logo-wide.webp" width="1952" height="588" alt="SentryIQ"><span class="sentryiq-vault-status">Docs</span></div><div class="sentryiq-mobile-header-actions"><form method="POST" class="sentryiq-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="btn btn-primary sentryiq-lock-button">Lock Vault</button></form><div class="vault-mobile-menu-bar"><button type="button" class="vault-mobile-menu-toggle" aria-expanded="false" aria-controls="vault-mobile-menu"><span class="vault-mobile-menu-icon" aria-hidden="true">☰</span><span>Menu</span></button></div></div></div>
<div id="vault-mobile-menu" class="vault-tabs"><button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=view">📋 Vault</button><button class="tab-btn active" type="button">📄 Docs</button><button class="tab-btn" type="button" data-sentryiq-nav="gallery.php">🖼️ Gallery</button><button class="tab-btn" type="button" data-sentryiq-nav="index.php?pane=settings">⚙️ System</button><form method="POST" class="vault-menu-lock-form"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="lock_vault" value="1"><button type="submit" class="tab-btn vault-menu-lock-button">🔒 Lock Vault</button></form></div>
<div class="docs-upload"><h3 style="margin-top:0;">Upload Documents</h3><p class="docs-note">Documents are stored outside the public web root. SentryIQ keeps the original file intact.</p><form method="POST" action="document_upload.php" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><div class="docs-file-row"><label class="docs-file-label" for="docs-input">📄 Choose Documents</label><input class="docs-file-input" id="docs-input" type="file" name="documents[]" multiple required accept=".pdf,.txt,.csv,.rtf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.odt,.ods,.odp"><span id="docs-file-name" class="docs-file-name">No documents selected</span><button type="submit" class="btn btn-primary">Upload Documents</button></div></form><?php if(isset($_GET['status'])): ?><div class="docs-message <?php echo $_GET['status']==='error'?'error':'success'; ?>"><?php echo $_GET['status']==='uploaded' ? 'Documents uploaded successfully.' : ($_GET['status']==='partial' ? 'Some documents were uploaded; one or more files were rejected.' : ($_GET['status']==='deleted' ? 'Document deleted safely from disk.' : 'The document operation could not be completed.')); ?></div><?php endif; ?></div>
<div class="docs-list"><?php if($documents===[]): ?><div class="docs-empty">No documents in the vault yet.</div><?php else: foreach($documents as $doc): ?><div class="docs-row"><div class="docs-icon" aria-hidden="true"><?php echo docs_icon($doc['extension']); ?></div><div><div class="docs-name"><?php echo htmlspecialchars($doc['name'],ENT_QUOTES,'UTF-8'); ?></div><div class="docs-meta"><?php echo htmlspecialchars(strtoupper($doc['extension'] ?: 'FILE')); ?> · <?php echo htmlspecialchars(docs_size($doc['size'])); ?> · <?php echo htmlspecialchars(date('Y-m-d H:i',$doc['created_at'])); ?></div></div><div class="docs-actions"><a class="docs-action" href="document_download.php?id=<?php echo rawurlencode($doc['id']); ?>" target="_blank" rel="noopener">View / Download</a><form method="POST" action="document_delete.php" data-confirm-submit="Delete this document permanently?"><input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf,ENT_QUOTES,'UTF-8'); ?>"><input type="hidden" name="id" value="<?php echo htmlspecialchars($doc['id'],ENT_QUOTES,'UTF-8'); ?>"><button class="docs-action docs-delete" type="submit">Delete</button></form></div></div><?php endforeach; endif; ?></div>
</div><script src="assets/js/documents.js" defer></script></body></html>
