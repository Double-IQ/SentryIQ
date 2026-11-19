<?php
declare(strict_types=1);

function cspCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
require_once $root . '/app/Security/SecurityBootstrap.php';
$templates = [
    'index.php',
    'documents.php',
    'welcome.php',
    'app/Auth/PasskeyLogin.php',
    'app/Auth/PasskeySetup.php',
    'app/Vault/DashboardList.php',
    'app/Vault/DashboardActions.php',
    'app/Gallery/SecurePage.php',
    'gallery_b2_diagnostic.php',
    'diagnostics/self_test.php',
    'gallery_b2_settings.php',
    'storage.php',
    'update.php',
    'first_run.php',
    'gallery_storage.php',
    'diagnostics/vault_runtime_diagnostic.php',
    'sentryiq_diagnostic.php',
    'credits.php',
    'app/Auth/Passkeys.php',
    'app/Gallery/Settings.php',
    'app/Security/SystemLog.php',
    'diagnostics/copy-code.php',
];

foreach ($templates as $relativePath) {
    $path = $root . '/' . $relativePath;
    $source = file_get_contents($path);
    cspCheck(is_string($source), 'Unable to read CSP template: ' . $relativePath);

    preg_match_all('/<script\b([^>]*)>(.*?)<\/script\s*>/is', $source, $scripts, PREG_SET_ORDER);
    foreach ($scripts as $script) {
        $attributes = $script[1];
        $external = preg_match('/\bsrc\s*=/i', $attributes) === 1;
        $dataBlock = preg_match('/\btype\s*=\s*[^>]*application\/json/i', $attributes) === 1;
        cspCheck($external || $dataBlock, 'Inline executable script remains in ' . $relativePath);
    }

    cspCheck(
        preg_match('/<[a-z][^>]*\son[a-z]+\s*=/i', $source) !== 1,
        'Inline event handler remains in ' . $relativePath
    );
}

$auditedTemplates = array_fill_keys($templates, true);
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
foreach ($iterator as $file) {
    if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') continue;
    $relativePath = str_replace(DIRECTORY_SEPARATOR, '/', substr($file->getPathname(), strlen($root) + 1));
    if (str_starts_with($relativePath, 'tests/') || isset($auditedTemplates[$relativePath])) continue;
    $source = file_get_contents($file->getPathname());
    if ($relativePath === 'private_data/email_template.php') continue;
    cspCheck(is_string($source), 'Unable to read PHP template: ' . $relativePath);
    preg_match_all('/<script\\b([^>]*)>(.*?)<\\/script\\s*>/is', $source, $scripts, PREG_SET_ORDER);
    foreach ($scripts as $script) {
        $attributes = $script[1];
        $external = preg_match('/\\bsrc\\s*=/i', $attributes) === 1;
        $dataBlock = preg_match('/\\btype\\s*=\\s*[^>]*application\\/json/i', $attributes) === 1;
        cspCheck($external || $dataBlock, 'Inline executable script remains in ' . $relativePath);
    }
    cspCheck(preg_match('/<[a-z][^>]*\\son[a-z]+\\s*=/i', $source) !== 1, 'Inline event handler remains in ' . $relativePath);
    cspCheck(preg_match('/<style\\b/i', $source) !== 1, 'Inline style block remains in ' . $relativePath);
    cspCheck(preg_match('/<[a-z][^>]*\\sstyle\\s*=/i', $source) !== 1, 'Inline style attribute remains in ' . $relativePath);
}
$cspFiles = [
    'app/Security/SecurityBootstrap.php',
];
foreach ($cspFiles as $relativePath) {
    $source = file_get_contents($root . '/' . $relativePath);
    cspCheck(is_string($source), 'Unable to read CSP source: ' . $relativePath);
    cspCheck(
        preg_match('/script-src\s+[^;]*unsafe-inline/i', $source) !== 1,
        'script-src still permits unsafe-inline in ' . $relativePath
    );
}

$galleryPolicy = sentryiq_build_content_security_policy(true, 's3.us-west-004.backblazeb2.com');
$defaultPolicy = sentryiq_build_content_security_policy(false);
cspCheck(str_contains($galleryPolicy, "img-src 'self' data: blob:"), 'Gallery CSP must permit decrypted blob images.');
cspCheck(str_contains($galleryPolicy, "connect-src 'self' https://s3.us-west-004.backblazeb2.com"), 'Gallery CSP must permit only the configured B2 endpoint.');
cspCheck(!str_contains($defaultPolicy, 'blob:'), 'Non-Gallery pages must not receive the Gallery blob image source.');
cspCheck(!str_contains($defaultPolicy, 'backblazeb2.com'), 'Non-Gallery pages must not receive B2 connect access.');
foreach (['app/Gallery/SecurePage.php', 'gallery_b2_diagnostic.php'] as $relativePath) {
    $source = file_get_contents($root . '/' . $relativePath);
    cspCheck(is_string($source) && !str_contains($source, "header('Content-Security-Policy:"), 'Page-specific CSP must not add a conflicting second policy: ' . $relativePath);
}
echo "CSP external-script and event-handler regression tests passed.\n";
