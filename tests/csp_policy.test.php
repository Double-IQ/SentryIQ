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

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
);
foreach ($iterator as $file) {
    if (!$file->isFile() || strtolower($file->getExtension()) !== 'php') continue;
    $relativePath = str_replace(DIRECTORY_SEPARATOR, '/', substr($file->getPathname(), strlen($root) + 1));
    if (str_starts_with($relativePath, 'tests/')) continue;
    $source = file_get_contents($file->getPathname());
    cspCheck(is_string($source), 'Unable to read PHP source: ' . $relativePath);

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

    // Email bodies are intentionally self-contained HTML and are not page templates.
    if (!in_array($relativePath, ['private_data/email_template.php', 'app/Auth/AuthFlow.php'], true)) {
        cspCheck(preg_match('/<style\b/i', $source) !== 1, 'Inline style block remains in ' . $relativePath);
        cspCheck(
            preg_match('/<[a-z][^>]*\sstyle\s*=/i', $source) !== 1,
            'Inline style attribute remains in ' . $relativePath
        );
    }
}

$cspSource = file_get_contents($root . '/app/Security/SecurityBootstrap.php');
cspCheck(is_string($cspSource), 'Unable to read CSP source.');
cspCheck(preg_match('/script-src\s+[^;]*unsafe-inline/i', $cspSource) !== 1, 'script-src still permits unsafe-inline.');
cspCheck(preg_match('/style-src\s+[^;]*unsafe-inline/i', $cspSource) !== 1, 'style-src still permits unsafe-inline.');

$galleryPolicy = sentryiq_build_content_security_policy(true, 's3.us-west-004.backblazeb2.com');
$defaultPolicy = sentryiq_build_content_security_policy(false);
cspCheck(str_contains($galleryPolicy, "img-src 'self' data: blob:"), 'Gallery CSP must permit decrypted blob images.');
cspCheck(str_contains($galleryPolicy, "connect-src 'self' https://s3.us-west-004.backblazeb2.com"), 'Gallery CSP must permit only the configured B2 endpoint.');
cspCheck(str_contains($galleryPolicy, "style-src 'self'"), 'Gallery CSP must permit same-origin stylesheets.');
cspCheck(!str_contains($galleryPolicy, 'unsafe-inline'), 'Gallery CSP must not permit unsafe-inline.');
cspCheck(!str_contains($defaultPolicy, 'blob:'), 'Non-Gallery pages must not receive the Gallery blob image source.');
cspCheck(!str_contains($defaultPolicy, 'backblazeb2.com'), 'Non-Gallery pages must not receive B2 connect access.');
cspCheck(!str_contains($defaultPolicy, 'unsafe-inline'), 'Non-Gallery CSP must not permit unsafe-inline.');

foreach (['app/Gallery/SecurePage.php', 'gallery_b2_diagnostic.php'] as $relativePath) {
    $source = file_get_contents($root . '/' . $relativePath);
    cspCheck(is_string($source) && !str_contains($source, "header('Content-Security-Policy:"), 'Page-specific CSP must not add a conflicting second policy: ' . $relativePath);
}

echo "CSP script, event-handler, and style regression tests passed.\n";
