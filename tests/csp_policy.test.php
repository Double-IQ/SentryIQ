<?php
declare(strict_types=1);

function cspCheck(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
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
];

foreach ($templates as $relativePath) {
    $path = $root . '/' . $relativePath;
    $source = file_get_contents($path);
    cspCheck(is_string($source), 'Unable to read CSP template: ' . $relativePath);

    preg_match_all('/<script\\b([^>]*)>(.*?)<\\/script\\s*>/is', $source, $scripts, PREG_SET_ORDER);
    foreach ($scripts as $script) {
        $attributes = $script[1];
        $external = preg_match('/\\bsrc\\s*=/i', $attributes) === 1;
        $dataBlock = preg_match('/\\btype\\s*=\\s*([\"\\\'])application\\/json\\1/i', $attributes) === 1;
        cspCheck($external || $dataBlock, 'Inline executable script remains in ' . $relativePath);
    }

    cspCheck(
        preg_match('/<[a-z][^>]*\\s+on[a-z]+\\s*=/i', $source) !== 1,
        'Inline event handler remains in ' . $relativePath
    );
}

$cspFiles = [
    'app/Security/SecurityBootstrap.php',
    'app/Gallery/SecurePage.php',
    'gallery_b2_diagnostic.php',
];
foreach ($cspFiles as $relativePath) {
    $source = file_get_contents($root . '/' . $relativePath);
    cspCheck(is_string($source), 'Unable to read CSP source: ' . $relativePath);
    cspCheck(
        preg_match('/script-src\\s+[^;]*unsafe-inline/i', $source) !== 1,
        'script-src still permits unsafe-inline in ' . $relativePath
    );
}

echo "CSP external-script and event-handler regression tests passed.\\n";
