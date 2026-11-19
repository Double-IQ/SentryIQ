<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['HTTP_HOST'] = 'sentryiq-self-test.invalid';
$_SERVER['SERVER_NAME'] = 'sentryiq-self-test.invalid';
$_SERVER['SCRIPT_NAME'] = '/diagnostics/self_test.php';
$_SERVER['DOCUMENT_ROOT'] = $root;

ob_start();
require $root . '/diagnostics/self_test.php';
$html = ob_get_clean();
if (!is_string($html) || $html === '') {
    throw new RuntimeException('Self-test diagnostic did not render output.');
}
if (!preg_match('~<script type="application/json" id="sentryiq-self-test-data">(.*?)</script>~s', $html, $matches)) {
    throw new RuntimeException('Self-test diagnostic did not expose its structured server-check report.');
}
$report = json_decode($matches[1], true, 512, JSON_THROW_ON_ERROR);
$checks = $report['serverChecks'] ?? null;
$browserTests = $report['tests'] ?? null;
if (!is_array($browserTests)) {
    throw new RuntimeException('Self-test diagnostic returned no browser URL contracts.');
}
$indexTest = array_values(array_filter(
    $browserTests,
    static fn($test): bool => is_array($test)
        && ($test['type'] ?? '') === 'page'
        && ($test['label'] ?? '') === 'index.php'
));
if (count($indexTest) !== 1) {
    throw new RuntimeException('Self-test browser contract for index.php is missing or duplicated.');
}
$requiredIndexScripts = ['assets/js/vault_folders.js', 'assets/js/vault_page.js', 'assets/js/vault_page_init.js'];
$actualIndexScripts = array_values(array_filter(
    $indexTest[0]['requiredHtmlRefs'] ?? [],
    static fn($ref): bool => is_array($ref) && ($ref['tag'] ?? '') === 'script'
));
foreach ($requiredIndexScripts as $requiredScript) {
    $found = false;
    foreach ($actualIndexScripts as $ref) {
        if (($ref['prefix'] ?? '') === $requiredScript || ($ref['value'] ?? '') === $requiredScript) {
            $found = true;
            break;
        }
    }
    if (!$found) {
        throw new RuntimeException('Self-test browser contract is missing current index script: ' . $requiredScript);
    }
}
foreach ($actualIndexScripts as $ref) {
    if (($ref['prefix'] ?? '') === 'assets/js/records_view.js') {
        throw new RuntimeException('Self-test browser contract still expects the obsolete Records script in index.php.');
    }
}
if (!is_array($checks) || $checks === []) {
    throw new RuntimeException('Self-test diagnostic returned no server-side checks.');
}
$installedChecks = array_values(array_filter(
    $checks,
    static fn($check): bool => is_array($check)
        && ($check['group'] ?? '') === 'Environment'
        && ($check['name'] ?? '') === 'Installed flag'
));
if (count($installedChecks) !== 1 || ($installedChecks[0]['ok'] ?? true) !== false) {
    throw new RuntimeException('Self-test CLI fixture must remain an isolated, uninstalled application.');
}
$failed = array_values(array_filter(
    $checks,
    static fn($check): bool => !is_array($check)
        || (($check['group'] ?? '') !== 'Environment' || ($check['name'] ?? '') !== 'Installed flag')
            && ($check['ok'] ?? false) !== true
));
if ($failed !== []) {
    $details = array_map(
        static fn(array $check): string => (string)($check['group'] ?? '?') . '/' . (string)($check['name'] ?? '?') . ': ' . (string)($check['detail'] ?? 'failed'),
        $failed
    );
    throw new RuntimeException("Self-test diagnostic has failing server-side checks:\n" . implode("\n", $details));
}

echo 'SentryIQ self-test server-side diagnostics passed (' . count($checks) . " checks).\n";
