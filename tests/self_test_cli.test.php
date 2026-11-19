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
if (!is_array($checks) || $checks === []) {
    throw new RuntimeException('Self-test diagnostic returned no server-side checks.');
}
$failed = array_values(array_filter(
    $checks,
    static fn($check): bool => !is_array($check) || ($check['ok'] ?? false) !== true
));
if ($failed !== []) {
    $details = array_map(
        static fn(array $check): string => (string)($check['group'] ?? '?') . '/' . (string)($check['name'] ?? '?') . ': ' . (string)($check['detail'] ?? 'failed'),
        $failed
    );
    throw new RuntimeException("Self-test diagnostic has failing server-side checks:\n" . implode("\n", $details));
}

echo 'SentryIQ self-test server-side diagnostics passed (' . count($checks) . " checks).\n";
