<?php

declare(strict_types=1);

/**
 * Temporary, read-only runtime probe.
 *
 * This checks the PHP extensions and outbound HTTPS/TUF refresh path required
 * by the candidate verifier. It does not modify SentryIQ, persist trust roots,
 * access application secrets, or activate Node C.
 */

use K2gl\Sigstore\TrustedRoot;

$autoload = __DIR__ . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "FAIL: Composer dependencies are not installed in this probe directory.\n");
    exit(2);
}
require $autoload;

$disabled = array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions'))));
$required = [
    'php_version' => version_compare(PHP_VERSION, '8.1.0', '>='),
    'openssl_extension' => extension_loaded('openssl'),
    'json_extension' => extension_loaded('json'),
    'sodium_extension' => extension_loaded('sodium'),
];
$report = [
    'probe' => 'sentryiq-heliohost-tuf-runtime',
    'status' => 'started',
    'php_version' => PHP_VERSION,
    'php_sapi' => PHP_SAPI,
    'openssl_version' => defined('OPENSSL_VERSION_TEXT') ? OPENSSL_VERSION_TEXT : null,
    'extensions' => [
        'openssl' => extension_loaded('openssl'),
        'json' => extension_loaded('json'),
        'sodium' => extension_loaded('sodium'),
        'curl' => extension_loaded('curl'),
    ],
    'settings' => [
        'allow_url_fopen' => ini_get('allow_url_fopen'),
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time'),
        'disable_functions_shell_exec' => in_array('shell_exec', $disabled, true),
        'disable_functions_exec' => in_array('exec', $disabled, true),
        'disable_functions_proc_open' => in_array('proc_open', $disabled, true),
    ],
    'requirements' => $required,
    'tuf_refresh' => null,
];

$transportAvailable = extension_loaded('curl')
    || filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOL);
$report['requirements']['https_transport_available'] = $transportAvailable;
$requirementsPassed = !in_array(false, $report['requirements'], true);

if (!$requirementsPassed) {
    $report['status'] = 'failed';
    $report['reason'] = 'One or more required PHP runtime capabilities are unavailable.';
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(1);
}

$started = microtime(true);
try {
    // This call starts from the package's bundled Sigstore TUF root, follows
    // any available root-rotation chain, refreshes timestamp/snapshot/targets,
    // verifies the trusted_root.json target, and parses the resulting root.
    // The library fails closed if metadata is expired, rolled back, unsigned,
    // unavailable, or inconsistent.
    $trustedRoot = TrustedRoot::fromSigstorePublicGood();
    $report['tuf_refresh'] = [
        'result' => 'passed',
        'certificate_authority_count' => count($trustedRoot->certificateAuthorities),
        'transparency_log_count' => count($trustedRoot->transparencyLogs),
        'timestamp_authority_count' => count($trustedRoot->timestampAuthorities),
        'ct_log_count' => count($trustedRoot->ctLogs),
        'elapsed_seconds' => round(microtime(true) - $started, 3),
    ];
    $report['status'] = 'passed';
} catch (Throwable $exception) {
    $report['status'] = 'failed';
    $report['tuf_refresh'] = [
        'result' => 'failed',
        'exception_class' => get_class($exception),
        'message' => $exception->getMessage(),
        'elapsed_seconds' => round(microtime(true) - $started, 3),
    ];
}

echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
exit($report['status'] === 'passed' ? 0 : 1);
