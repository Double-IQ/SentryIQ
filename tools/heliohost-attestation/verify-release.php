<?php
declare(strict_types=1);

/**
 * One-shot HelioHost web entry point for the genuine v0.1.2 attestation test.
 * Keep all artifacts and Composer dependencies in the sibling private folder.
 */

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('X-Content-Type-Options: nosniff');

register_shutdown_function(static function (): void {
    if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])) {
        $script = (string) $_SERVER['SCRIPT_FILENAME'];
        if ($script !== '' && is_file($script)) {
            @unlink($script);
        }
    }
});

$privateDir = dirname(__DIR__) . '/sentryiq-probe-private';
$artifact = $privateDir . '/sentryiq-0.1.2.zip';
$bundle = $privateDir . '/attestation-bundle.jsonl';
$validator = $privateDir . '/validate-native-php-sigstore.php';
$autoload = $privateDir . '/vendor/autoload.php';

foreach ([$artifact, $bundle, $validator, $autoload] as $requiredFile) {
    if (!is_file($requiredFile) || !is_readable($requiredFile)) {
        http_response_code(500);
        echo "FAIL: A required private verification file is missing or unreadable.\n";
        exit(1);
    }
}

putenv('SENTRYIQ_SIGSTORE_VENDOR=' . $privateDir . '/vendor');
$argc = 5;
$argv = [
    $validator,
    $artifact,
    $bundle,
    '0.1.2',
    '9c639a4792cadd5421f01ed198ba2a9261c5145f',
];

require $validator;
