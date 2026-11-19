<?php

declare(strict_types=1);

use SentryIQ\Updates\IntegrityNodeEventRunner;
use SentryIQ\Updates\IntegrityNodeScheduledRunner;
use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once __DIR__ . '/../app/Updates/IntegrityReleaseArtifactFetcher.php';
require_once __DIR__ . '/../app/Updates/IntegrityEventClient.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEventRunner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeScheduledRunner.php';
require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeA.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeB.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeC.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeVerifierBinding.php';
require_once __DIR__ . '/../app/Updates/IntegrityPublicAssetPolicy.php';
require_once __DIR__ . '/../app/Updates/IntegrityOriginSecurityHeaderVerifier.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeAlertedException.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeReleaseStateStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEvidenceStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityDeployedReleaseResolver.php';
require_once __DIR__ . '/../app/Updates/ReleaseArtifactVerifier.php';
require_once __DIR__ . '/../app/Updates/ReleaseTrustPolicy.php';
require_once __DIR__ . '/../app/Updates/SigstoreProvenance.php';
require_once __DIR__ . '/../app/Updates/TufRootStore.php';
require_once __DIR__ . '/../app/Updates/NativeSigstoreReleaseVerifier.php';
require_once __DIR__ . '/../app/Updates/NativeSigstoreIntegrityAttestationVerifier.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationGate.php';

$configPath = getenv('SENTRYIQ_INTEGRITY_NODE_CONFIG');
$privateDataDirectory = getenv('SENTRYIQ_INTEGRITY_PRIVATE_DATA_DIR');
$publicWebRoot = getenv('SENTRYIQ_INTEGRITY_PUBLIC_WEB_ROOT');
$private = is_string($privateDataDirectory) ? realpath($privateDataDirectory) : false;
$web = is_string($publicWebRoot) ? realpath($publicWebRoot) : false;
$configReal = is_string($configPath) ? realpath($configPath) : false;
if (is_string($configPath)) clearstatcache(true, $configPath);
$configStat = is_string($configPath) ? @lstat($configPath) : false;
$privateStat = is_string($private) ? @lstat($private) : false;
if (!is_string($configPath) || $configPath === '' || !str_starts_with($configPath, DIRECTORY_SEPARATOR)
    || is_link($configPath) || !is_string($private) || !is_dir($private)
    || !is_array($privateStat) || (($privateStat['mode'] ?? 0) & 0170000) !== 0040000
    || (($privateStat['mode'] ?? 0) & 0777) !== 0700
    || !is_string($web) || !is_dir($web) || !is_string($publicWebRoot) || is_link($publicWebRoot)
    || $private === $web || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || !is_string($configReal) || !is_array($configStat)
    || (($configStat['mode'] ?? 0) & 0170000) !== 0100000
    || (($configStat['mode'] ?? 0) & 0777) !== 0600
    || !str_starts_with($configReal, rtrim($private, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)
    || str_starts_with($configReal, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
    fwrite(STDERR, "A mode-0600 node configuration inside the exact-0700 private data directory is required.\n");
    exit(2);
}

try {
    $configHandle = @fopen($configReal, 'rb');
    $openedConfigStat = is_resource($configHandle) ? @fstat($configHandle) : false;
    clearstatcache(true, $configReal);
    $currentConfigStat = @lstat($configReal);
    if (!is_resource($configHandle) || !is_array($openedConfigStat) || !is_array($currentConfigStat)
        || ($openedConfigStat['dev'] ?? null) !== ($configStat['dev'] ?? null)
        || ($openedConfigStat['ino'] ?? null) !== ($configStat['ino'] ?? null)
        || ($currentConfigStat['dev'] ?? null) !== ($openedConfigStat['dev'] ?? null)
        || ($currentConfigStat['ino'] ?? null) !== ($openedConfigStat['ino'] ?? null)) {
        if (is_resource($configHandle)) fclose($configHandle);
        throw new RuntimeException('Private node configuration changed during open.');
    }
    fclose($configHandle);
    $runner = require $configReal;
    if (!$runner instanceof IntegrityNodeScheduledRunner) {
        throw new RuntimeException('Private node configuration must return an IntegrityNodeScheduledRunner.');
    }
    $result = $runner->run();
    $approved = ($result['approved'] ?? null) === true;
    $summary = [
        'status' => $approved ? 'approved' : 'rejected',
        'release_version' => $result['release_version'] ?? null,
        'release_commit' => $result['release_commit'] ?? null,
        'release_manifest_sha256' => $result['release_manifest_sha256'] ?? null,
        'release_artifact_sha256' => $result['release_artifact_sha256'] ?? null,
        'evidence_id' => $result['evidence_id'] ?? null,
        'evidence_path' => $result['evidence_path'] ?? null,
        'report_id' => $result['event_acknowledgement']['report_id'] ?? null,
    ];
    fwrite(STDOUT, json_encode($summary, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit($approved ? 0 : 3);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Integrity node run failed: ' . get_class($exception) . PHP_EOL);
    exit(1);
}
