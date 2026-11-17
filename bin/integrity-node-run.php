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
if (!is_string($configPath) || $configPath === '' || !str_starts_with($configPath, DIRECTORY_SEPARATOR)
    || is_link($configPath) || !is_file($configPath) || !is_readable($configPath)
    || (fileperms($configPath) & 0777) !== 0600) {
    fwrite(STDERR, "A readable absolute private node configuration path is required.\n");
    exit(2);
}

try {
    $runner = require realpath($configPath);
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
