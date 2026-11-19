<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReleaseArtifactFetcher.php';
require_once __DIR__ . '/../app/Updates/IntegrityEventClient.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEventRunner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeScheduledRunner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeReleaseStateStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEvidenceStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeA.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeB.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeC.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationClient.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationVerifier.php';
require_once __DIR__ . '/../app/Updates/PrivateHostAttestationGate.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeVerifierBinding.php';

use SentryIQ\Updates\IntegrityNodeScheduledRunner;
use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;
use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityNodeB;
use SentryIQ\Updates\IntegrityNodeC;
use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationVerifier;
use SentryIQ\Updates\PrivateHostAttestationGate;
use SentryIQ\Updates\IntegrityNodeVerifierBinding;

function scheduledAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-scheduled-' . bin2hex(random_bytes(8));
$webroot = $root . '/public';
$private = $root . '/private';
mkdir($webroot, 0700, true);
mkdir($private, 0700, true);
$releaseStateLock = $private . '/integrity-release-state.lock';
file_put_contents($releaseStateLock, '');
chmod($releaseStateLock, 0600);
$fetcher = new IntegrityReleaseArtifactFetcher();
$releaseState = new SentryIQ\Updates\IntegrityNodeReleaseStateStore($private, $webroot);
$keyPair = sodium_crypto_sign_keypair();
$evidenceStore = new SentryIQ\Updates\IntegrityNodeEvidenceStore($private, $webroot, base64_encode(sodium_crypto_sign_publickey($keyPair)));
$releaseState->initializeBaseline('0.1.3', str_repeat('a', 40), str_repeat('c', 64), str_repeat('d', 64));
$alerts = [];
$attestationNoop = static function (string $path, string $version, string $commit, string $installed): void {};
$fetchNoop = static fn(string $url): string => '';
$alertNoop = static function (string $node, string $reason, array $context) use (&$alerts): void {
    $alerts[] = [$node, $reason];
};
$headersNoop = static fn(string $origin): array => ['approved' => true, 'mismatches' => []];

$nodeC = new IntegrityNodeC(
    new IntegrityReportSigner('integrity-c', base64_encode(sodium_crypto_sign_secretkey($keyPair))),
    $attestationNoop,
    $fetchNoop,
    $alertNoop,
    $headersNoop
);
$bindingC = new IntegrityNodeVerifierBinding('integrity-c', $nodeC);

$pairA = sodium_crypto_sign_keypair();
$privateClientA = new PrivateHostAttestationClient(
    'integrity-a',
    str_repeat('A', 64),
    'https://sentryiq.bichet.co.za/private-host-attestation',
    static fn(string $url, array $headers, string $body, int $maxBytes): array => ['status' => 503, 'body' => '']
);
$privateVerifierA = new PrivateHostAttestationVerifier(base64_encode(sodium_crypto_sign_publickey($pairA)));
$privateGateA = new PrivateHostAttestationGate(
    'integrity-a',
    $privateClientA,
    $privateVerifierA,
    ['app/release.php' => hash('sha256', 'release')],
    []
);
$nodeA = new IntegrityNodeA(
    new IntegrityReportSigner('integrity-a', base64_encode(sodium_crypto_sign_secretkey($pairA))),
    $attestationNoop,
    $privateGateA,
    $fetchNoop,
    $alertNoop,
    $headersNoop
);
$bindingA = new IntegrityNodeVerifierBinding('integrity-a', $nodeA);

$runner = new IntegrityNodeScheduledRunner(
    'integrity-c',
    $fetcher,
    static fn(): array => ['version' => '0.1.3', 'commit' => str_repeat('a', 40)],
    $bindingC,
    $alertNoop,
    $private,
    $webroot,
    'https://sentryiq.bichet.co.za',
    ['assets/app.js'],
    $releaseState,
    null,
    $evidenceStore
);

// This runner is intentionally not executed: network access is not part of
// this unit test. Constructor policy and the no-Node-4 boundary are tested.
$rejectedA = false;
try {
    new IntegrityNodeScheduledRunner(
        'integrity-a', $fetcher,
        static fn(): array => [],
        $bindingA,
        $alertNoop,
        $private, $webroot, 'https://sentryiq.bichet.co.za', ['assets/app.js'], $releaseState, null
    );
} catch (RuntimeException) {
    $rejectedA = true;
}
scheduledAssert($rejectedA, 'Nodes A/B must not start without their Node 4 event exchange.');

$wrongEventIdentityRejected = false;
try {
    $wrongNode4Runner = new SentryIQ\Updates\IntegrityNodeEventRunner(
        new SentryIQ\Updates\IntegrityEventClient(
            'https://sentryiq.bichet.co.za/integrity_event.php',
            'integrity-b',
            str_repeat('y', 48),
            static fn(): array => []
        ),
        static function (): void {}
    );
    new IntegrityNodeScheduledRunner(
        'integrity-a', $fetcher,
        static fn(): array => [],
        $bindingA,
        $alertNoop,
        $private, $webroot, 'https://sentryiq.bichet.co.za', ['assets/app.js'], $releaseState,
        $wrongNode4Runner
    );
} catch (RuntimeException) {
    $wrongEventIdentityRejected = true;
}
scheduledAssert($wrongEventIdentityRejected,
    'Node A scheduled runner must reject a Node B event client.');

$rejectedC = false;
try {
    new IntegrityNodeScheduledRunner(
        'integrity-c', $fetcher,
        static fn(): array => [],
        $bindingC,
        $alertNoop,
        $private, $webroot, 'https://sentryiq.bichet.co.za', ['assets/app.js'], $releaseState,
        new SentryIQ\Updates\IntegrityNodeEventRunner(
            new SentryIQ\Updates\IntegrityEventClient(
                'https://sentryiq.bichet.co.za/integrity_event.php',
                'integrity-a',
                str_repeat('x', 48),
                static fn(): array => []
            ),
            static function (): void {}
        )
    );
} catch (RuntimeException) {
    $rejectedC = true;
}
scheduledAssert($rejectedC, 'Node C must not depend on Node 4.');

@unlink($private . '/integrity-release-state.json');
@unlink($private . '/integrity-release-state.lock');
@rmdir($private . '/integrity-node-c-evidence');
rmdir($private);
rmdir($webroot);
rmdir($root);
echo "Integrity node scheduled runner tests passed.\n";
