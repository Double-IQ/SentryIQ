<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReportSigner.php';
require_once __DIR__ . '/../app/Updates/IntegrityEventReportVerifier.php';
require_once __DIR__ . '/../app/Updates/FileIntegrityEventStore.php';

use SentryIQ\Updates\FileIntegrityEventStore;
use SentryIQ\Updates\IntegrityEventReportVerifier;
use SentryIQ\Updates\IntegrityReportSigner;

function storeAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function storeReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (RuntimeException) {
        return;
    }
    throw new RuntimeException($message);
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sentryiq-node4-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary Node 4 test directory.');
}

try {
    chmod($directory, 0755);
    storeReject(
        static fn() => new FileIntegrityEventStore($directory),
        'Node 4 storage must reject directories accessible to group or other users.'
    );
    chmod($directory, 0700);
    $lockPath = $directory . DIRECTORY_SEPARATOR . 'integrity-events.lock';
    file_put_contents($lockPath, '');
    chmod($lockPath, 0600);
    $store = new FileIntegrityEventStore($directory);
    $weakLockDirectory = $directory . '/weak-lock';
    mkdir($weakLockDirectory, 0700);
    file_put_contents($weakLockDirectory . '/integrity-events.lock', '');
    chmod($weakLockDirectory . '/integrity-events.lock', 0640);
    storeReject(
        static fn() => new FileIntegrityEventStore($weakLockDirectory),
        'Node 4 store must reject a lock file without exact 0600 permissions.'
    );

    $symlinkLockDirectory = $directory . '/symlink-lock';
    mkdir($symlinkLockDirectory, 0700);
    $lockTarget = $directory . '/lock-target';
    file_put_contents($lockTarget, 'do-not-touch');
    chmod($lockTarget, 0600);
    symlink($lockTarget, $symlinkLockDirectory . '/integrity-events.lock');
    storeReject(
        static fn() => new FileIntegrityEventStore($symlinkLockDirectory),
        'Node 4 store must reject a symlinked lock file.'
    );
    storeAssert(file_get_contents($lockTarget) === 'do-not-touch',
        'A symlinked Node 4 lock must never redirect writes.');

    $symlinkStateDirectory = $directory . '/symlink-state';
    mkdir($symlinkStateDirectory, 0700);
    file_put_contents($symlinkStateDirectory . '/integrity-events.lock', '');
    chmod($symlinkStateDirectory . '/integrity-events.lock', 0600);
    $stateTarget = $directory . '/state-target';
    file_put_contents($stateTarget, 'do-not-touch');
    chmod($stateTarget, 0600);
    symlink($stateTarget, $symlinkStateDirectory . '/integrity-events.json');
    storeReject(
        static fn() => new FileIntegrityEventStore($symlinkStateDirectory),
        'Node 4 store must reject a symlinked state file.'
    );
    storeAssert(file_get_contents($stateTarget) === 'do-not-touch',
        'A symlinked Node 4 state must never redirect reads or writes.');

    $keyA = sodium_crypto_sign_keypair();
    $secretA = sodium_crypto_sign_secretkey($keyA);
    $publicA = sodium_crypto_sign_publickey($keyA);
    $keyB = sodium_crypto_sign_keypair();
    $publicB = sodium_crypto_sign_publickey($keyB);
    $now = time();

    $version = '0.1.3';
    $commit = str_repeat('b', 40);
    $artifact = str_repeat('c', 64);
    $manifest = str_repeat('d', 64);
    $origin = 'https://sentryiq.bichet.co.za';

    $challenge = $store->issueChallenge(
        'integrity-a',
        $origin,
        $version,
        $commit,
        $artifact,
        $manifest
    );

    $signer = new IntegrityReportSigner('integrity-a', base64_encode($secretA));
    $envelope = $signer->createReport(
        $version,
        $commit,
        $artifact,
        $challenge['nonce'],
        'approve',
        [
            'target_origin' => $origin,
            'manifest_sha256' => $manifest,
            'checked_paths' => ['index.php', 'assets/app.js', '@origin-headers', '@private-host-attestation'],
            'mismatches' => [],
        ]
    );

    $verifier = new IntegrityEventReportVerifier(
        [
            'integrity-a' => base64_encode($publicA),
            'integrity-b' => base64_encode($publicB),
        ],
        [$store, 'consumeAndStore']
    );

    $accepted = $verifier->accept($envelope);
    storeAssert($accepted['accepted'] === true, 'Valid challenged report must be accepted.');
    storeAssert((fileperms($lockPath) & 0777) === 0600,
        'Node 4 lock file must remain at exact 0600 permissions.');

    chmod($directory . DIRECTORY_SEPARATOR . 'integrity-events.json', 0640);
    storeReject(
        static fn() => new FileIntegrityEventStore($directory),
        'Node 4 store must reject state files with permissions other than exact 0600.'
    );
    storeAssert((fileperms($directory . DIRECTORY_SEPARATOR . 'integrity-events.json') & 0777) === 0640,
        'Node 4 store must not repair operator-supplied state permissions.');
    chmod($directory . DIRECTORY_SEPARATOR . 'integrity-events.json', 0600);

    $snapshot = $store->snapshot();
    storeAssert(count($snapshot['challenges']) === 0, 'Accepted challenge must be consumed.');
    storeAssert(count($snapshot['reports']) === 1, 'Accepted report must be durably retained.');

    storeReject(
        fn() => $verifier->accept($envelope),
        'A consumed challenge must not accept a replay.'
    );

    $store->issueChallenge(
        'integrity-a',
        $origin,
        $version,
        $commit,
        $artifact,
        $manifest,
        time() - 600
    );

    $wrongBinding = $store->issueChallenge(
        'integrity-a',
        $origin,
        $version,
        $commit,
        $artifact,
        $manifest
    );
    $wrongSigner = $signer->createReport(
        $version,
        $commit,
        $artifact,
        $wrongBinding['nonce'],
        'approve',
        [
            'target_origin' => $origin,
            'manifest_sha256' => str_repeat('e', 64),
            'checked_paths' => ['index.php', '@origin-headers', '@private-host-attestation'],
            'mismatches' => [],
        ]
    );
    storeReject(
        fn() => $verifier->accept($wrongSigner),
        'A report with a mismatched manifest binding must be rejected.'
    );

    $snapshot = $store->snapshot();
    storeAssert(count($snapshot['challenges']) === 1, 'Rejected binding must not consume the legitimate challenge.');
    storeAssert(count($snapshot['reports']) === 1, 'Rejected binding must not create evidence.');

    $incident = ['code' => 'node_stale', 'message' => 'integrity-b report is stale.'];
    $queued = $store->queueAlert($incident);
    $duplicate = $store->queueAlert($incident);
    storeAssert($queued['created'] === true && $duplicate['created'] === false, 'Identical incident alerts must be deduplicated.');
    $pending = $store->pendingAlerts();
    storeAssert(count($pending) === 1 && $pending[0]['occurrences'] === 2, 'Outbox must retain one pending alert and count occurrences.');
    $store->markAlertDelivered($queued['id'], time());
    storeAssert(count($store->pendingAlerts()) === 0, 'Delivered alerts must leave the pending outbox.');
    $cooldownDuplicate = $store->queueAlert($incident);
    storeAssert($cooldownDuplicate['created'] === false, 'Recently delivered incidents must be suppressed during the alert cooldown.');

    $statePath = $directory . DIRECTORY_SEPARATOR . 'integrity-events.json';
    $retentionState = $store->snapshot();
    $retentionNow = time();
    $retentionState['challenges']['expired-test'] = ['expires_at' => $retentionNow - 1];
    $retentionState['challenges']['active-test'] = ['expires_at' => $retentionNow + 120];
    $retentionState['reports']['old-test'] = ['accepted_at' => $retentionNow - 8 * 86400];
    $retentionState['reports']['recent-test'] = ['accepted_at' => $retentionNow - 60];
    $retentionState['alerts']['old-delivered-test'] = [
        'status' => 'delivered',
        'delivered_at' => $retentionNow - 31 * 86400,
    ];
    $retentionState['alerts']['pending-test'] = [
        'status' => 'pending',
        'created_at' => $retentionNow - 31 * 86400,
        'last_seen' => $retentionNow - 31 * 86400,
        'occurrences' => 1,
    ];
    file_put_contents($statePath, json_encode($retentionState, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    chmod($statePath, 0600);
    $pruned = $store->pruneRetention($retentionNow);
    storeAssert($pruned === ['challenges' => 1, 'reports' => 1, 'alerts' => 1],
        'Node 4 retention must prune expired challenges, reports older than seven days and delivered alerts older than thirty days.');
    $afterPrune = $store->snapshot();
    storeAssert(isset($afterPrune['challenges']['active-test']) && !isset($afterPrune['challenges']['expired-test']),
        'Retention must preserve live challenges and remove expired challenges.');
    storeAssert(isset($afterPrune['reports']['recent-test']) && !isset($afterPrune['reports']['old-test']),
        'Retention must preserve recent evidence and remove reports older than seven days.');
    storeAssert(isset($afterPrune['alerts']['pending-test']) && !isset($afterPrune['alerts']['old-delivered-test']),
        'Retention must never discard pending alerts but must remove old delivered alerts.');
} finally {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($iterator as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($directory);
}

echo "File-backed Node 4 event store tests passed.\n";
