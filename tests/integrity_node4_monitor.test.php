<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/FileIntegrityEventStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityIncidentCorrelator.php';
require_once __DIR__ . '/../app/Updates/IntegrityAlertDispatcher.php';
require_once __DIR__ . '/../app/Updates/IntegrityNode4Monitor.php';

use SentryIQ\Updates\FileIntegrityEventStore;
use SentryIQ\Updates\IntegrityAlertDispatcher;
use SentryIQ\Updates\IntegrityIncidentCorrelator;
use SentryIQ\Updates\IntegrityNode4Monitor;

function monitorAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sentryiq-monitor-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary monitor directory.');
}
try {
    file_put_contents($directory . DIRECTORY_SEPARATOR . 'integrity-events.lock', '');
    chmod($directory . DIRECTORY_SEPARATOR . 'integrity-events.lock', 0600);
    $store = new FileIntegrityEventStore($directory);
    $send = false;
    $dispatcher = new IntegrityAlertDispatcher(
        $store,
        static function (array $incident, string $idempotencyKey) use (&$send): bool {
            return $send;
        }
    );
    $directAlerts = [];
    $monitor = new IntegrityNode4Monitor(
        $store,
        new IntegrityIncidentCorrelator(1800),
        $dispatcher,
        static function (string $nodeId, string $reason, array $context) use (&$directAlerts): void {
            $directAlerts[] = [$nodeId, $reason, $context];
        }
    );

    $first = $monitor->run('https://sentryiq.bichet.co.za');
    monitorAssert($first['evaluation']['status'] === 'incident', 'No A/B reports must produce an incident state.');
    monitorAssert($first['queued'] === 2, 'Missing A and B must each queue an alert.');
    monitorAssert($first['delivery']['remaining'] === 2, 'Failed notification transport must leave alerts pending.');
    monitorAssert(count($directAlerts) === 1, 'Failed outbox delivery must trigger an independent owner alert.');
    monitorAssert($directAlerts[0][0] === 'integrity-node4'
        && $directAlerts[0][1] === 'node4_alert_delivery_degraded'
        && ($directAlerts[0][2]['remaining'] ?? null) === 2,
        'Independent alert must identify Node 4 and report the pending delivery backlog.');

    $send = true;
    $second = $monitor->run('https://sentryiq.bichet.co.za');
    monitorAssert($second['delivery']['delivered'] === 2, 'A later cron run must retry and deliver pending alerts.');
    monitorAssert($second['delivery']['remaining'] === 0, 'Successfully delivered alerts must leave the pending queue.');
    monitorAssert(count($directAlerts) === 1, 'Successful retry must not send another delivery-degraded alert.');

    $failingMonitor = new IntegrityNode4Monitor(
        $store,
        new IntegrityIncidentCorrelator(1800, static fn(): int => 0),
        $dispatcher,
        static function (string $nodeId, string $reason, array $context) use (&$directAlerts): void {
            $directAlerts[] = [$nodeId, $reason, $context];
        }
    );
    $monitorFailureAlerted = false;
    try {
        $failingMonitor->run('https://sentryiq.bichet.co.za');
    } catch (RuntimeException) {
        $monitorFailureAlerted = true;
    }
    monitorAssert($monitorFailureAlerted, 'Monitor execution failure must fail visibly.');
    monitorAssert(count($directAlerts) === 2
        && $directAlerts[1][0] === 'integrity-node4'
        && $directAlerts[1][1] === 'node4_monitor_execution_failed',
        'Monitor execution failure must trigger the independent owner-alert path.');
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) {
            unlink($file);
        }
    }
    rmdir($directory);
}

echo "Node 4 monitor pipeline tests passed.\n";
