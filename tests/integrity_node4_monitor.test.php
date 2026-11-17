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
    $store = new FileIntegrityEventStore($directory);
    $send = false;
    $dispatcher = new IntegrityAlertDispatcher(
        $store,
        static function (array $incident, string $idempotencyKey) use (&$send): bool {
            return $send;
        }
    );
    $correlator = new IntegrityIncidentCorrelator(900);
    $monitor = new IntegrityNode4Monitor($store, $correlator, $dispatcher);

    $first = $monitor->run('https://sentryiq.bichet.co.za');
    monitorAssert($first['evaluation']['status'] === 'incident', 'No A/B reports must produce an incident state.');
    monitorAssert($first['queued'] === 2, 'Missing A and B must each queue an alert.');
    monitorAssert($first['delivery']['remaining'] === 2, 'Failed notification transport must leave alerts pending.');

    $send = true;
    $second = $monitor->run('https://sentryiq.bichet.co.za');
    monitorAssert($second['delivery']['delivered'] === 2, 'A later cron run must retry and deliver pending alerts.');
    monitorAssert($second['delivery']['remaining'] === 0, 'Successfully delivered alerts must leave the pending queue.');
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) {
            unlink($file);
        }
    }
    rmdir($directory);
}

echo "Node 4 monitor pipeline tests passed.\n";
