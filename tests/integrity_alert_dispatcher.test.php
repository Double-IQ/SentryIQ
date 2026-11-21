<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/FileIntegrityEventStore.php';
require_once __DIR__ . '/../app/Updates/IntegrityAlertDispatcher.php';

use SentryIQ\Updates\FileIntegrityEventStore;
use SentryIQ\Updates\IntegrityAlertDispatcher;

function alertAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sentryiq-alerts-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary alert outbox directory.');
}
try {
    file_put_contents($directory . DIRECTORY_SEPARATOR . 'integrity-events.lock', '');
    chmod($directory . DIRECTORY_SEPARATOR . 'integrity-events.lock', 0600);
    $store = new FileIntegrityEventStore($directory);
    $attempts = [];
    $shouldSend = false;
    $dispatcher = new IntegrityAlertDispatcher(
        $store,
        static function (array $incident, string $idempotencyKey) use (&$attempts, &$shouldSend): bool {
            $attempts[] = [$incident['code'], $idempotencyKey];
            return $shouldSend;
        }
    );

    $evaluation = [
        'incidents' => [
            ['code' => 'node_missing', 'message' => 'integrity-a is missing.'],
            ['code' => 'node_stale', 'message' => 'integrity-b is stale.'],
        ],
    ];
    alertAssert($dispatcher->enqueueEvaluation($evaluation) === 2, 'Both incidents should be queued.');
    $failed = $dispatcher->dispatchPending();
    alertAssert($failed['delivered'] === 0 && $failed['remaining'] === 2, 'Failed transport must leave alerts pending.');

    $shouldSend = true;
    $sent = $dispatcher->dispatchPending();
    alertAssert($sent['delivered'] === 2 && $sent['remaining'] === 0, 'Successful transport should acknowledge both alerts.');
    alertAssert(count($attempts) === 4, 'Each alert should be retried once after the initial failed attempt.');
    alertAssert($attempts[0][1] === $attempts[2][1] && $attempts[1][1] === $attempts[3][1], 'Retries must reuse stable idempotency keys.');
    // The backlog count must not silently cap at the maximum fetch page size.
    $backlog = [];
    for ($index = 0; $index < 101; $index++) {
        $backlog[] = ['code' => 'synthetic_backlog_' . $index, 'message' => 'Pending test alert ' . $index];
    }
    alertAssert($dispatcher->enqueueEvaluation(['incidents' => $backlog]) === 101, 'All backlog incidents should be enqueued.');
    $backlogResult = $dispatcher->dispatchPending(1);
    alertAssert(
        $backlogResult['delivered'] === 0 && $backlogResult['remaining'] === 101,
        'Remaining backlog must report the exact count even when it exceeds the 100-record fetch page.'
    );
} finally {
    foreach (glob($directory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
        if (is_file($file) && !is_link($file)) {
            unlink($file);
        }
    }
    rmdir($directory);
}

echo "Integrity alert dispatcher tests passed.\n";
