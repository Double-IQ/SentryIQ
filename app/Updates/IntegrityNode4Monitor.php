<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;
use Throwable;

/**
 * Cron-callable Node 4 processing pipeline: correlate the latest verified
 * reports, enqueue incident notifications, and retry pending delivery.
 *
 * The independent owner-alert callback is mandatory: the Node 4 outbox cannot
 * be its own fallback when the monitor or notification transport is failing.
 */
final class IntegrityNode4Monitor
{
    /** @var callable(string,string,array<string,mixed>):void */
    private $notifyFailure;

    public function __construct(
        private readonly FileIntegrityEventStore $store,
        private readonly IntegrityIncidentCorrelator $correlator,
        private readonly IntegrityAlertDispatcher $dispatcher,
        callable $notifyFailure
    ) {
        $this->notifyFailure = $notifyFailure;
    }

    /** @return array{evaluation:array<string,mixed>,queued:int,delivery:array{delivered:int,remaining:int}} */
    public function run(string $expectedOrigin, int $deliveryBatch = 25): array
    {
        try {
            $this->store->pruneRetention();
            $evaluation = $this->correlator->evaluate($this->store->snapshot(), $expectedOrigin);
            $queued = $this->dispatcher->enqueueEvaluation($evaluation);
            $delivery = $this->dispatcher->dispatchPending($deliveryBatch);
            if ($delivery['remaining'] > 0) {
                $this->alertOwner('node4_alert_delivery_degraded', [
                    'delivered' => $delivery['delivered'],
                    'remaining' => $delivery['remaining'],
                ]);
            }
            return [
                'evaluation' => $evaluation,
                'queued' => $queued,
                'delivery' => $delivery,
            ];
        } catch (Throwable $exception) {
            try {
                $this->alertOwner('node4_monitor_execution_failed', [
                    'exception' => get_class($exception),
                    'message' => substr($exception->getMessage(), 0, 300),
                ]);
            } catch (Throwable $alertException) {
                throw new RuntimeException(
                    'Node 4 monitor and independent owner alert both failed.',
                    0,
                    $alertException
                );
            }
            throw new RuntimeException(
                'Node 4 monitor failed after independent owner alert delivery was attempted.',
                0,
                $exception
            );
        }
    }

    /** @param array<string,mixed> $context */
    private function alertOwner(string $reason, array $context): void
    {
        ($this->notifyFailure)('integrity-node4', $reason, $context);
    }
}
