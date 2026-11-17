<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

/**
 * Cron-callable Node 4 processing pipeline: correlate the latest verified
 * reports, enqueue incident notifications, and retry pending delivery.
 */
final class IntegrityNode4Monitor
{
    public function __construct(
        private readonly FileIntegrityEventStore $store,
        private readonly IntegrityIncidentCorrelator $correlator,
        private readonly IntegrityAlertDispatcher $dispatcher
    ) {
    }

    /** @return array{evaluation:array<string,mixed>,queued:int,delivery:array{delivered:int,remaining:int}} */
    public function run(string $expectedOrigin, int $deliveryBatch = 25): array
    {
        $evaluation = $this->correlator->evaluate($this->store->snapshot(), $expectedOrigin);
        $queued = $this->dispatcher->enqueueEvaluation($evaluation);
        $delivery = $this->dispatcher->dispatchPending($deliveryBatch);
        return [
            'evaluation' => $evaluation,
            'queued' => $queued,
            'delivery' => $delivery,
        ];
    }
}
