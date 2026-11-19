<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Durable incident outbox dispatcher.
 *
 * The transport is injected so SMTP/provider credentials stay in private
 * runtime configuration. The idempotency key is supplied to prevent duplicate
 * notifications if delivery succeeds but the acknowledgement write is retried.
 */
final class IntegrityAlertDispatcher
{
    /** @var callable(array<string,mixed>,string):bool */
    private $send;

    public function __construct(
        private readonly FileIntegrityEventStore $store,
        callable $send
    ) {
        $this->send = $send;
    }

    /** @param array<string,mixed> $evaluation */
    public function enqueueEvaluation(array $evaluation): int
    {
        $incidents = $evaluation['incidents'] ?? null;
        if (!is_array($incidents) || !array_is_list($incidents)) {
            throw new RuntimeException('Incident evaluation does not contain a valid incident list.');
        }
        $queued = 0;
        foreach ($incidents as $incident) {
            if (!is_array($incident)) {
                throw new RuntimeException('Incident evaluation contains a malformed incident.');
            }
            $this->store->queueAlert($incident);
            $queued++;
        }
        return $queued;
    }

    /**
     * @return array{delivered:int,remaining:int}
     */
    public function dispatchPending(int $limit = 25): array
    {
        $delivered = 0;
        foreach ($this->store->pendingAlerts($limit) as $alert) {
            try {
                $sent = ($this->send)($alert['incident'], $alert['id']);
            } catch (\Throwable) {
                $sent = false;
            }
            if ($sent === true) {
                $this->store->markAlertDelivered($alert['id']);
                $delivered++;
            }
        }
        return ['delivered' => $delivered, 'remaining' => count($this->store->pendingAlerts(100))];
    }
}
