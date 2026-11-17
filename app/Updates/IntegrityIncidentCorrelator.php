<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Correlates the latest independent A/B evidence without treating Node 4 as a
 * third independent monitor. A/B signatures are verified before storage.
 */
final class IntegrityIncidentCorrelator
{
    /** @var callable():int */
    private $clock;

    public function __construct(
        private readonly int $maxAgeSeconds = 900,
        ?callable $clock = null
    ) {
        if ($maxAgeSeconds < 60 || $maxAgeSeconds > 86400) {
            throw new RuntimeException('Incident correlation freshness window is invalid.');
        }
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * @param array<string,mixed> $state FileIntegrityEventStore snapshot.
     * @return array{status:string,severity:string,checked_at:int,nodes:array<string,array<string,mixed>>,incidents:list<array{code:string,message:string}>}
     */
    public function evaluate(array $state, string $expectedOrigin): array
    {
        $now = ($this->clock)();
        if (!is_int($now) || $now < 1) {
            throw new RuntimeException('Incident correlator clock is invalid.');
        }
        $parts = parse_url($expectedOrigin);
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https' || empty($parts['host'])
            || isset($parts['path']) || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])) {
            throw new RuntimeException('Incident correlator requires an HTTPS target origin.');
        }
        $reports = $state['reports'] ?? null;
        if (!is_array($reports)) {
            throw new RuntimeException('Incident evidence snapshot is invalid.');
        }

        $latest = ['integrity-a' => null, 'integrity-b' => null];
        foreach ($reports as $record) {
            if (!is_array($record) || !is_string($record['node_id'] ?? null)
                || !array_key_exists($record['node_id'], $latest)
                || !is_array($record['payload'] ?? null) || !is_int($record['accepted_at'] ?? null)) {
                continue;
            }
            $nodeId = $record['node_id'];
            if ($latest[$nodeId] === null || $record['accepted_at'] > $latest[$nodeId]['accepted_at']) {
                $latest[$nodeId] = $record;
            }
        }

        $nodes = [];
        $incidents = [];
        foreach (['integrity-a', 'integrity-b'] as $nodeId) {
            $record = $latest[$nodeId];
            if ($record === null) {
                $nodes[$nodeId] = ['state' => 'missing'];
                $incidents[] = ['code' => 'node_missing', 'message' => $nodeId . ' has not submitted a verified report.'];
                continue;
            }
            $age = $now - $record['accepted_at'];
            $payload = $record['payload'];
            if ($age < -30 || $age > $this->maxAgeSeconds) {
                $nodes[$nodeId] = ['state' => 'stale', 'age_seconds' => $age, 'decision' => $payload['decision'] ?? null];
                $incidents[] = ['code' => 'node_stale', 'message' => $nodeId . ' report is outside the freshness window.'];
                continue;
            }
            if (($payload['target_origin'] ?? null) !== rtrim($expectedOrigin, '/')) {
                $nodes[$nodeId] = ['state' => 'wrong_target', 'age_seconds' => $age];
                $incidents[] = ['code' => 'target_mismatch', 'message' => $nodeId . ' report targets an unexpected origin.'];
                continue;
            }
            $decision = $payload['decision'] ?? null;
            if (!in_array($decision, ['approve', 'reject'], true)) {
                $nodes[$nodeId] = ['state' => 'invalid_decision', 'age_seconds' => $age];
                $incidents[] = ['code' => 'invalid_decision', 'message' => $nodeId . ' report has an invalid decision.'];
                continue;
            }
            $nodes[$nodeId] = [
                'state' => 'fresh',
                'age_seconds' => $age,
                'decision' => $decision,
                'release_version' => $payload['release_version'] ?? null,
                'commit' => $payload['commit'] ?? null,
                'artifact_sha256' => $payload['artifact_sha256'] ?? null,
                'manifest_sha256' => $payload['manifest_sha256'] ?? null,
            ];
            if ($decision === 'reject') {
                $incidents[] = ['code' => 'integrity_rejected', 'message' => $nodeId . ' rejected the deployed release.'];
            }
        }

        $a = $latest['integrity-a']['payload'] ?? null;
        $b = $latest['integrity-b']['payload'] ?? null;
        if (is_array($a) && is_array($b)
            && ($nodes['integrity-a']['state'] ?? null) === 'fresh'
            && ($nodes['integrity-b']['state'] ?? null) === 'fresh') {
            foreach (['release_version', 'commit', 'artifact_sha256', 'manifest_sha256', 'target_origin'] as $field) {
                if (($a[$field] ?? null) !== ($b[$field] ?? null)) {
                    $incidents[] = ['code' => 'node_disagreement', 'message' => 'Integrity Nodes A and B disagree on ' . $field . '.'];
                    break;
                }
            }
        }

        $hasCritical = count($incidents) > 0;
        $allFreshApproved = ($nodes['integrity-a']['state'] ?? null) === 'fresh'
            && ($nodes['integrity-b']['state'] ?? null) === 'fresh'
            && ($nodes['integrity-a']['decision'] ?? null) === 'approve'
            && ($nodes['integrity-b']['decision'] ?? null) === 'approve'
            && $incidents === [];

        return [
            'status' => $allFreshApproved ? 'healthy' : ($hasCritical ? 'incident' : 'incomplete'),
            'severity' => $allFreshApproved ? 'none' : ($hasCritical ? 'high' : 'warning'),
            'checked_at' => $now,
            'nodes' => $nodes,
            'incidents' => $incidents,
        ];
    }
}
