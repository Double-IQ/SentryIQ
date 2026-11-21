<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityIncidentCorrelator.php';

use SentryIQ\Updates\IntegrityIncidentCorrelator;

function correlationAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$now = 1794900000;
$basePayload = [
    'target_origin' => 'https://sentryiq.bichet.co.za',
    'decision' => 'approve',
    'release_version' => '0.1.3',
    'commit' => str_repeat('a', 40),
    'artifact_sha256' => str_repeat('b', 64),
    'manifest_sha256' => str_repeat('c', 64),
];
$state = [
    'reports' => [
        'a' => ['node_id' => 'integrity-a', 'accepted_at' => $now - 10, 'payload' => $basePayload],
        'b' => ['node_id' => 'integrity-b', 'accepted_at' => $now - 20, 'payload' => $basePayload],
    ],
];
$correlator = new IntegrityIncidentCorrelator(1800, static fn(): int => $now);
$healthy = $correlator->evaluate($state, 'https://sentryiq.bichet.co.za');
correlationAssert($healthy['status'] === 'healthy', 'Matching fresh approvals should be healthy.');

$rejected = $state;
$rejected['reports']['b']['payload']['decision'] = 'reject';
$incident = $correlator->evaluate($rejected, 'https://sentryiq.bichet.co.za');
correlationAssert($incident['status'] === 'incident', 'A signed rejection must create an incident.');
correlationAssert(in_array('integrity_rejected', array_column($incident['incidents'], 'code'), true), 'Rejection incident code must be retained.');

$disagreement = $state;
$disagreement['reports']['b']['payload']['commit'] = str_repeat('d', 40);
$split = $correlator->evaluate($disagreement, 'https://sentryiq.bichet.co.za');
correlationAssert(in_array('node_disagreement', array_column($split['incidents'], 'code'), true), 'Different release commits must be reported as disagreement.');

$missing = $correlator->evaluate(['reports' => ['a' => $state['reports']['a']]], 'https://sentryiq.bichet.co.za');
correlationAssert(($missing['nodes']['integrity-b']['state'] ?? null) === 'missing', 'Missing Node B must be detected.');

$staleState = $state;
$staleState['reports']['a']['accepted_at'] = $now - 1801;
$stale = $correlator->evaluate($staleState, 'https://sentryiq.bichet.co.za');
correlationAssert(($stale['nodes']['integrity-a']['state'] ?? null) === 'stale', 'Stale Node A must be detected.');

$wrongTarget = $state;
$wrongTarget['reports']['b']['payload']['target_origin'] = 'https://attacker.example';
$target = $correlator->evaluate($wrongTarget, 'https://sentryiq.bichet.co.za');
correlationAssert(in_array('target_mismatch', array_column($target['incidents'], 'code'), true), 'Wrong target origin must create an incident.');

echo "Integrity incident correlation tests passed.\n";
