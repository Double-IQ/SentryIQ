<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityEventClient.php';

use SentryIQ\Updates\IntegrityEventClient;

function clientAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
foreach ([
    'https://attacker.invalid/integrity_event.php',
    'https://sentryiq.bichet.co.za/other.php',
    'https://sentryiq.bichet.co.za:8443/integrity_event.php',
] as $untrustedEndpoint) {
    $rejected = false;
    try {
        new IntegrityEventClient($untrustedEndpoint, 'integrity-a', $token);
    } catch (RuntimeException) {
        $rejected = true;
    }
    clientAssert($rejected, 'Node 4 client must reject an endpoint outside the pinned SentryIQ URL.');
}
$requests = [];
$client = new IntegrityEventClient(
    'https://sentryiq.bichet.co.za/integrity_event.php',
    'integrity-a',
    $token,
    static function (string $url, array $headers, string $body) use (&$requests): array {
        $requests[] = ['url' => $url, 'headers' => $headers, 'body' => $body];
        $request = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
        if (($request['action'] ?? null) === 'challenge') {
            return [
                'status' => 201,
                'body' => json_encode([
                    'status' => 'ok',
                    'node_id' => 'integrity-a',
                    'nonce' => str_repeat('a', 64),
                    'expires_at' => time() + 300,
                ], JSON_THROW_ON_ERROR),
            ];
        }
        return [
            'status' => 202,
            'body' => json_encode(['status' => 'accepted', 'report_id' => 'event-123'], JSON_THROW_ON_ERROR),
        ];
    }
);

$challenge = $client->requestChallenge(
    'https://sentryiq.bichet.co.za',
    '0.1.3',
    str_repeat('b', 40),
    str_repeat('c', 64),
    str_repeat('d', 64)
);
clientAssert($challenge['node_id'] === 'integrity-a', 'Challenge must be bound to the configured node.');
clientAssert($challenge['nonce'] === str_repeat('a', 64), 'Challenge nonce must be returned to the caller.');
clientAssert($requests[0]['headers']['Authorization'] === 'Bearer ' . $token, 'Per-node bearer token must be sent.');

$accepted = $client->submitReport('{"payload":"c2lnbmVk","signature":"c2ln"}');
clientAssert(($accepted['report_id'] ?? null) === 'event-123', 'Accepted report ID must be returned.');
clientAssert(count($requests) === 2, 'Challenge and report should produce two HTTPS requests.');

$badClient = new IntegrityEventClient(
    'https://sentryiq.bichet.co.za/integrity_event.php',
    'integrity-b',
    $token,
    static fn(): array => [
        'status' => 201,
        'body' => json_encode([
            'status' => 'ok',
            'node_id' => 'integrity-a',
            'nonce' => str_repeat('a', 64),
            'expires_at' => time() + 300,
        ], JSON_THROW_ON_ERROR),
    ]
);
try {
    $badClient->requestChallenge(
        'https://sentryiq.bichet.co.za',
        '0.1.3',
        str_repeat('b', 40),
        str_repeat('c', 64),
        str_repeat('d', 64)
    );
    throw new RuntimeException('Client must reject a challenge issued to a different node.');
} catch (RuntimeException $exception) {
    clientAssert(str_contains($exception->getMessage(), 'invalid or expired challenge'), 'Wrong-node challenge should be rejected.');
}

echo "Integrity event client tests passed.\n";
