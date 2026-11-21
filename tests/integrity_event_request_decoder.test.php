<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityEventRequestDecoder.php';

use SentryIQ\Updates\IntegrityEventRequestDecoder;

function eventDecoderAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function eventDecoderReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$challenge = '{"action":"challenge","node_id":"integrity-a","target_origin":"https://sentryiq.bichet.co.za","release_version":"1.2.3","commit":"' . str_repeat('a', 40) . '","artifact_sha256":"' . str_repeat('b', 64) . '","manifest_sha256":"' . str_repeat('c', 64) . '"}';
$decoded = IntegrityEventRequestDecoder::decode($challenge);
eventDecoderAssert(($decoded['action'] ?? null) === 'challenge'
    && ($decoded['node_id'] ?? null) === 'integrity-a',
    'A valid Node 4 challenge object must decode.');

$escapedQuoteValue = '{"action":"challenge","note":"quoted \\" text"}';
$escapedQuoteDecoded = IntegrityEventRequestDecoder::decode($escapedQuoteValue);
eventDecoderAssert(($escapedQuoteDecoded['note'] ?? null) === 'quoted " text',
    'A valid escaped quote inside a JSON string must not confuse duplicate-key scanning.');
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":"challenge","note":"quoted \\" text","action":"report"}'),
    'Duplicate fields after a JSON string containing an escaped quote must still be rejected.'
);

eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":"challenge","action":"report"}'),
    'Duplicate action fields must be rejected.'
);
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":"challenge","act\\u0069on":"report"}'),
    'Duplicate JSON keys expressed through Unicode escapes must be rejected.'
);
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":"challenge","nested":{"x":1,"x":2}}'),
    'Duplicate keys inside nested JSON objects must also be rejected.'
);
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('["challenge"]'),
    'Top-level JSON arrays must be rejected.'
);
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":'),
    'Malformed JSON must be rejected.'
);
eventDecoderReject(
    fn() => IntegrityEventRequestDecoder::decode('{"action":"challenge"}', 8),
    'Oversized JSON must be rejected.'
);

echo "Integrity event request decoder tests passed.\n";
