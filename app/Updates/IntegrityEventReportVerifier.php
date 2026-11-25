<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

require_once __DIR__ . '/IntegrityEventRequestDecoder.php';

/**
 * Verifies one independently signed Node A/B event report for BTM-SA.
 *
 * This is deliberately separate from IntegrityReportVerifier: event ingestion
 * accepts one report at a time, including signed rejections. The injected
 * consume-and-store operation MUST atomically match and consume the challenge
 * and persist the exact envelope/payload in one transaction.
 */
final class IntegrityEventReportVerifier
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';
    private const MAX_REPORT_BYTES = 16384;
    private const MAX_EVIDENCE_ITEMS = 100;

    /** @var array<string,string> */
    private array $trustedNodeKeys;

    /** @var callable(string,array<string,mixed>,string,string):string */
    private $consumeAndStore;

    /** @var callable():int */
    private $clock;

    /**
     * @param array<string,string> $trustedNodeKeys Node ID => base64 Ed25519 public key.
     * @param callable(string,array<string,mixed>,string,string):string $consumeAndStore
     *        Arguments: node ID, signed payload, exact envelope JSON, exact payload bytes.
     *        Must atomically validate the outstanding challenge binding, consume its
     *        nonce once, and persist the report; returns the durable report ID.
     * @param callable():int|null $clock Test seam.
     */
    public function __construct(
        array $trustedNodeKeys,
        callable $consumeAndStore,
        ?callable $clock = null
    ) {
        if (count($trustedNodeKeys) !== 2) {
            throw new RuntimeException('Exactly the two independent Integrity Node keys must be configured.');
        }
        foreach ($trustedNodeKeys as $nodeId => $encodedKey) {
            if (!in_array($nodeId, ['integrity-a', 'integrity-b'], true) || !is_string($encodedKey)) {
                throw new RuntimeException('Node 4 trust configuration contains an unknown node identity.');
            }
            $key = base64_decode($encodedKey, true);
            if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new RuntimeException('Node 4 requires valid base64 Ed25519 public keys.');
            }
        }
        $this->trustedNodeKeys = $trustedNodeKeys;
        $this->consumeAndStore = $consumeAndStore;
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * @return array{accepted:bool,report_id:string,node_id:string,decision:string,accepted_at:int}
     */
    public function accept(string $encodedEnvelope): array
    {
        if ($encodedEnvelope === '' || strlen($encodedEnvelope) > self::MAX_REPORT_BYTES) {
            throw new RuntimeException('Integrity event report is empty or exceeds the size limit.');
        }
        IntegrityEventRequestDecoder::assertNoDuplicateObjectKeys($encodedEnvelope);
        try {
            $envelope = json_decode($encodedEnvelope, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Integrity event envelope is not valid JSON.', 0, $exception);
        }
        if (!is_array($envelope) || array_is_list($envelope)
            || count($envelope) !== 2
            || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['signature'] ?? null)) {
            throw new RuntimeException('Integrity event envelope must contain only payload and signature.');
        }

        $rawPayload = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        if (!is_string($rawPayload) || $rawPayload === ''
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('Integrity event envelope encoding is invalid.');
        }
        IntegrityEventRequestDecoder::assertNoDuplicateObjectKeys($rawPayload);
        try {
            $payload = json_decode($rawPayload, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Signed integrity event payload is not valid JSON.', 0, $exception);
        }
        if (!is_array($payload) || array_is_list($payload)) {
            throw new RuntimeException('Signed integrity event payload must be a JSON object.');
        }

        $nodeId = $payload['node_id'] ?? null;
        if (!is_string($nodeId) || !isset($this->trustedNodeKeys[$nodeId])) {
            throw new RuntimeException('Integrity event report has an unknown node identity.');
        }
        $publicKey = base64_decode($this->trustedNodeKeys[$nodeId], true);
        if (!is_string($publicKey) || !sodium_crypto_sign_verify_detached($signature, $rawPayload, $publicKey)) {
            throw new RuntimeException('Integrity event report signature is invalid.');
        }

        $this->validatePayload($payload);
        $acceptedAt = ($this->clock)();
        if (!is_int($acceptedAt) || $acceptedAt < 1) {
            throw new RuntimeException('Node 4 clock returned an invalid timestamp.');
        }

        // The callback is the persistence security boundary: it must perform
        // challenge comparison, one-time consume, and report insert atomically.
        $reportId = ($this->consumeAndStore)($nodeId, $payload, $encodedEnvelope, $rawPayload);
        if (!is_string($reportId) || $reportId === '' || strlen($reportId) > 128) {
            throw new RuntimeException('Node 4 persistence adapter returned an invalid report identifier.');
        }

        return [
            'accepted' => true,
            'report_id' => $reportId,
            'node_id' => $nodeId,
            'decision' => $payload['decision'],
            'accepted_at' => $acceptedAt,
        ];
    }

    /** @param array<string,mixed> $payload */
    private function validatePayload(array $payload): void
    {
        $required = [
            'schema_version', 'node_id', 'decision', 'issued_at', 'expires_at', 'nonce',
            'repository', 'repository_id', 'release_version', 'tag', 'commit',
            'artifact_sha256', 'workflow_path', 'target_origin', 'manifest_sha256',
            'checked_paths', 'mismatches',
        ];
        $keys = array_keys($payload);
        sort($keys);
        $expected = $required;
        sort($expected);
        if ($keys !== $expected) {
            throw new RuntimeException('Signed integrity event payload has missing or unknown fields.');
        }
        if (($payload['schema_version'] ?? null) !== 2
            || !in_array($payload['decision'] ?? null, ['approve', 'reject'], true)
            || ($payload['repository'] ?? null) !== self::REPOSITORY
            || (string)($payload['repository_id'] ?? '') !== self::REPOSITORY_ID
            || ($payload['workflow_path'] ?? null) !== self::WORKFLOW_PATH) {
            throw new RuntimeException('Signed integrity event does not satisfy the Node 4 trust policy.');
        }

        $version = $payload['release_version'] ?? null;
        $commit = $payload['commit'] ?? null;
        $tag = $payload['tag'] ?? null;
        $digest = $payload['artifact_sha256'] ?? null;
        $nonce = $payload['nonce'] ?? null;
        $manifestDigest = $payload['manifest_sha256'] ?? null;
        if (!is_string($version) || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)
            || $tag !== 'v' . $version
            || !is_string($commit) || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !is_string($digest) || !preg_match('/^[a-f0-9]{64}$/', $digest)
            || !is_string($nonce) || !preg_match('/^[a-f0-9]{64}$/', $nonce)
            || !is_string($manifestDigest) || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)) {
            throw new RuntimeException('Signed integrity event release identity is malformed.');
        }

        $issuedAt = $payload['issued_at'] ?? null;
        $expiresAt = $payload['expires_at'] ?? null;
        $now = ($this->clock)();
        if (!is_int($issuedAt) || !is_int($expiresAt)
            || $issuedAt > $now + 30 || $issuedAt < $now - 300
            || $expiresAt <= $now || $expiresAt <= $issuedAt || $expiresAt - $issuedAt > 300) {
            throw new RuntimeException('Signed integrity event is stale, expired, or has invalid timestamps.');
        }

        $origin = $payload['target_origin'] ?? null;
        $parts = is_string($origin) ? parse_url($origin) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || $origin !== 'https://sentryiq.bichet.co.za'
            || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || isset($parts['port']) || isset($parts['path']) || rtrim($origin, '/') !== $origin) {
            throw new RuntimeException('Signed integrity event target origin is invalid.');
        }

        $checked = $payload['checked_paths'] ?? null;
        $mismatches = $payload['mismatches'] ?? null;
        if (!is_array($checked) || !array_is_list($checked) || count($checked) > self::MAX_EVIDENCE_ITEMS
            || !is_array($mismatches) || !array_is_list($mismatches) || count($mismatches) > self::MAX_EVIDENCE_ITEMS) {
            throw new RuntimeException('Signed integrity event evidence exceeds limits or has invalid shape.');
        }
        $seen = [];
        $publicPathCount = 0;
        foreach ($checked as $path) {
            if (!is_string($path) || !$this->safePath($path) || isset($seen[$path])
                || (str_starts_with($path, '@') && !in_array($path, ['@origin-headers', '@private-host-attestation'], true))) {
                throw new RuntimeException('Signed integrity event contains an unsafe or duplicate checked path.');
            }
            $seen[$path] = true;
            if (!str_starts_with($path, '@')) $publicPathCount++;
        }
        if (!isset($seen['@origin-headers']) || !isset($seen['@private-host-attestation']) || $publicPathCount < 1) {
            throw new RuntimeException('Node A/B event evidence must include public assets, origin headers and private-host attestation.');
        }
        $mismatchSeen = [];
        foreach ($mismatches as $item) {
            if (!is_array($item) || array_is_list($item)
                || array_keys($item) !== ['path', 'reason']
                || !is_string($item['path']) || !$this->safePath($item['path'])
                || !in_array($item['reason'], ['content_mismatch', 'fetch_failed', 'security_header_mismatch', 'private_host_attestation_failed'], true)
                || !isset($seen[$item['path']]) || isset($mismatchSeen[$item['path']])) {
                throw new RuntimeException('Signed integrity event contains an invalid or duplicate mismatch record.');
            }
            $mismatchSeen[$item['path']] = true;
            if (($item['reason'] === 'security_header_mismatch' && $item['path'] !== '@origin-headers')
                || ($item['reason'] === 'private_host_attestation_failed' && $item['path'] !== '@private-host-attestation')
                || (in_array($item['reason'], ['content_mismatch', 'fetch_failed'], true) && str_starts_with($item['path'], '@'))) {
                throw new RuntimeException('Signed integrity event mismatch reason does not match its evidence path.');
            }
        }
        if (($payload['decision'] === 'approve') !== ($mismatches === [])) {
            throw new RuntimeException('Signed integrity event decision conflicts with mismatch evidence.');
        }
    }

    private function safePath(string $path): bool
    {
        return $path !== '' && strlen($path) <= 512 && !str_starts_with($path, '/')
            && !str_contains($path, '\\') && !str_contains($path, '//')
            && !preg_match('~(^|/)\.\.?(/|$)~', $path)
            && !preg_match('/[%?#\x00-\x1f]/', $path);
    }
}
