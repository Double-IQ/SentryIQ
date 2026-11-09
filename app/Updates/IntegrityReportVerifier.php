<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Verifies two independent, detached Ed25519 approvals for one exact release.
 *
 * Each report is JSON: {"payload":"<base64 raw JSON>","signature":"<base64 Ed25519 signature>"}.
 * The signature covers the exact decoded payload bytes; no JSON re-encoding is performed.
 * Private signing keys must remain on the Integrity Nodes.
 */
final class IntegrityReportVerifier
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';

    /** @var array<string, string> Node ID => base64-encoded Ed25519 public key */
    private array $trustedNodeKeys;

    /** @var callable():int */
    private $clock;

    /**
     * @param array<string, string> $trustedNodeKeys Exactly two independently managed node public keys.
     * @param callable():int|null $clock Test seam; production uses the system clock.
     */
    public function __construct(array $trustedNodeKeys, ?callable $clock = null)
    {
        if (count($trustedNodeKeys) !== 2) {
            throw new RuntimeException('Exactly two trusted Integrity Node keys must be configured.');
        }

        foreach ($trustedNodeKeys as $nodeId => $encodedKey) {
            if (!is_string($nodeId) || !preg_match('/^[a-z0-9][a-z0-9._-]{2,63}$/', $nodeId)
                || !is_string($encodedKey)) {
                throw new RuntimeException('Integrity Node trust configuration is invalid.');
            }
            $key = base64_decode($encodedKey, true);
            if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new RuntimeException('Each Integrity Node public key must be a base64 Ed25519 public key.');
            }
        }

        $this->trustedNodeKeys = $trustedNodeKeys;
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * Both reports must approve the same version, commit, archive digest and
     * per-attempt nonce. Reports are short-lived to limit replay.
     *
     * @param list<string> $reports Two JSON report envelopes from independent nodes.
     * @return array{approved:bool,node_ids:list<string>,release_version:string,commit:string,artifact_sha256:string}
     */
    public function assertTwoNodeApproval(
        array $reports,
        string $expectedVersion,
        string $expectedCommit,
        string $expectedArtifactSha256,
        string $expectedNonce
    ): array {
        if (count($reports) !== 2 || !array_is_list($reports)) {
            throw new RuntimeException('Exactly two Integrity Node reports are required.');
        }

        $version = $this->normalizeVersion($expectedVersion);
        $commit = strtolower(trim($expectedCommit));
        $digest = strtolower(trim($expectedArtifactSha256));
        $nonce = strtolower(trim($expectedNonce));
        if (!preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $digest)
            || !preg_match('/^[a-f0-9]{64}$/', $nonce)) {
            throw new RuntimeException('Expected release identity or approval nonce is invalid.');
        }

        $seen = [];
        foreach ($reports as $encodedReport) {
            if (!is_string($encodedReport) || strlen($encodedReport) > 16384) {
                throw new RuntimeException('Integrity Node report is malformed or exceeds the size limit.');
            }
            $payload = $this->verifyEnvelope($encodedReport);
            $nodeId = $payload['node_id'] ?? null;
            if (!is_string($nodeId) || !isset($this->trustedNodeKeys[$nodeId]) || isset($seen[$nodeId])) {
                throw new RuntimeException('Integrity Node identity is unknown or duplicated.');
            }
            $seen[$nodeId] = true;

            if (($payload['schema_version'] ?? null) !== 1
                || ($payload['decision'] ?? null) !== 'approve'
                || ($payload['repository'] ?? null) !== self::REPOSITORY
                || ($payload['repository_id'] ?? null) !== self::REPOSITORY_ID
                || ($payload['workflow_path'] ?? null) !== self::WORKFLOW_PATH) {
                throw new RuntimeException('Integrity Node approval does not satisfy the SentryIQ trust policy.');
            }

            if (($payload['release_version'] ?? null) !== $version
                || ($payload['tag'] ?? null) !== 'v' . $version
                || strtolower((string)($payload['commit'] ?? '')) !== $commit
                || strtolower((string)($payload['artifact_sha256'] ?? '')) !== $digest
                || strtolower((string)($payload['nonce'] ?? '')) !== $nonce) {
                throw new RuntimeException('Integrity Node approval does not match this update attempt.');
            }

            $issuedAt = $payload['issued_at'] ?? null;
            $expiresAt = $payload['expires_at'] ?? null;
            if (!is_int($issuedAt) || !is_int($expiresAt)) {
                throw new RuntimeException('Integrity Node approval timestamps are invalid.');
            }
            $now = ($this->clock)();
            if ($issuedAt > $now + 30 || $issuedAt < $now - 300
                || $expiresAt <= $now || $expiresAt <= $issuedAt
                || $expiresAt - $issuedAt > 300) {
                throw new RuntimeException('Integrity Node approval is expired, stale, or outside the allowed time window.');
            }
        }

        if (count($seen) !== 2) {
            throw new RuntimeException('Both distinct trusted Integrity Nodes must approve the release.');
        }

        return [
            'approved' => true,
            'node_ids' => array_keys($seen),
            'release_version' => $version,
            'commit' => $commit,
            'artifact_sha256' => $digest,
        ];
    }

    /** @return array<string, mixed> */
    private function verifyEnvelope(string $json): array
    {
        try {
            $envelope = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Integrity Node report envelope is not valid JSON.', 0, $exception);
        }
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['signature'] ?? null)) {
            throw new RuntimeException('Integrity Node report envelope is incomplete.');
        }

        $rawPayload = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        if (!is_string($rawPayload) || $rawPayload === ''
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RuntimeException('Integrity Node report encoding is invalid.');
        }

        try {
            $payload = json_decode($rawPayload, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Signed Integrity Node payload is not valid JSON.', 0, $exception);
        }
        if (!is_array($payload) || array_is_list($payload)) {
            throw new RuntimeException('Signed Integrity Node payload must be a JSON object.');
        }

        $nodeId = $payload['node_id'] ?? null;
        if (!is_string($nodeId) || !isset($this->trustedNodeKeys[$nodeId])) {
            throw new RuntimeException('Integrity Node report was signed by an untrusted identity.');
        }
        $publicKey = base64_decode($this->trustedNodeKeys[$nodeId], true);
        if (!is_string($publicKey)
            || !sodium_crypto_sign_verify_detached($signature, $rawPayload, $publicKey)) {
            throw new RuntimeException('Integrity Node report signature is invalid.');
        }

        return $payload;
    }

    private function normalizeVersion(string $version): string
    {
        $version = trim($version);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Release version must use stable MAJOR.MINOR.PATCH format.');
        }
        return $version;
    }
}
