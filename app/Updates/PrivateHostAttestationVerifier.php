<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Verifies a detached, nonce-bound attestation from the production-host
 * read-only collector. The collector key is pinned independently on A and B.
 */
final class PrivateHostAttestationVerifier
{
    private string $publicKey;

    /** @var callable():int */
    private $clock;

    public function __construct(string $collectorPublicKeyBase64, ?callable $clock = null)
    {
        $key = base64_decode($collectorPublicKeyBase64, true);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('Private host attestation requires a pinned Ed25519 collector public key.');
        }
        $this->publicKey = $key;
        $this->clock = $clock ?? static fn(): int => time();
    }

    /**
     * Expected maps are administrator-pinned by each independent node:
     * file path => signed-release SHA-256; config policy ID => approved SHA-256.
     *
     * @param array<string,string> $expectedFiles
     * @param array<string,string> $expectedPrivateConfig
     * @return array{approved:bool,collector_id:string,issued_at:int,expires_at:int,files_checked:int,private_config_checked:int,mismatches:list<array<string,mixed>>}
     */
    public function assertAttested(
        string $signedEnvelope,
        string $expectedNonce,
        string $releaseVersion,
        string $commit,
        string $manifestDigest,
        string $artifactDigest,
        array $expectedFiles,
        array $expectedPrivateConfig
    ): array {
        if ($signedEnvelope === '' || strlen($signedEnvelope) > 1_048_576) {
            throw new RuntimeException('Private host attestation envelope is empty or exceeds the size limit.');
        }
        $nonce = strtolower(trim($expectedNonce));
        $version = trim($releaseVersion);
        if (str_starts_with($version, 'v')) $version = substr($version, 1);
        $commit = strtolower(trim($commit));
        $manifestDigest = strtolower(trim($manifestDigest));
        $artifactDigest = strtolower(trim($artifactDigest));
        if (!preg_match('/^[a-f0-9]{64}$/', $nonce)
            || !preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)
            || !preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
            || !preg_match('/^[a-f0-9]{64}$/', $artifactDigest)) {
            throw new RuntimeException('Expected private host attestation challenge or release identity is invalid.');
        }
        $this->validateExpectedMap($expectedFiles, false);
        $this->validateExpectedMap($expectedPrivateConfig, true);
        if ($expectedFiles === [] || count($expectedFiles) > 5000 || count($expectedPrivateConfig) > 100) {
            throw new RuntimeException('Private host attestation policy inventory is empty or exceeds its bounds.');
        }

        try {
            $envelope = json_decode($signedEnvelope, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Private host attestation envelope is not valid JSON.', 0, $exception);
        }
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['signature'] ?? null)) {
            throw new RuntimeException('Private host attestation envelope schema is invalid.');
        }
        $payloadBytes = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        if (!is_string($payloadBytes) || $payloadBytes === '' || strlen($payloadBytes) > 786432
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($signature, $payloadBytes, $this->publicKey)) {
            throw new RuntimeException('Private host attestation signature is invalid.');
        }
        try {
            $payload = json_decode($payloadBytes, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Signed private host attestation payload is not valid JSON.', 0, $exception);
        }
        if (!is_array($payload)
            || ($payload['schema_version'] ?? null) !== 1
            || !is_string($payload['collector_id'] ?? null)
            || !preg_match('/^[a-z0-9][a-z0-9._-]{2,63}$/', $payload['collector_id'])
            || !is_int($payload['issued_at'] ?? null) || $payload['issued_at'] < 1
            || !is_int($payload['expires_at'] ?? null)
            || $payload['expires_at'] <= $payload['issued_at']
            || $payload['expires_at'] > $payload['issued_at'] + 120
            || !is_string($payload['nonce'] ?? null) || !hash_equals($nonce, $payload['nonce'])
            || !is_string($payload['target_origin'] ?? null)
            || $payload['target_origin'] !== 'https://sentryiq.bichet.co.za'
            || ($payload['repository'] ?? null) !== 'Double-IQ/SentryIQ'
            || (string)($payload['repository_id'] ?? '') !== '1345956206'
            || ($payload['release_version'] ?? null) !== $version
            || ($payload['tag'] ?? null) !== 'v' . $version
            || ($payload['commit'] ?? null) !== $commit
            || ($payload['manifest_sha256'] ?? null) !== $manifestDigest
            || ($payload['artifact_sha256'] ?? null) !== $artifactDigest
            || !in_array($payload['decision'] ?? null, ['approve', 'reject'], true)
            || !is_array($payload['files'] ?? null) || !array_is_list($payload['files'])
            || !is_array($payload['private_config'] ?? null) || !array_is_list($payload['private_config'])) {
            throw new RuntimeException('Signed private host attestation identity, freshness, or schema is invalid.');
        }

        $now = ($this->clock)();
        if (!is_int($now) || $now < 1 || $payload['issued_at'] > $now + 15 || $payload['expires_at'] < $now) {
            throw new RuntimeException('Private host attestation is stale or not yet valid.');
        }

        $mismatches = [];
        $seenFiles = [];
        foreach ($payload['files'] as $entry) {
            if (!is_array($entry) || !is_string($entry['path'] ?? null)
                || !$this->safeRelativePath($entry['path'])
                || isset($seenFiles[$entry['path']])
                || !in_array($entry['result'] ?? null, ['match', 'missing', 'unreadable', 'symlink', 'permission_mismatch', 'digest_mismatch', 'unexpected'], true)) {
                throw new RuntimeException('Private host file evidence contains an invalid or duplicate entry.');
            }
            $path = $entry['path'];
            $seenFiles[$path] = true;
            if ($entry['result'] === 'unexpected') {
                if (isset($expectedFiles[$path])) {
                    throw new RuntimeException('A required file cannot be marked as unexpected.');
                }
                $mismatches[] = ['path' => $path, 'reason' => 'unexpected'];
                continue;
            }
            if (!isset($expectedFiles[$path]) || !is_string($entry['expected_sha256'] ?? null)
                || !hash_equals($expectedFiles[$path], $entry['expected_sha256'])) {
                throw new RuntimeException('Private host file evidence does not match the node-pinned release inventory.');
            }
            $observed = $entry['observed_sha256'] ?? null;
            if ($entry['result'] === 'match') {
                if (!is_string($observed) || !preg_match('/^[a-f0-9]{64}$/', $observed)
                    || !hash_equals($expectedFiles[$path], $observed)) {
                    throw new RuntimeException('Collector marked a private file as matching without the expected digest.');
                }
            } elseif ($observed !== null && (!is_string($observed) || !preg_match('/^[a-f0-9]{64}$/', $observed))) {
                throw new RuntimeException('Private host file evidence contains an invalid observed digest.');
            } elseif ($entry['result'] === 'digest_mismatch' && (!is_string($observed) || hash_equals($expectedFiles[$path], $observed))) {
                throw new RuntimeException('Private host digest-mismatch evidence does not show a changed digest.');
            }
            if ($entry['result'] !== 'match') {
                $mismatches[] = ['path' => $path, 'reason' => $entry['result']];
            }
        }
        foreach ($expectedFiles as $path => $_digest) {
            if (!isset($seenFiles[$path])) {
                throw new RuntimeException('Private host attestation omitted a required deployed file.');
            }
        }

        $seenConfig = [];
        foreach ($payload['private_config'] as $entry) {
            if (!is_array($entry) || !is_string($entry['policy_id'] ?? null)
                || !preg_match('/^[a-z0-9][a-z0-9._-]{1,95}$/', $entry['policy_id'])
                || isset($seenConfig[$entry['policy_id']])
                || !isset($expectedPrivateConfig[$entry['policy_id']])
                || !is_string($entry['expected_sha256'] ?? null)
                || !hash_equals($expectedPrivateConfig[$entry['policy_id']], $entry['expected_sha256'])
                || !in_array($entry['result'] ?? null, ['match', 'missing', 'unreadable', 'digest_mismatch'], true)) {
                throw new RuntimeException('Private host configuration evidence is invalid or outside the pinned policy.');
            }
            $id = $entry['policy_id'];
            $seenConfig[$id] = true;
            $observed = $entry['observed_sha256'] ?? null;
            if ($entry['result'] === 'match') {
                if (!is_string($observed) || !preg_match('/^[a-f0-9]{64}$/', $observed)
                    || !hash_equals($expectedPrivateConfig[$id], $observed)) {
                    throw new RuntimeException('Collector marked private configuration as matching without the approved digest.');
                }
            } elseif ($observed !== null && (!is_string($observed) || !preg_match('/^[a-f0-9]{64}$/', $observed))) {
                throw new RuntimeException('Private host configuration evidence contains an invalid observed digest.');
            } elseif ($entry['result'] === 'digest_mismatch' && (!is_string($observed) || hash_equals($expectedPrivateConfig[$id], $observed))) {
                throw new RuntimeException('Private host configuration mismatch evidence does not show a changed digest.');
            }
            if ($entry['result'] !== 'match') {
                $mismatches[] = ['path' => '@private-config/' . $id, 'reason' => $entry['result']];
            }
        }
        foreach ($expectedPrivateConfig as $id => $_digest) {
            if (!isset($seenConfig[$id])) {
                throw new RuntimeException('Private host attestation omitted an approved configuration policy entry.');
            }
        }

        if (($payload['decision'] === 'approve') !== ($mismatches === [])) {
            throw new RuntimeException('Private host attestation decision does not match its signed file evidence.');
        }
        return [
            'approved' => $payload['decision'] === 'approve',
            'collector_id' => $payload['collector_id'],
            'issued_at' => $payload['issued_at'],
            'expires_at' => $payload['expires_at'],
            'files_checked' => count($payload['files']),
            'private_config_checked' => count($payload['private_config']),
            'mismatches' => $mismatches,
        ];
    }

    /** @param array<string,string> $map */
    private function validateExpectedMap(array $map, bool $policyIds): void
    {
        foreach ($map as $key => $digest) {
            if (!is_string($key) || !is_string($digest)
                || ($policyIds
                    ? !preg_match('/^[a-z0-9][a-z0-9._-]{1,95}$/', $key)
                    : !$this->safeRelativePath($key))
                || !preg_match('/^[a-f0-9]{64}$/', $digest)) {
                throw new RuntimeException('Private host attestation expected inventory is invalid.');
            }
        }
    }

    private function safeRelativePath(string $path): bool
    {
        return $path !== '' && strlen($path) <= 240
            && !str_starts_with($path, '/') && !str_contains($path, '\\')
            && !str_contains($path, '%') && !str_contains($path, '//')
            && !preg_match('~(^|/)\.\.?(/|$)~', $path)
            && !preg_match('/[\x00-\x20\x7f]/', $path);
    }
}
