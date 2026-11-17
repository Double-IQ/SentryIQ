<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Append-only private evidence retention for independent Node C.
 * Every stored report is signature-verified against Node C's public key.
 */
final class IntegrityNodeEvidenceStore
{
    private string $directory;
    private string $publicKey;

    public function __construct(
        string $privateDataDirectory,
        string $publicWebRoot,
        string $nodePublicKeyBase64
    ) {
        $private = realpath($privateDataDirectory);
        $web = realpath($publicWebRoot);
        if (!is_string($private) || !is_dir($private) || is_link($privateDataDirectory)
            || !is_string($web) || !is_dir($web) || is_link($publicWebRoot)) {
            throw new RuntimeException('Node C evidence requires real private-data and public-web directories.');
        }
        if ($private === $web
            || str_starts_with($private . DIRECTORY_SEPARATOR, rtrim($web, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
            throw new RuntimeException('Node C evidence must be stored outside the public webroot.');
        }
        $publicKey = base64_decode($nodePublicKeyBase64, true);
        if (!is_string($publicKey) || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('Node C evidence requires its own valid base64 Ed25519 public key.');
        }
        $directory = $private . '/integrity-node-c-evidence';
        if (is_link($directory) || (file_exists($directory) && !is_dir($directory))) {
            throw new RuntimeException('Node C evidence directory must be a real directory, not a symlink.');
        }
        if (!is_dir($directory) && !@mkdir($directory, 0700)) {
            throw new RuntimeException('Unable to create private Node C evidence storage.');
        }
        if (is_link($directory) || !@chmod($directory, 0700)
            || ((fileperms($directory) ?: 0) & 0077) !== 0) {
            throw new RuntimeException('Node C evidence directory must have private 0700 permissions.');
        }
        $this->directory = $directory;
        $this->publicKey = $publicKey;
    }

    /**
     * Verify and durably append one signed Node C report.
     *
     * @return array{evidence_id:string,evidence_path:string,stored_at:int}
     */
    public function append(string $signedEnvelope, string $expectedVersion, string $expectedCommit, string $expectedManifestDigest, string $expectedArtifactDigest, bool $expectedApproved, string $expectedNonce): array
    {
        if ($signedEnvelope === '' || strlen($signedEnvelope) > 65536) {
            throw new RuntimeException('Node C signed evidence is empty or exceeds the size limit.');
        }
        try {
            $envelope = json_decode($signedEnvelope, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Node C signed evidence envelope is not valid JSON.', 0, $exception);
        }
        if (!is_array($envelope) || !is_string($envelope['payload'] ?? null)
            || !is_string($envelope['signature'] ?? null)) {
            throw new RuntimeException('Node C signed evidence envelope schema is invalid.');
        }
        $payloadBytes = base64_decode($envelope['payload'], true);
        $signature = base64_decode($envelope['signature'], true);
        if (!is_string($payloadBytes) || $payloadBytes === '' || strlen($payloadBytes) > 32768
            || !is_string($signature) || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($signature, $payloadBytes, $this->publicKey)) {
            throw new RuntimeException('Node C evidence signature is invalid.');
        }
        try {
            $payload = json_decode($payloadBytes, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Node C signed evidence payload is not valid JSON.', 0, $exception);
        }
        if (!is_array($payload)
            || ($payload['schema_version'] ?? null) !== 2
            || ($payload['node_id'] ?? null) !== 'integrity-c'
            || ($payload['repository'] ?? null) !== 'Double-IQ/SentryIQ'
            || (string)($payload['repository_id'] ?? '') !== '1345956206'
            || !in_array($payload['decision'] ?? null, ['approve', 'reject'], true)
            || !is_string($payload['release_version'] ?? null)
            || !preg_match('/^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$/', $payload['release_version'])
            || !is_string($payload['commit'] ?? null) || !preg_match('/^[a-f0-9]{40}$/', $payload['commit'])
            || !is_string($payload['artifact_sha256'] ?? null) || !preg_match('/^[a-f0-9]{64}$/', $payload['artifact_sha256'])
            || !is_string($payload['nonce'] ?? null) || !preg_match('/^[a-f0-9]{64}$/', $payload['nonce'])
            || !is_int($payload['issued_at'] ?? null) || $payload['issued_at'] < 1
            || !is_int($payload['expires_at'] ?? null) || $payload['expires_at'] < $payload['issued_at']
            || $payload['expires_at'] > $payload['issued_at'] + 300
            || ($payload['workflow_path'] ?? null) !== '.github/workflows/release.yml'
            || ($payload['tag'] ?? null) !== 'v' . $payload['release_version']) {
            throw new RuntimeException('Node C signed evidence release identity or schema is invalid.');
        }
        $expectedNonce = strtolower(trim($expectedNonce));
        if (!preg_match('/^[a-f0-9]{64}$/', $expectedNonce)
            || !hash_equals($expectedNonce, $payload['nonce'])
            || $payload['issued_at'] > time() + 30
            || $payload['expires_at'] < time()) {
            throw new RuntimeException('Node C signed evidence nonce or freshness is invalid.');
        }
        if (!hash_equals(ltrim($expectedVersion, 'v'), $payload['release_version'])
            || !hash_equals(strtolower($expectedCommit), $payload['commit'])
            || !hash_equals(strtolower($expectedManifestDigest), (string)($payload['manifest_sha256'] ?? ''))
            || !hash_equals(strtolower($expectedArtifactDigest), $payload['artifact_sha256'])
            || (($payload['decision'] === 'approve') !== $expectedApproved)) {
            throw new RuntimeException('Node C signed evidence does not bind the staged release artifacts.');
        }

        $origin = $payload['target_origin'] ?? null;
        $parts = is_string($origin) ? parse_url($origin) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? null) !== 'https'
            || strtolower((string)($parts['host'] ?? '')) !== 'sentryiq.bichet.co.za'
            || ($parts['path'] ?? '') !== '' || isset($parts['port']) && $parts['port'] !== 443
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !is_string($payload['manifest_sha256'] ?? null)
            || !preg_match('/^[a-f0-9]{64}$/', $payload['manifest_sha256'])) {
            throw new RuntimeException('Node C signed evidence origin or manifest digest is invalid.');
        }

        $checked = $payload['checked_paths'] ?? null;
        $mismatches = $payload['mismatches'] ?? null;
        if (!is_array($checked) || !array_is_list($checked) || count($checked) > 100
            || !is_array($mismatches) || !array_is_list($mismatches) || count($mismatches) > 100) {
            throw new RuntimeException('Node C signed evidence path lists are invalid.');
        }
        $seenChecked = [];
        foreach ($checked as $path) {
            if (!is_string($path) || !self::safeEvidencePath($path) || isset($seenChecked[$path])) {
                throw new RuntimeException('Node C signed evidence contains an unsafe or duplicate checked path.');
            }
            $seenChecked[$path] = true;
        }
        foreach ($mismatches as $item) {
            if (!is_array($item) || !is_string($item['path'] ?? null)
                || !self::safeEvidencePath($item['path']) || !isset($seenChecked[$item['path']])
                || !in_array($item['reason'] ?? null, ['content_mismatch', 'fetch_failed', 'security_header_mismatch', 'private_host_attestation_failed'], true)) {
                throw new RuntimeException('Node C signed evidence contains an invalid mismatch record.');
            }
        }
        if (($payload['decision'] === 'approve') !== ($mismatches === [])) {
            throw new RuntimeException('Node C signed decision does not match its signed mismatch evidence.');
        }

        $existingRecords = glob($this->directory . '/report-*.json');
        if (!is_array($existingRecords) || count($existingRecords) >= 10000) {
            throw new RuntimeException('Node C private evidence store is full or unreadable.');
        }
        $evidenceId = hash('sha256', $signedEnvelope);
        $filename = 'report-' . $payload['issued_at'] . '-' . $payload['nonce'] . '.json';
        $destination = $this->directory . '/' . $filename;
        $record = [
            'format' => 1,
            'node_id' => 'integrity-c',
            'evidence_id' => $evidenceId,
            'stored_at' => time(),
            'release_version' => $payload['release_version'],
            'commit' => $payload['commit'],
            'manifest_sha256' => $payload['manifest_sha256'],
            'artifact_sha256' => $payload['artifact_sha256'],
            'decision' => $payload['decision'],
            'target_origin' => rtrim($origin, '/'),
            'checked_paths' => $checked,
            'mismatches' => $mismatches,
            'signed_report' => $signedEnvelope,
        ];
        $bytes = json_encode($record, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
        $temporary = $destination . '.tmp-' . bin2hex(random_bytes(8));
        $stream = @fopen($temporary, 'xb');
        if ($stream === false) {
            throw new RuntimeException('Unable to create private Node C evidence record.');
        }
        $written = fwrite($stream, $bytes);
        $flushed = fflush($stream);
        fclose($stream);
        if ($written !== strlen($bytes) || !$flushed || !@chmod($temporary, 0600)
            || !@link($temporary, $destination)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to atomically append private Node C evidence.');
        }
        @unlink($temporary);
        if (((fileperms($destination) ?: 0) & 0077) !== 0) {
            @unlink($destination);
            throw new RuntimeException('Node C evidence record permissions are unsafe.');
        }

        return [
            'evidence_id' => $evidenceId,
            'evidence_path' => $destination,
            'stored_at' => $record['stored_at'],
        ];
    }

    private static function safeEvidencePath(string $path): bool
    {
        return $path !== '' && strlen($path) <= 512 && !str_starts_with($path, '/')
            && !str_contains($path, '\\') && !str_contains($path, '//')
            && !preg_match('~(^|/)\\.\\.?(/|$)~', $path)
            && !preg_match('/[%?#\\x00-\\x1f]/', $path);
    }
}
