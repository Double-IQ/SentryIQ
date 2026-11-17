<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/**
 * Creates a short-lived, detached Ed25519 approval report for one Integrity Node.
 *
 * The private key is supplied by the node's protected runtime configuration.
 * It must never be committed, packaged with SentryIQ, or shared between nodes.
 */
final class IntegrityReportSigner
{
    private const REPOSITORY = 'Double-IQ/SentryIQ';
    private const REPOSITORY_ID = '1345956206';
    private const WORKFLOW_PATH = '.github/workflows/release.yml';
    private const REPORT_TTL_SECONDS = 300;

    /** @var callable():int */
    private $clock;

    private string $secretKey;

    /**
     * @param callable():int|null $clock Test seam; production uses the system clock.
     */
    public function __construct(
        private readonly string $nodeId,
        string $base64SecretKey,
        ?callable $clock = null
    ) {
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{2,63}$/', $nodeId)) {
            throw new RuntimeException('Integrity Node identity is invalid.');
        }

        $secretKey = base64_decode($base64SecretKey, true);
        if (!is_string($secretKey) || strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('Integrity Node signing key must be a base64 Ed25519 secret key.');
        }

        $this->secretKey = $secretKey;
        $this->clock = $clock ?? static fn(): int => time();
    }

    public function nodeId(): string
    {
        return $this->nodeId;
    }

    /**
     * @param string $releaseVersion Stable MAJOR.MINOR.PATCH version, with optional leading v.
     * @param string $commit Full lowercase or uppercase Git commit SHA.
     * @param string $artifactSha256 SHA-256 digest of the exact release ZIP.
     * @param string $nonce 32-byte random nonce encoded as 64 hexadecimal characters.
     */
    public function createReport(
        string $releaseVersion,
        string $commit,
        string $artifactSha256,
        string $nonce,
        string $decision = 'approve',
        array $eventEvidence = []
    ): string {
        $version = $this->normalizeVersion($releaseVersion);
        $commit = strtolower(trim($commit));
        $digest = strtolower(trim($artifactSha256));
        $nonce = strtolower(trim($nonce));

        if (!preg_match('/^[a-f0-9]{40}$/', $commit)
            || !preg_match('/^[a-f0-9]{64}$/', $digest)
            || !preg_match('/^[a-f0-9]{64}$/', $nonce)) {
            throw new RuntimeException('Release identity or attempt nonce is invalid.');
        }
        if (!in_array($decision, ['approve', 'reject'], true)) {
            throw new RuntimeException('Integrity Node decision must be approve or reject.');
        }

        $issuedAt = ($this->clock)();
        if (!is_int($issuedAt) || $issuedAt < 1) {
            throw new RuntimeException('Integrity Node clock returned an invalid timestamp.');
        }

        if ($eventEvidence !== []) {
            $eventEvidence = $this->validateEventEvidence($eventEvidence);
        }

        $payload = [
            'schema_version' => $eventEvidence === [] ? 1 : 2,
            'node_id' => $this->nodeId,
            'decision' => $decision,
            'issued_at' => $issuedAt,
            'expires_at' => $issuedAt + self::REPORT_TTL_SECONDS,
            'nonce' => $nonce,
            'repository' => self::REPOSITORY,
            'repository_id' => self::REPOSITORY_ID,
            'release_version' => $version,
            'tag' => 'v' . $version,
            'commit' => $commit,
            'artifact_sha256' => $digest,
            'workflow_path' => self::WORKFLOW_PATH,
        ];

        if ($eventEvidence !== []) {
            $payload += $eventEvidence;
        }

        try {
            $rawPayload = json_encode(
                $payload,
                JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
            );
        } catch (\JsonException $exception) {
            throw new RuntimeException('Unable to encode Integrity Node report.', 0, $exception);
        }

        $signature = sodium_crypto_sign_detached($rawPayload, $this->secretKey);
        $envelope = [
            'payload' => base64_encode($rawPayload),
            'signature' => base64_encode($signature),
        ];

        try {
            $encoded = json_encode($envelope, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (\JsonException $exception) {
            throw new RuntimeException('Unable to encode Integrity Node report envelope.', 0, $exception);
        }

        if (strlen($encoded) > 16384) {
            throw new RuntimeException('Integrity Node report exceeds the verifier size limit.');
        }

        return $encoded;
    }

    /** @return array{target_origin:string,manifest_sha256:string,checked_paths:list<string>,mismatches:list<array{path:string,reason:string}>} */
    private function validateEventEvidence(array $evidence): array
    {
        $origin = $evidence['target_origin'] ?? null;
        $manifestDigest = $evidence['manifest_sha256'] ?? null;
        $checked = $evidence['checked_paths'] ?? null;
        $mismatches = $evidence['mismatches'] ?? null;
        $parts = is_string($origin) ? parse_url($origin) : false;
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || !is_string($manifestDigest) || !preg_match('/^[a-f0-9]{64}$/', $manifestDigest)
            || !is_array($checked) || !array_is_list($checked) || count($checked) > 100
            || !is_array($mismatches) || !array_is_list($mismatches) || count($mismatches) > 100) {
            throw new RuntimeException('Signed event evidence is incomplete or invalid.');
        }
        $checkedPaths = [];
        foreach ($checked as $path) {
            if (!is_string($path) || !$this->isSafeEvidencePath($path) || in_array($path, $checkedPaths, true)) {
                throw new RuntimeException('Signed event evidence contains an unsafe or duplicate checked path.');
            }
            $checkedPaths[] = $path;
        }
        $normalizedMismatches = [];
        foreach ($mismatches as $item) {
            if (!is_array($item) || !is_string($item['path'] ?? null) || !$this->isSafeEvidencePath($item['path'])
                || !in_array($item['reason'] ?? null, ['content_mismatch', 'fetch_failed'], true)) {
                throw new RuntimeException('Signed event evidence contains an invalid mismatch record.');
            }
            $normalizedMismatches[] = ['path' => $item['path'], 'reason' => $item['reason']];
        }
        return [
            'target_origin' => rtrim($origin, '/'),
            'manifest_sha256' => strtolower($manifestDigest),
            'checked_paths' => $checkedPaths,
            'mismatches' => $normalizedMismatches,
        ];
    }

    private function isSafeEvidencePath(string $path): bool
    {
        return $path !== '' && strlen($path) <= 512 && !str_starts_with($path, '/')
            && !str_contains($path, '\\') && !preg_match('~(^|/)\\.\\.?(/|$)~', $path)
            && !preg_match('/[?#\\x00-\\x1f]/', $path);
    }

    private function normalizeVersion(string $version): string
    {
        $version = trim($version);
        if (str_starts_with($version, 'v')) {
            $version = substr($version, 1);
        }
        if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/', $version)) {
            throw new RuntimeException('Release version must use stable MAJOR.MINOR.PATCH format.');
        }
        return $version;
    }
}
