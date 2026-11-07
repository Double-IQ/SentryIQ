<?php

declare(strict_types=1);

namespace SentryIQCloud\Gallery\Storage;

use DateTimeImmutable;
use DateTimeZone;
use RuntimeException;

final class BackblazeB2Signer
{
    private string $bucket;
    private string $region;
    private string $keyId;
    private string $applicationKey;
    private string $host;

    public function __construct(array $configuration)
    {
        $this->bucket = trim((string)($configuration['bucket'] ?? ''));
        $this->region = trim((string)($configuration['region'] ?? ''));
        $this->keyId = trim((string)($configuration['key_id'] ?? ''));
        $this->applicationKey = trim((string)($configuration['application_key'] ?? ''));

        if (!preg_match('/^[a-z0-9][a-z0-9.-]{3,61}[a-z0-9]$/', $this->bucket)
            || str_contains($this->bucket, '..')
            || !preg_match('/^[a-z0-9-]{3,32}$/', $this->region)
            || $this->keyId === ''
            || $this->applicationKey === '') {
            throw new RuntimeException('Backblaze B2 configuration is incomplete or invalid.');
        }

        $this->host = 's3.' . $this->region . '.backblazeb2.com';
    }

    /**
     * Load credentials from the protected SentryIQ runtime directory.
     * Expected file: <data-dir>/gallery_b2.php returning bucket, region,
     * key_id and application_key. The file must not be inside DOCUMENT_ROOT.
     */
    public static function fromRuntimeDirectory(string $dataDirectory): self
    {
        if ($dataDirectory === '' || !str_starts_with($dataDirectory, '/') || is_link($dataDirectory)) {
            throw new RuntimeException('SentryIQ secure runtime is unavailable.');
        }

        $runtime = realpath($dataDirectory);
        if ($runtime === false || !is_dir($runtime)) {
            throw new RuntimeException('SentryIQ secure runtime is unavailable.');
        }

        $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) ? realpath((string)$_SERVER['DOCUMENT_ROOT']) : false;
        if (is_string($documentRoot) && $documentRoot !== ''
            && ($runtime === $documentRoot || str_starts_with($runtime . DIRECTORY_SEPARATOR, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR))) {
            throw new RuntimeException('Gallery B2 credentials must be stored outside the public web root.');
        }

        $file = $runtime . '/gallery_b2.php';
        if (!is_file($file) || is_link($file) || !is_readable($file)) {
            throw new RuntimeException('Backblaze B2 credentials are not configured in the protected runtime.');
        }

        $permissions = @fileperms($file);
        if (is_int($permissions) && (($permissions & 0077) !== 0)) {
            throw new RuntimeException('Backblaze B2 credential file permissions must be owner-only (0600).');
        }

        $configuration = require $file;
        if (!is_array($configuration)) {
            throw new RuntimeException('Backblaze B2 configuration is invalid.');
        }

        return new self($configuration);
    }

    public static function newObjectKey(string $role): string
    {
        if (!in_array($role, ['original', 'thumbnail', 'preview', 'metadata'], true)) {
            throw new RuntimeException('Invalid Gallery object role.');
        }

        return 'gallery/v1/' . bin2hex(random_bytes(32)) . '/' . $role;
    }

    /**
     * Create a short-lived SigV4 URL for one exact object and HTTP method.
     * Only the Host header is signed; callers must not alter the URL host/path.
     */
    public function presign(
        string $method,
        string $objectKey,
        int $expiresSeconds = 300,
        ?DateTimeImmutable $now = null
    ): string {
        $method = strtoupper(trim($method));
        if (!in_array($method, ['PUT', 'GET', 'HEAD', 'DELETE'], true)) {
            throw new RuntimeException('Unsupported Backblaze B2 signed method.');
        }
        if (!preg_match('#^gallery/v1/[a-f0-9]{64}/(original|thumbnail|preview|metadata)$#', $objectKey)) {
            throw new RuntimeException('Invalid Gallery object key.');
        }
        if ($expiresSeconds < 1 || $expiresSeconds > 600) {
            throw new RuntimeException('Backblaze B2 authorization expiry must be between 1 and 600 seconds.');
        }

        $now = ($now ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'));
        $amzDate = $now->format('Ymd\THis\Z');
        $dateStamp = $now->format('Ymd');
        $scope = $dateStamp . '/' . $this->region . '/s3/aws4_request';

        $canonicalUri = '/' . $this->encodePathSegment($this->bucket);
        foreach (explode('/', $objectKey) as $segment) {
            $canonicalUri .= '/' . $this->encodePathSegment($segment);
        }

        $query = [
            'X-Amz-Algorithm' => 'AWS4-HMAC-SHA256',
            'X-Amz-Credential' => $this->keyId . '/' . $scope,
            'X-Amz-Date' => $amzDate,
            'X-Amz-Expires' => (string)$expiresSeconds,
            'X-Amz-SignedHeaders' => 'host',
        ];
        ksort($query, SORT_STRING);
        $canonicalQuery = $this->canonicalQuery($query);
        $canonicalHeaders = 'host:' . $this->host . "\n";
        $signedHeaders = 'host';
        $canonicalRequest = $method . "\n"
            . $canonicalUri . "\n"
            . $canonicalQuery . "\n"
            . $canonicalHeaders . "\n"
            . $signedHeaders . "\n"
            . 'UNSIGNED-PAYLOAD';

        $stringToSign = "AWS4-HMAC-SHA256\n"
            . $amzDate . "\n"
            . $scope . "\n"
            . hash('sha256', $canonicalRequest);

        $dateKey = hash_hmac('sha256', $dateStamp, 'AWS4' . $this->applicationKey, true);
        $regionKey = hash_hmac('sha256', $this->region, $dateKey, true);
        $serviceKey = hash_hmac('sha256', 's3', $regionKey, true);
        $signingKey = hash_hmac('sha256', 'aws4_request', $serviceKey, true);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        $query['X-Amz-Signature'] = $signature;
        return 'https://' . $this->host . $canonicalUri . '?' . $this->canonicalQuery($query);
    }

    private function encodePathSegment(string $segment): string
    {
        return str_replace('%7E', '~', rawurlencode($segment));
    }

    private function canonicalQuery(array $query): string
    {
        $pairs = [];
        foreach ($query as $name => $value) {
            $pairs[] = $this->encodePathSegment((string)$name) . '=' . $this->encodePathSegment((string)$value);
        }
        return implode('&', $pairs);
    }
}
