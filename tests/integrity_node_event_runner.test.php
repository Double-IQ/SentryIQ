<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityEventClient.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeEventRunner.php';

use SentryIQ\Updates\IntegrityEventClient;
use SentryIQ\Updates\IntegrityNodeEventRunner;

function runnerAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sentryiq-runner-' . bin2hex(random_bytes(8));
if (!mkdir($directory, 0700)) {
    throw new RuntimeException('Unable to create temporary runner directory.');
}
$manifestPath = $directory . DIRECTORY_SEPARATOR . 'manifest.json';
$artifactPath = $directory . DIRECTORY_SEPARATOR . 'release.zip';
file_put_contents($manifestPath, '{"release":"test"}');
file_put_contents($artifactPath, 'test-artifact');

try {
    $manifestDigest = hash_file('sha256', $manifestPath);
    $artifactDigest = hash_file('sha256', $artifactPath);
    $seenNonce = null;
    $client = new IntegrityEventClient(
        'https://sentryiq.bichet.co.za/integrity_event.php',
        'integrity-b',
        str_repeat('x', 48),
        static function (string $url, array $headers, string $body) use (&$seenNonce): array {
            $request = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
            if (($request['action'] ?? null) === 'challenge') {
                return [
                    'status' => 201,
                    'body' => json_encode([
                        'status' => 'ok',
                        'node_id' => 'integrity-b',
                        'nonce' => str_repeat('e', 64),
                        'expires_at' => time() + 300,
                    ], JSON_THROW_ON_ERROR),
                ];
            }
            return [
                'status' => 202,
                'body' => json_encode(['status' => 'accepted', 'report_id' => 'node4-ack'], JSON_THROW_ON_ERROR),
            ];
        }
    );

    $runnerAlerts = [];
    $runner = new IntegrityNodeEventRunner(
        $client,
        static function (string $nodeId, string $reason, array $context) use (&$runnerAlerts): void {
            $runnerAlerts[] = [$nodeId, $reason];
        }
    );
    $result = $runner->run(
        static function (string $nonce) use (&$seenNonce, $manifestDigest, $artifactDigest): array {
            $seenNonce = $nonce;
            return [
                'approved' => true,
                'report' => '{"signed":"report"}',
                'manifest_sha256' => $manifestDigest,
                'artifact_sha256' => $artifactDigest,
            ];
        },
        $manifestPath,
        $artifactPath,
        'v0.1.3',
        str_repeat('a', 40),
        'https://sentryiq.bichet.co.za/'
    );

    runnerAssert($seenNonce === str_repeat('e', 64), 'Local node verification must receive the Node 4 nonce.');
    runnerAssert(($result['event_acknowledgement']['report_id'] ?? null) === 'node4-ack', 'Node 4 acknowledgement must be returned.');

    $downClient = new IntegrityEventClient(
        'https://sentryiq.bichet.co.za/integrity_event.php',
        'integrity-b',
        str_repeat('x', 48),
        static function (): array {
            throw new RuntimeException('synthetic Node 4 outage');
        }
    );
    $downRunner = new IntegrityNodeEventRunner(
        $downClient,
        static function (string $nodeId, string $reason, array $context) use (&$runnerAlerts): void {
            $runnerAlerts[] = [$nodeId, $reason];
        }
    );
    $outageAlerted = false;
    try {
        $downRunner->run(
            static fn(string $nonce): array => [],
            $manifestPath,
            $artifactPath,
            '0.1.3',
            str_repeat('a', 40),
            'https://sentryiq.bichet.co.za'
        );
    } catch (RuntimeException $exception) {
        $outageAlerted = str_contains($exception->getMessage(), 'independent owner alert');
    }
    runnerAssert($outageAlerted && in_array(['integrity-b', 'node4_challenge_unavailable'], $runnerAlerts, true),
        'Node 4 transport failure must trigger the node’s independent owner alert before stopping.');

    try {
        $runner->run(
            static fn(string $nonce): array => [
                'report' => '{"signed":"report"}',
                'manifest_sha256' => str_repeat('0', 64),
                'artifact_sha256' => $artifactDigest,
            ],
            $manifestPath,
            $artifactPath,
            '0.1.3',
            str_repeat('a', 40),
            'https://sentryiq.bichet.co.za'
        );
        throw new RuntimeException('Runner must reject changed verification inputs.');
    } catch (RuntimeException $exception) {
        runnerAssert(str_contains($exception->getMessage(), 'inputs changed'), 'Input mismatch should fail before report submission.');
    }
    $verificationFailureAlerted = false;
    try {
        $runner->run(
            static function (string $nonce): array {
                throw new RuntimeException('synthetic local verifier failure');
            },
            $manifestPath,
            $artifactPath,
            '0.1.3',
            str_repeat('a', 40),
            'https://sentryiq.bichet.co.za'
        );
    } catch (RuntimeException $exception) {
        $verificationFailureAlerted = str_contains($exception->getMessage(), 'independent owner alert');
    }
    runnerAssert(
        $verificationFailureAlerted
            && in_array(['integrity-b', 'local_verification_failed'], $runnerAlerts, true),
        'Any local verification failure must trigger the independent owner alert.'
    );

} finally {
    @unlink($manifestPath);
    @unlink($artifactPath);
    @rmdir($directory);
}

echo "Integrity node event runner tests passed.\n";
