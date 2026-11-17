<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityReleaseArtifactFetcher.php';
require_once __DIR__ . '/../app/Updates/IntegrityNodeScheduledRunner.php';

use SentryIQ\\Updates\\IntegrityNodeScheduledRunner;
use SentryIQ\\Updates\\IntegrityReleaseArtifactFetcher;
use RuntimeException;

function scheduledAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = sys_get_temp_dir() . '/sentryiq-scheduled-' . bin2hex(random_bytes(8));
$webroot = $root . '/public';
$private = $root . '/private';
mkdir($webroot, 0700, true);
mkdir($private, 0700, true);
$fetcher = new IntegrityReleaseArtifactFetcher();
$alerts = [];
$fetchCalls = 0;
$runner = new IntegrityNodeScheduledRunner(
    'integrity-c',
    $fetcher,
    static fn(): array => ['version' => '0.1.3', 'commit' => str_repeat('a', 40), 'installed_version' => '0.1.3'],
    static function (...$args) use (&$fetchCalls): array {
        $fetchCalls++;
        return ['approved' => true, 'report' => 'signed-envelope'];
    },
    static function (string $node, string $reason, array $context) use (&$alerts): void {
        $alerts[] = [$node, $reason];
    },
    $private,
    $webroot,
    'https://sentryiq.bichet.co.za',
    ['index.php']
);

// This runner is intentionally not executed: network access is not part of
// this unit test. Constructor policy and the no-Node-4 boundary are tested.
$rejectedA = false;
try {
    new IntegrityNodeScheduledRunner(
        'integrity-a', $fetcher,
        static fn(): array => [],
        static fn(): array => [],
        static function (): void {},
        $private, $webroot, 'https://sentryiq.bichet.co.za', ['index.php'], null
    );
} catch (RuntimeException) {
    $rejectedA = true;
}
scheduledAssert($rejectedA, 'Nodes A/B must not start without their Node 4 event exchange.');

$rejectedC = false;
try {
    new IntegrityNodeScheduledRunner(
        'integrity-c', $fetcher,
        static fn(): array => [],
        static fn(): array => [],
        static function (): void {},
        $private, $webroot, 'https://sentryiq.bichet.co.za', ['index.php'],
        new SentryIQ\\Updates\\IntegrityNodeEventRunner(
            new SentryIQ\\Updates\\IntegrityEventClient(
                'https://sentryiq.bichet.co.za/integrity_event.php',
                'integrity-a',
                str_repeat('x', 48),
                static fn(): array => []
            ),
            static function (): void {}
        )
    );
} catch (RuntimeException) {
    $rejectedC = true;
}
scheduledAssert($rejectedC, 'Node C must not depend on Node 4.');

rmdir($private);
rmdir($webroot);
rmdir($root);
echo "Integrity node scheduled runner tests passed.\\n";
