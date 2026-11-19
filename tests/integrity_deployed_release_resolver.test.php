<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/IntegrityDeployedReleaseResolver.php';

use SentryIQ\Updates\IntegrityDeployedReleaseResolver;

function deployedResolverAssert(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function deployedResolverReject(callable $operation, string $message): void
{
    try { $operation(); } catch (Throwable) { return; }
    throw new RuntimeException($message);
}

$commit = str_repeat('a', 40);
$requests = [];
$resolver = new IntegrityDeployedReleaseResolver(
    'https://sentryiq.bichet.co.za',
    static function (string $url, int $maxBytes) use (&$requests, $commit): array {
        $requests[] = $url;
        if (str_ends_with($url, '/VERSION')) {
            return ['status' => 200, 'body' => "1.2.3\n"];
        }
        return ['status' => 200, 'body' => json_encode(['sha' => $commit], JSON_THROW_ON_ERROR)];
    }
);
$resolved = $resolver();
deployedResolverAssert($resolved === ['version' => '1.2.3', 'commit' => $commit], 'Resolver must return the live version and canonical tag commit.');
deployedResolverAssert($requests === [
    'https://sentryiq.bichet.co.za/VERSION',
    'https://api.github.com/repos/Double-IQ/SentryIQ/commits/v1.2.3',
], 'Resolver must use the live VERSION file and the canonical repository tag.');

$badVersion = new IntegrityDeployedReleaseResolver(
    'https://sentryiq.bichet.co.za',
    static fn(string $url, int $maxBytes): array => ['status' => 200, 'body' => 'latest']
);
deployedResolverReject(fn() => $badVersion(), 'Non-semver public VERSION must be rejected.');

$badCommit = new IntegrityDeployedReleaseResolver(
    'https://sentryiq.bichet.co.za',
    static fn(string $url, int $maxBytes): array => str_ends_with($url, '/VERSION')
        ? ['status' => 200, 'body' => '1.2.3']
        : ['status' => 200, 'body' => '{"sha":"short"}']
);
deployedResolverReject(fn() => $badCommit(), 'A non-full Git commit must be rejected.');

$badStatus = new IntegrityDeployedReleaseResolver(
    'https://sentryiq.bichet.co.za',
    static fn(string $url, int $maxBytes): array => ['status' => 302, 'body' => '']
);
deployedResolverReject(fn() => $badStatus(), 'Redirected or non-200 VERSION responses must be rejected.');

deployedResolverReject(
    fn() => new IntegrityDeployedReleaseResolver('https://attacker.example'),
    'Resolver must pin the canonical SentryIQ origin.'
);

$tokenedResolver = new IntegrityDeployedReleaseResolver(
    'https://sentryiq.bichet.co.za',
    static fn(string $url, int $maxBytes): array => ['status' => 500, 'body' => ''],
    'github_pat_' . str_repeat('A', 40)
);
deployedResolverReject(
    fn() => new IntegrityDeployedReleaseResolver('https://sentryiq.bichet.co.za', null, 'bad-token'),
    'Resolver must reject malformed GitHub API tokens.'
);

echo "Integrity deployed release resolver tests passed.\n";
