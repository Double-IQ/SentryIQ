<?php

declare(strict_types=1);

namespace SentryIQ\Updates;

use RuntimeException;

/** Restricts updater release downloads and every redirect hop to GitHub HTTPS hosts. */
final class ReleaseDownloadPolicy
{
    private const ALLOWED_HOSTS = [
        'github.com',
        'release-assets.githubusercontent.com',
        'objects.githubusercontent.com',
        'github-releases.githubusercontent.com',
    ];

    public static function assertAllowedUrl(string $url): void
    {
        $parts = parse_url($url);
        $host = strtolower((string)($parts['host'] ?? ''));
        if (($parts['scheme'] ?? '') !== 'https'
            || !in_array($host, self::ALLOWED_HOSTS, true)
            || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && (int)$parts['port'] !== 443)
            || isset($parts['fragment'])) {
            throw new RuntimeException('Update download redirect is outside the approved HTTPS GitHub hosts.');
        }
    }

    public static function isAllowedUrl(string $url): bool
    {
        try {
            self::assertAllowedUrl($url);
            return true;
        } catch (RuntimeException) {
            return false;
        }
    }
}
