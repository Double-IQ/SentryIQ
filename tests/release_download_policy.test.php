<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Updates/ReleaseDownloadPolicy.php';

use SentryIQ\\Updates\\ReleaseDownloadPolicy;

function downloadPolicyAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$allowed = [
    'https://github.com/Double-IQ/SentryIQ/releases/download/v1.2.3/package.zip',
    'https://release-assets.githubusercontent.com/assets/123?token=example',
    'https://objects.githubusercontent.com/assets/123',
    'https://github-releases.githubusercontent.com/assets/123',
];
foreach ($allowed as $url) {
    downloadPolicyAssert(ReleaseDownloadPolicy::isAllowedUrl($url), 'Expected approved GitHub URL to pass: ' . $url);
}

$rejected = [
    'http://github.com/Double-IQ/SentryIQ/archive.zip',
    'https://evil.example/redirect',
    'https://github.com.evil.example/redirect',
    'https://evilgithub.com/redirect',
    'https://user:pass@github.com/redirect',
    'https://github.com:8443/redirect',
    'https://github.com/redirect#fragment',
    '//release-assets.githubusercontent.com/redirect',
];
foreach ($rejected as $url) {
    downloadPolicyAssert(!ReleaseDownloadPolicy::isAllowedUrl($url), 'Expected unapproved URL to be rejected: ' . $url);
}

echo "Release download redirect policy tests passed.\\n";
