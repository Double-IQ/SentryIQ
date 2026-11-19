<?php

declare(strict_types=1);

/**
 * Resolve the explicitly configured first-run storage path.
 *
 * The hosting environment must provide SENTRYIQ_DATA_DIR. Deliberately do
 * not infer a path by walking up from the application source directory.
 */
function sentryiq_first_run_configured_data_dir(?array $server = null, ?string $environment = null): string
{
    $server ??= $_SERVER;
    if ($environment === null) {
        $environment = getenv('SENTRYIQ_DATA_DIR');
        if (!is_string($environment) || $environment === '') {
            $environment = (string)($server['SENTRYIQ_DATA_DIR'] ?? '');
        }
    }

    $path = trim($environment);
    if ($path === '' || !str_starts_with($path, '/') || str_contains($path, "\0")) {
        return '';
    }

    // Reject ambiguous/non-canonical path components before any mkdir call.
    $parts = explode('/', $path);
    foreach ($parts as $part) {
        if ($part === '.' || $part === '..') return '';
    }

    $normalized = rtrim($path, '/');
    if ($normalized === '' || $normalized === '/') return '';
    if (preg_match('#/(public_html|htdocs|www)(/|$)#i', $normalized)) return '';

    return $normalized;
}
