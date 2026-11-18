<?php
declare(strict_types=1);

function deploymentCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$root = dirname(__DIR__);
$ini = file_get_contents($root . '/.user.ini');
$apache = file_get_contents($root . '/.htaccess');
deploymentCheck(is_string($ini) && is_string($apache), 'Unable to read deployment hardening files.');

foreach ([
    'display_errors = Off',
    'display_startup_errors = Off',
    'html_errors = Off',
    'log_errors = On',
    'expose_php = Off',
    'allow_url_include = Off',
    'session.use_strict_mode = 1',
    'session.use_only_cookies = 1',
    'session.cookie_secure = 1',
    'session.cookie_httponly = 1',
    'session.cookie_samesite = Strict',
] as $setting) {
    deploymentCheck(str_contains($ini, $setting), 'Missing PHP hardening setting: ' . $setting);
}

deploymentCheck(
    str_contains($apache, 'RewriteRule ^(?:sentryiq_config\.php|auth_flow\.php|\.user\.ini)$ - [F,L]'),
    'Apache rules must deny direct requests to root configuration and bootstrap files.'
);

echo "PHP and Apache deployment hardening source checks passed.\n";
