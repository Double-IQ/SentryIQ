<?php

declare(strict_types=1);

function vault_unlock(string $password): array|false
{
    if ($password === 'throws') throw new RuntimeException('vault_unlock:key_wrap_failed');
    if ($password === 'valid') return ['records' => [], 'key' => str_repeat('k', 32)];
    return false;
}

$_SERVER['REQUEST_METHOD'] = 'GET';
require_once __DIR__ . '/../app/Auth/AuthFlow.php';

function authThrottleCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

authThrottleCheck(
    sentryiq_safe_vault_unlock('throws') === false,
    'An exception from vault_unlock must be normalized to a failed authentication result.'
);
authThrottleCheck(
    sentryiq_safe_vault_unlock('wrong') === false,
    'A false vault_unlock result must remain a failed authentication result.'
);
authThrottleCheck(
    sentryiq_safe_vault_unlock('') === false,
    'An empty password must fail without invoking vault_unlock.'
);
$valid = sentryiq_safe_vault_unlock('valid');
authThrottleCheck(
    is_array($valid) && isset($valid['key']),
    'A valid vault unlock result must be preserved.'
);

echo "Authentication throttle exception regression tests passed.\\n";
