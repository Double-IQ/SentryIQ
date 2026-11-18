<?php

declare(strict_types=1);

function vault_unlock(string $password): array|false
{
    if ($password === 'throws') {
        throw new RuntimeException('Simulated malformed vault envelope.');
    }
    if ($password === 'valid') {
        return ['key' => str_repeat('k', 32), 'records' => []];
    }
    return false;
}

$_SERVER['REQUEST_METHOD'] = 'GET';
require_once __DIR__ . '/../app/Auth/AuthFlow.php';

function authUnlockCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

authUnlockCheck(
    sentryiq_try_vault_unlock('throws') === false,
    'A vault exception must become a normal failed unlock result.'
);
authUnlockCheck(
    sentryiq_try_vault_unlock('wrong') === false,
    'An ordinary invalid password must remain a failed unlock result.'
);
authUnlockCheck(
    sentryiq_try_vault_unlock('') === false,
    'An empty password must not invoke vault unlock.'
);
$result = sentryiq_try_vault_unlock('valid');
authUnlockCheck(
    is_array($result) && strlen((string)($result['key'] ?? '')) === 32,
    'A successful vault unlock result must be preserved.'
);

echo "Password unlock exception handling tests passed.\n";
