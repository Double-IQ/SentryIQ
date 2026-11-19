<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Security/SecurityBootstrap.php';

function sessionExpiryCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

$now = 100000;
$key = str_repeat('k', 32);
$active = [
    'master_key' => $key,
    'authenticated_at' => $now - 3600,
    'last_activity' => $now - 30,
];
sessionExpiryCheck(
    !sentryiq_authenticated_session_expired($active, $now),
    'An active session inside both limits should remain valid.'
);

$idleExpired = $active;
$idleExpired['last_activity'] = $now - SENTRYIQ_IDLE_TIMEOUT - 1;
sessionExpiryCheck(
    sentryiq_authenticated_session_expired($idleExpired, $now),
    'Idle sessions must expire after the configured inactivity window.'
);

$absoluteExpired = $active;
$absoluteExpired['authenticated_at'] = $now - SENTRYIQ_ABSOLUTE_SESSION_TIMEOUT - 1;
$absoluteExpired['last_activity'] = $now - 1;
sessionExpiryCheck(
    sentryiq_authenticated_session_expired($absoluteExpired, $now),
    'Active sessions must expire at the absolute lifetime even with recent activity.'
);

$missingStart = $active;
unset($missingStart['authenticated_at']);
sessionExpiryCheck(
    sentryiq_authenticated_session_expired($missingStart, $now),
    'Authenticated sessions without a start timestamp must fail closed.'
);

$futureStart = $active;
$futureStart['authenticated_at'] = $now + 6;
sessionExpiryCheck(
    sentryiq_authenticated_session_expired($futureStart, $now),
    'Authenticated sessions with a future start timestamp must fail closed.'
);

echo "Authenticated session expiry tests passed.\\n";
