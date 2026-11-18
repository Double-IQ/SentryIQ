<?php

declare(strict_types=1);

require_once __DIR__ . '/../app/Auth/WebAuthnChallenge.php';

use SentryIQ\Auth\WebAuthnChallenge;

function challengeCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function challengeReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

$session = [];
$raw = random_bytes(32);
$encoded = WebAuthnChallenge::issue($session, 'login', $raw, 1000);
challengeCheck(strlen($encoded) === 43, 'Issued WebAuthn challenge must be 32-byte base64url.');
challengeCheck(
    WebAuthnChallenge::consume($session, 'login', 1120) === $encoded,
    'A challenge within the 120-second lifetime should be accepted.'
);
challengeCheck(
    !isset($session['pk_login_challenge'], $session['pk_login_challenge_issued_at']),
    'A consumed challenge and timestamp must be removed from the session.'
);
challengeReject(
    fn() => WebAuthnChallenge::consume($session, 'login', 1120),
    'A consumed challenge must not be replayable.'
);

$expired = [];
WebAuthnChallenge::issue($expired, 'register', random_bytes(32), 1000);
challengeReject(
    fn() => WebAuthnChallenge::consume($expired, 'register', 1121),
    'An expired registration challenge must be rejected.'
);
challengeCheck(
    !isset($expired['pk_register_challenge'], $expired['pk_register_challenge_issued_at']),
    'An expired challenge must be consumed/cleared.'
);

$future = [];
WebAuthnChallenge::issue($future, 'login', random_bytes(32), 2000);
challengeReject(
    fn() => WebAuthnChallenge::consume($future, 'login', 1994),
    'A challenge timestamp too far in the future must be rejected.'
);

$malformed = ['pk_login_challenge' => 'not-base64url', 'pk_login_challenge_issued_at' => 1000];
challengeReject(
    fn() => WebAuthnChallenge::consume($malformed, 'login', 1001),
    'Malformed challenge material must be rejected.'
);

challengeReject(
    fn() => WebAuthnChallenge::issue($session, 'other', random_bytes(32), 1000),
    'Unknown challenge purposes must be rejected.'
);
challengeReject(
    fn() => WebAuthnChallenge::issue($session, 'register', random_bytes(31), 1000),
    'Challenges shorter than 32 bytes must be rejected.'
);

$fresh = ['authenticated_at' => 1000];
WebAuthnChallenge::assertFreshAuthentication($fresh, 1300, 300);
challengeReject(
    fn() => WebAuthnChallenge::assertFreshAuthentication($fresh, 1301, 300),
    'Passkey credential changes must reject authentication older than the fresh-auth window.'
);
challengeReject(
    fn() => WebAuthnChallenge::assertFreshAuthentication([], 1000, 300),
    'Passkey credential changes must reject sessions without an authentication timestamp.'
);
challengeReject(
    fn() => WebAuthnChallenge::assertFreshAuthentication(['authenticated_at' => 1006], 1000, 300),
    'Passkey credential changes must reject timestamps too far in the future.'
);

echo "WebAuthn challenge expiry and replay tests passed.\\n";
