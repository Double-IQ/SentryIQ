<?php

declare(strict_types=1);

namespace SentryIQ\Auth;

use RuntimeException;

final class WebAuthnChallenge
{
    public const TTL_SECONDS = 120;
    private const MAX_FUTURE_SKEW_SECONDS = 5;

    public static function issue(array &$session, string $purpose, string $challenge, int $now): string
    {
        self::assertPurpose($purpose);
        if (strlen($challenge) !== 32) {
            throw new RuntimeException('WebAuthn challenge must contain 32 random bytes.');
        }
        $encoded = rtrim(strtr(base64_encode($challenge), '+/', '-_'), '=');
        $session['pk_' . $purpose . '_challenge'] = $encoded;
        $session['pk_' . $purpose . '_challenge_issued_at'] = $now;
        return $encoded;
    }

    public static function consume(array &$session, string $purpose, int $now): string
    {
        self::assertPurpose($purpose);
        $challengeKey = 'pk_' . $purpose . '_challenge';
        $issuedKey = 'pk_' . $purpose . '_challenge_issued_at';
        $encoded = $session[$challengeKey] ?? null;
        $issuedAt = $session[$issuedKey] ?? null;

        // Consume before validation so even failed submissions cannot replay
        // the same challenge. The browser can request a fresh challenge.
        unset($session[$challengeKey], $session[$issuedKey]);

        if (!is_string($encoded)
            || !is_int($issuedAt)
            || $issuedAt > $now + self::MAX_FUTURE_SKEW_SECONDS
            || $now - $issuedAt > self::TTL_SECONDS) {
            throw new RuntimeException('WebAuthn challenge expired or missing.');
        }

        if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $encoded)) {
            throw new RuntimeException('WebAuthn challenge is malformed.');
        }
        $padded = $encoded . '=';
        $raw = base64_decode(strtr($padded, '-_', '+/'), true);
        if (!is_string($raw) || strlen($raw) !== 32) {
            throw new RuntimeException('WebAuthn challenge is malformed.');
        }
        return $encoded;
    }

    private static function assertPurpose(string $purpose): void
    {
        if (!in_array($purpose, ['register', 'login'], true)) {
            throw new RuntimeException('Invalid WebAuthn challenge purpose.');
        }
    }
}
