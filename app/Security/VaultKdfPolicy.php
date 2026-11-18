<?php

declare(strict_types=1);

namespace SentryIQ\Security;

use RuntimeException;

final class VaultKdfPolicy
{
    public const MAX_OPSLIMIT = 10;
    public const MAX_MEMLIMIT_BYTES = 64 * 1024 * 1024;

    public static function assertValid(int $opslimit, int $memlimit): void
    {
        if (!function_exists('sodium_crypto_pwhash')) {
            throw new RuntimeException('Sodium is required for SentryIQ vault key derivation.');
        }
        if ($opslimit < SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
            || $opslimit > self::MAX_OPSLIMIT
            || $memlimit < 19 * 1024 * 1024
            || $memlimit > self::MAX_MEMLIMIT_BYTES) {
            throw new RuntimeException('Vault KDF parameters are outside the approved resource limits.');
        }
    }
}
