<?php

declare(strict_types=1);

require_once __DIR__ . '/../private_data/VaultKdfPolicy.php';

use SentryIQ\Security\VaultKdfPolicy;

function kdfCheck(bool $condition, string $message): void
{
    if (!$condition) throw new RuntimeException($message);
}

function kdfReject(callable $operation, string $message): void
{
    try {
        $operation();
    } catch (Throwable) {
        return;
    }
    throw new RuntimeException($message);
}

VaultKdfPolicy::assertValid(3, 32 * 1024 * 1024);
VaultKdfPolicy::assertValid(
    VaultKdfPolicy::MAX_OPSLIMIT,
    VaultKdfPolicy::MAX_MEMLIMIT_BYTES
);

kdfReject(
    fn() => VaultKdfPolicy::assertValid(SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE - 1, 32 * 1024 * 1024),
    'KDF opslimit below the approved minimum must be rejected.'
);
kdfReject(
    fn() => VaultKdfPolicy::assertValid(VaultKdfPolicy::MAX_OPSLIMIT + 1, 32 * 1024 * 1024),
    'KDF opslimit above the resource ceiling must be rejected.'
);
kdfReject(
    fn() => VaultKdfPolicy::assertValid(3, 19 * 1024 * 1024 - 1),
    'KDF memory below the approved minimum must be rejected.'
);
kdfReject(
    fn() => VaultKdfPolicy::assertValid(3, VaultKdfPolicy::MAX_MEMLIMIT_BYTES + 1),
    'KDF memory above the resource ceiling must be rejected.'
);

echo "Vault Argon2id KDF resource policy tests passed.\\n";
