<?php

declare(strict_types=1);

/*
 * NON-PRODUCTION TEMPLATE ONLY.
 *
 * Copy to the private SentryIQ data directory as bootstrap-runtime.php and
 * chmod 0600 only after all values and callbacks have been independently
 * provisioned and reviewed. Never put private signing keys in this file.
 */
return [
    // Public ES256 registry-anchor verification pins.
    'registry_signer_keys' => [
        [
            'kid' => 'REPLACE_WITH_REGISTRY_ANCHOR_KEY_ID',
            'role' => 'registry-anchor',
            'alg' => 'ES256',
            'public_key_pem' => 'REPLACE_WITH_PUBLIC_P256_PEM',
        ],
    ],

    // Public release-authorisation keys trusted to sign the candidate bundle.
    'bundle_signer_keys' => [
        [
            'kid' => 'REPLACE_WITH_RELEASE_SIGNER_KEY_ID',
            'role' => 'release-authorisation',
            'alg' => 'ES256',
            'public_key_pem' => 'REPLACE_WITH_PUBLIC_P256_PEM',
        ],
    ],

    // Exact candidate bundle bytes and independently signed registry anchor.
    'bundle_json' => 'REPLACE_WITH_CANONICAL_TRUST_BUNDLE_JSON',
    'registry_anchor_payload' => 'REPLACE_WITH_CANONICAL_SIGNED_ANCHOR_PAYLOAD',
    'registry_anchor_signature_base64url' => 'REPLACE_WITH_64_BYTE_JOSE_SIGNATURE_BASE64URL',

    // Previous accepted registry state; both null only for sequence-one bootstrap.
    'current_sequence' => null,
    'current_bundle_digest' => null,

    // Raw signed TUF metadata bytes. Root rotations use root/<version>.json.
    'tuf_metadata' => [
        'root.json' => 'REPLACE_WITH_INITIAL_PINNED_ROOT_METADATA',
        'timestamp.json' => 'REPLACE_WITH_SIGNED_TIMESTAMP_METADATA',
        'snapshot.json' => 'REPLACE_WITH_SIGNED_SNAPSHOT_METADATA',
        'targets.json' => 'REPLACE_WITH_SIGNED_TARGETS_METADATA',
        // 'root/2.json' => 'REPLACE_WITH_SIGNED_ROOT_ROTATION',
        // 'delegated-order.json' => '["release","application"]',
        // 'delegated/release.json' => 'REPLACE_WITH_SIGNED_DELEGATED_METADATA',
    ],

    // Map the already authenticated web session user to the immutable owner ID.
    'resolve_owner_id' => static function (string $sessionUsername): string {
        throw new RuntimeException('Provision an authenticated account-to-owner mapping.');
    },

    // Must independently verify root/timestamp/snapshot/targets and any delegated metadata.
    'verify_tuf' => static function (array $validatedBundle, array $tufMetadata): bool {
        throw new RuntimeException('Provision the independent TUF metadata verifier.');
    },

    // Return target bytes only for a safe relative path from the approved target store.
    'resolve_target' => static function (string $relativeTargetPath): ?string {
        throw new RuntimeException('Provision a path-confined TUF target resolver.');
    },
];
