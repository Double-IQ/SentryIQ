# Phase 3.2 — Master-device identity creation and protected key storage

**Status:** Implementation contract; native key-generation and protected-storage primitives exist, end-to-end identity lifecycle integration is in progress.  
**Authority:** The owner's first-run native companion only.  
**Protocol:** P-256 signing (ES256) and separate P-256 key agreement (ECDH-ES).

## 1. Security invariants

1. Master identity creation is an explicit owner-started operation. No login, restore, app launch, failed key lookup, or bootstrap retry may create or replace a master identity.
2. Signing and key-agreement keys are separate, non-exportable hardware-backed keys. Private key bytes never leave Secure Enclave / Android Keystore.
3. The identity is bound to an immutable pair of role-specific key IDs, public SPKI keys, hardware-assurance tier, protocol version, and a domain-separated keyset digest.
4. A partial keyset is an unrecoverable setup interruption, not permission to generate replacements. It enters recovery-required handling.
5. A previously created keyset is loaded and verified; it is never silently overwritten. Explicit reset/replacement belongs to the Phase 3.7 recovery ceremony.
6. Public descriptors may be exported for trust-bundle construction. Private keys, authentication secrets, and attestation challenge material must never be logged or persisted outside the platform keystore.
7. The UI must display the signing and agreement fingerprints separately and identify the actual hardware assurance. It must not label a TEE key as StrongBox or a software key as hardware-backed.

## 2. Existing platform primitives

- iOS: `SecureEnclaveMasterKeyStore.createInitialMasterKeyset(context:)` creates separate Secure Enclave P-256 signing and key-agreement keys, stores device-bound references in Keychain, and exposes public SPKI descriptors. `loadExisting()` fails on a missing/incomplete archive. Passcode-bound user-presence access control is required.
- Android: `AndroidKeystoreMasterKeyStore.createInitialMasterKeyset()` creates separate P-256 signing and agreement aliases, prefers StrongBox, accepts TEE only after the injected attestation policy validates both certificate chains and the fresh challenge, and returns the assurance tier and keyset digest. `loadExisting()` never creates keys and rejects a partial alias pair.
- Both platforms implement the same `SENTRYIQ-MASTER-KEYSET-V1\n` length-prefixed SHA-256 transcript and role-specific key IDs.

These primitives are not, by themselves, a complete owner-facing identity lifecycle. The consuming app must supply the explicit owner-start confirmation, per-use local authentication, identity state presentation, and recovery-required route.

## 3. Required lifecycle coordinator

The platform integration must expose only these operations:

- `inspectIdentity()`: return absent, complete, or incomplete; never mutate storage.
- `createIdentityAfterOwnerConfirmation()`: require a one-shot confirmation token produced by the native owner-confirmation UI; create only when both key slots are absent; return the public descriptor and digest.
- `loadIdentity()`: load both existing keys and recompute/validate descriptor consistency; never create.
- `signMasterOperation(...)`: require fresh platform user verification for every authority-bearing operation.
- `deriveDeviceEnvelopeKey(...)`: use the distinct agreement key and approved HKDF context; never expose the raw ECDH secret.
- `handleIncompleteIdentity()`: enter recovery-required state; never delete one key and regenerate it automatically.

The confirmation token must be process-local, short-lived, single-use, and bound to the exact setup intent. It is not a replacement for Secure Enclave / Keystore user authentication.

## 4. Persistence and recovery

The private keys remain in their platform hardware stores. The public identity descriptor and its digest may be persisted in protected local application state, but must be re-derived from the hardware keys on every load and compared byte-for-byte. A missing descriptor can be reconstructed from an intact key pair; a missing private key cannot.

Do not persist a "master created" flag before both keys have been created and independently reloaded. If creation is interrupted after only one platform key is created, fail closed and require the explicit recovery/replacement process; do not silently delete or overwrite the surviving key.

## 5. Acceptance tests

- Fresh setup creates two distinct keys with the correct roles, algorithms, SPKI encoding, immutable IDs, and matching cross-platform digest.
- Repeated setup does not replace either key and returns the same public identity.
- Loading an absent identity never creates keys.
- A one-key/partial identity is rejected and never auto-repaired.
- Creation cannot run without a valid one-shot owner confirmation.
- Confirmation expires and cannot be replayed or used for a different setup intent.
- Signing and agreement operations require fresh local authentication and use only their respective key.
- Android StrongBox and qualified TEE assurance are reported accurately; invalid/missing TEE attestation fails closed.
- Restore/reinstall with missing hardware keys enters recovery; it never generates a replacement identity.
- No private key bytes or authentication material appear in logs, files, IPC, or exported descriptors.

## 6. Explicit exclusions

This phase does not enrol additional devices, issue device certificates, approve permissions, rotate the master, initialise recovery material, or provision production trust roots. Those are later Phase 3 steps and require their own owner-authorised ceremonies.
