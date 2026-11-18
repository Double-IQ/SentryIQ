# ADR: Safe, resumable Secure Gallery key rotation

- **Status:** Implemented in the feature branch; awaiting real-device and live Backblaze validation
- **Date:** 2026-11-18
- **Branch:** `feature/gallery-zero-knowledge-e2e`

## Context

Gallery currently has one RSA-OAEP-256 identity key pair. The RSA private key is encrypted by the Gallery root key; passkey PRF envelopes and the recovery envelope independently wrap that same root key. Each stored object has a random AES-256-GCM DEK, and that DEK is wrapped by the single Gallery RSA public key.

A naïve rotation that rewrites every object's wrapped DEK in one operation is unsafe. A browser crash, network interruption, object deletion, or concurrent upload midway through the rewrite could leave some photos dependent on the old private key while the server has already replaced it.

## Decision

Separate **RSA wrapping-key rotation** from **Gallery root-key rotation**. The first is the routine operation for retiring an RSA key pair. The second is a separate, higher-impact operation that changes the root key and therefore every passkey and recovery envelope.

### RSA wrapping-key rotation

1. Give every RSA public/private key pair an immutable random `keyId`. Every object envelope records the `keyId` that can unwrap its DEK.
2. Store a keyring, not a single mutable key: each entry contains `keyId`, public JWK and a private-key envelope encrypted under the unchanged Gallery root key. Keep one explicit `activeKeyId`.
3. Adding a wrapping key creates a new RSA key pair in the unlocked browser. The browser encrypts its private JWK under the existing root key and submits the new public JWK and private-key envelope. The server validates and stores the new entry as inactive. Starting a rotation explicitly switches the active upload key while retaining the old key.
4. The browser migrates each active object independently: read its current encrypted envelope and revision hash, unwrap the DEK locally with the old private key, wrap the same DEK with the new public key, then submit only the replacement envelope. The photo ciphertext is not downloaded or re-encrypted for this operation; no plaintext image or DEK reaches PHP.
5. Every replacement is conditional on the object's current envelope version/hash still matching the version the browser read. A conflict means the object changed or was already migrated; refetch and retry rather than overwriting newer state.
6. Persist a server-side migration journal with migration ID, source key ID, target key ID, start time, and state. Progress is derived from the active object index, not trusted from a browser-supplied completed counter. The client resumes by scanning and skipping envelopes already using the target key.
7. Uploads created after the active-key switch use the new key. Deletes may remove an object while migration is running; missing objects are treated as complete. A failed object remains readable through the old key and is retried.
8. Retire the old key only after the server verifies that no active object envelope or pending/cancelling upload references it, all migration writes are committed, and a final inventory pass confirms the invariant under the shared Gallery rotation lock. The implementation retains the old key for a 24-hour rollback window before irreversible retirement. Never delete the old private-key envelope merely because a client reports 100%.
9. If the migration is abandoned, both keys remain in the keyring and every object remains readable. A later session can resume or explicitly abort the migration; aborting reactivates the prior key and retains the target key, so objects already migrated to the target remain readable.

### Gallery root-key rotation

Root-key rotation is not the same operation. It requires an unlocked browser to generate a new random root key, re-encrypt every retained RSA private-key JWK under it, and create new envelopes for **every remaining enrolled passkey** and the recovery secret. The server must stage all new envelopes and activate them atomically only after the browser proves it can reopen the new root key from both a passkey and the new recovery envelope. If an enrolled device is unavailable, its old envelope cannot unlock the new root key; that device must be re-enrolled after rotation. Root-key rotation must not be silently bundled into ordinary RSA rotation.

### Data model and API requirements

- Gallery identity schema must be versioned before rotation ships. Existing v1 single-key records need a read-only compatibility path and a deliberate v2 upgrade.
- New object envelopes include `keyId`; the existing v1 envelope shape remains readable for legacy objects without IDs. Server-side object records carry envelope revision hashes for compare-and-swap. Unknown key IDs, malformed envelopes, and unsupported versions fail closed.
- Add server operations to begin/resume/status/abort/finalize a rotation, plus conditional per-object envelope replacement.
- Server-side code validates key IDs, envelope shape, migration state, object ownership and revision transitions. Public RSA JWK validation explicitly rejects private components (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`) on initialization, key enrollment, legacy migration and key-store reads. It never receives a DEK, RSA private key, root key, PRF output or plaintext image.
- The server must not trust client-reported counts, object lists or completion state. It computes remaining references from its authoritative object index.
- Rotation APIs require authenticated account access, CSRF protection and a recent verified Gallery passkey. Finalization requires a fresh server-side inventory check under the same storage lock used for object-envelope writes.
- Keep object ciphertext bytes, opaque B2 object keys and AES-GCM nonces unchanged during RSA wrapping-key rotation.

## Required tests before implementation is considered complete

- New uploads use the active key ID after the activation commit.
- Old and new key IDs both decrypt objects during an in-progress rotation.
- A simulated interruption after any migrated object leaves all objects readable and rotation resumable.
- Concurrent upload, delete, and envelope replacement cannot lose an object or overwrite a newer envelope.
- Conditional updates reject stale envelope revisions.
- Finalization is rejected while even one active object references the old key.
- Unknown key IDs and malformed v2 envelopes fail closed.
- Aborting a partially completed rotation retains both keys and all data remains readable.
- A root-key rotation cannot activate unless every retained passkey envelope and the recovery envelope have been staged and independently verified.
- No rotation request sends plaintext image data, a DEK, private-key JWK, root key, recovery secret or PRF output to PHP.

## Consequences

RSA rotation can be long-running and resumable, but it does not require re-uploading or re-encrypting photo ciphertext. The old private key must remain available until the server's authoritative inventory proves it is no longer referenced. Root-key rotation is a separate coordinated recovery event and may require unavailable devices to be re-enrolled.

## Implementation status

The development branch now contains the complete RSA wrapping-key rotation workflow: backward-compatible v2 keyring persistence, inactive-key enrollment, multi-key passkey/recovery unlock, key-aware object envelopes, browser-side DEK rewrapping, conditional envelope replacement, a durable rotation journal, explicit active-key switching, resume/abort controls, and inventory-gated retirement after a 24-hour rollback window. A shared Gallery rotation lock serializes reservations, commits, cancellations, envelope replacements, inventory and final retirement. Pending uploads are bound to their allocated key; cancellation closes a reservation before B2 cleanup and interrupted cleanup remains retryable. Existing v1 objects remain readable and are attributed to the original key during inventory.

Automated regression coverage includes keyring migration, multi-key passkey/recovery unlock, legacy-object decryption, DEK rewrapping without changing ciphertext, object reference inventory, stale-revision rejection, cancellation races, journal transitions, rollback-window behavior, and browser migration flow. These tests use mocked browser/storage boundaries; real iOS Safari/WebAuthn PRF and live Backblaze transfers have not yet been validated. The feature remains on the draft PR and has not been merged or deployed. Root-key rotation remains separate.

The current v1 object envelope remains readable; `keyId` is an additive field in the existing envelope version. A future schema version may formalize this further, but must preserve this compatibility path.
