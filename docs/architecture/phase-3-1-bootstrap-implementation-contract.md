# Phase 3.1 — Trusted first-run bootstrap implementation contract

**Status:** Implementation contract; owner-approved baseline dated 2026-11-25.  
**Application:** `https://sentryiq.bichet.co.za`  
**Master authority:** Owner's native phone companion.  
**Production status:** No production keys, trust roots, or pins are created by this work.

## 1. Purpose and authority

This contract translates the Phase 2.3 trust-root lifecycle and Phase 2.8 master-phone gate into a first-run state machine. It establishes which public keys and policies the owner's phone trusts. It does not enrol additional devices, approve a release, initialise user-data roots, or provision HelioHost.

The phone is authoritative. The application host may relay public metadata but is never a bootstrap authority. The HelioHost verifier cannot make its own key trusted. Release-authorisation, verifier-report, master-device, Sigstore/TUF, and recovery keys remain separate roles.

## 2. Approved cryptographic profile

- Master signing: P-256, ES256, hardware-backed and non-exportable where the platform supports it.
- Master key agreement: a separate P-256 key; never reuse the signing key.
- iOS master adapter: Apple Secure Enclave P-256 signing and key-agreement operations, with Keychain-protected trust state.
- Android master adapter: Android Keystore P-256 keys, preferring StrongBox-backed storage; accept TEE-backed keys only when hardware security level and device attestation meet the qualified policy. Record StrongBox versus TEE assurance explicitly.
- Android devices without an acceptable hardware-backed key implementation are not eligible for master authority; they may participate only in a separately approved lower-assurance device tier.
- Release authorisation: separate owner-controlled custody boundary; never use the master key.
- HelioHost reports: separate verifier-only key, generated only after Phase 4 host qualification and explicit provisioning approval.
- Sigstore/TUF: maintained upstream bootstrap and root-rotation process.
- Recovery: DRS and MRAK remain distinct.
- Browser-managed additional-device keys are lower assurance and cannot administer trust roots.

Every public key is bound to an immutable `kid`, role, algorithm, purpose, and protocol version. Key material and `kid` values are never reused across roles.

## 3. Bootstrap inputs and provenance

The ceremony accepts:
1. A release-authorisation public root and fingerprint from its separately controlled custody process.
2. A HelioHost verifier public key and fingerprint only after Phase 4 establishes host isolation and key custody.
3. Sigstore/TUF bootstrap metadata validated under the maintained upstream TUF procedure.
4. A locally generated master keyset from the native platform adapter (Secure Enclave on iOS; Android Keystore with StrongBox preferred and qualified TEE fallback on Android).
5. An owner-controlled out-of-band fingerprint record for independently comparing each SentryIQ root.

The application origin, app-host API, database, QR code displayed only by the application origin, and unsigned verifier response are untrusted transport. A received value is not a trust anchor until independently authenticated and explicitly accepted on the phone.

The verifier root may remain **pending** until HelioHost qualification. Do not generate or temporarily trust a verifier key to make bootstrap appear complete.

## 4. Canonical trust bundle

Use strict JSON with duplicate-member rejection and a maintained RFC 8785 JCS implementation. Required fields:

| Field | Requirement |
|---|---|
| `type` | Exact value `SENTRYIQ-TRUST-BUNDLE` |
| `schema_version` | Supported integer; no coercion |
| `policy_version` | Monotonic policy identifier |
| `sequence` | Canonical unsigned decimal string; persisted high-water mark |
| `previous_digest` | SHA-256 of prior bundle; null only for owner-supervised bootstrap |
| `issued_at`, `expires_at` | Bounded UTC validity |
| `owner_id` | Exact account binding |
| `master_keyset` | Distinct signing/key-agreement public keys, key IDs, suites, roles, fingerprints |
| `release_authorisation` | Role-bound public keys and allowed purpose |
| `verifier` | Role-bound public keys, policy version, qualification state |
| `sigstore_tuf` | Upstream trust metadata version/digest references |
| `revocations` | Sorted unique revoked key IDs, effective time, reason |
| `signatures` | Detached signatures over exact canonical payload, signer role and key ID |

Reject duplicate member names/IDs, malformed keys, unknown algorithms or critical fields, unsupported schema/policy, non-canonical encodings, role/purpose mismatch, invalid timestamps, and type coercion.

The bundle contains public keys and policy metadata only. It must never contain private keys, DRS/MRAK, content roots, DEKs, session secrets, or user content.

### 4.1 Executable validator profile

The first platform-independent validator implementation uses the following concrete encoding profile; native adapters must consume the same fixtures and semantics:

- Trust bundle schema version is integer `1`; the top-level member set is exact and unknown members are rejected.
- Public P-256 keys are carried as PEM SubjectPublicKeyInfo values. The master keyset includes an explicit `hardware_assurance` value (`secure-enclave`, `android-strongbox`, or `android-tee-qualified`). Master signing and key-agreement keys, release-authorisation keys, and verifier-report keys must have unique key IDs and distinct public-key material. Software-only keys are never eligible for master authority.
- Master signing and release/verifier signatures use ES256. Detached signatures use the 64-byte JOSE `r || s` representation encoded as unpadded base64url, with canonical low-S ECDSA values to prevent signature malleability. Native signers must normalize S before emitting a signature.
- Key arrays, revocation entries, and detached signatures are sorted by key ID and contain no duplicates. A detached signature covers the RFC 8785 canonical JSON representation of the complete bundle with only the `signatures` member omitted. The chain digest is SHA-256 over the canonical JSON representation of the complete bundle, including signatures.
- The validator receives independently pinned signer keys, the expected owner ID, the previously committed digest, and the locally persisted sequence high-water mark as separate inputs. It never derives trust anchors from candidate bundle contents.
- The initial PHP implementation enforces a 256 KiB input ceiling, a 30-day maximum bundle validity window, and a five-minute future-issued-time allowance. These are conservative protocol limits to retain in cross-platform fixtures and review during independent security assessment.
- A verifier marked `pending` must have an empty key list. A `qualified` verifier must have at least one role-bound report key; production acceptance remains gated on Phase 4 and owner approval.

The PHP implementation is a protocol validator, not the native trust-state persistence or owner ceremony. Its accepted schema and adversarial fixtures are the cross-platform compatibility reference, subject to independent security review.

## 5. First-run state machine

The native companion persists one of these states:

- `UNINITIALISED`: no trusted master identity or trust bundle.
- `MASTER_CREATED_PENDING_ROOTS`: local master keyset exists; independent SentryIQ roots not yet accepted.
- `ROOTS_PENDING_VERIFIER`: release root and upstream TUF bootstrap accepted; verifier root legitimately pending Phase 4.
- `TRUSTED`: required trust roots and policy accepted and committed.
- `RECOVERY_REQUIRED`: trust state corrupt, rolled back, mismatched, or unauthenticated.
- `SUSPENDED`: required root revoked/expired or policy demands revalidation.

Transitions:

1. `UNINITIALISED -> MASTER_CREATED_PENDING_ROOTS`: only after the owner explicitly starts first-run master setup, generate separate hardware-backed P-256 signing and key-agreement keys through the platform adapter; display role-specific public fingerprints and record the hardware security level. On iOS use Secure Enclave; on Android prefer StrongBox, otherwise require a qualified TEE-backed key. Existing-key loading is a separate operation; a missing keyset after restore, migration, or secure-storage invalidation must enter recovery and must never trigger automatic master-key regeneration.
2. `MASTER_CREATED_PENDING_ROOTS -> ROOTS_PENDING_VERIFIER`: owner independently compares and accepts the release-authorisation fingerprint with fresh local user verification; validate TUF bootstrap; atomically commit initial trust state.
3. `ROOTS_PENDING_VERIFIER -> TRUSTED`: only after Phase 4 qualification, owner compares and accepts the verifier fingerprint and proof-of-possession through an independently authenticated channel.
4. Signature failure, owner/account mismatch, rollback, storage-integrity failure, ambiguous fingerprint, or interrupted commit fails closed and never advances trust.
5. Pending-verifier state denies operations that require independent verifier evidence.

No remote endpoint can directly set the phone to `TRUSTED`.

## 6. Owner confirmation surface

For each root, show role, key ID, algorithm, full fingerprint, source/provenance, exact permitted and forbidden purposes, and expiry/activation policy. The owner confirms each root independently with fresh local user verification. A generic “Trust SentryIQ” action is prohibited; server labels cannot replace role and fingerprint display.

## 7. Persistence and anti-rollback

The native companion stores the trust bundle, canonical digest, sequence high-water mark, accepted key IDs, revocations, TUF root versions, and bootstrap receipt in protected platform storage.

- Validate fully, write a new version, verify the write, then advance the active pointer/high-water mark.
- Never destroy the last valid state before the new state is durably committed.
- Reject lower sequences and same-sequence/different-digest objects.
- Require previous-digest continuity after initial bootstrap.
- Do not claim hardware monotonic-counter protection unless the target platform provides it.
- Backup restore, reinstall, migration, secure-storage invalidation, or suspected rollback enters `RECOVERY_REQUIRED` pending independent revalidation.
- The application host cannot reset a phone-held high-water mark.

The native storage implementations must be reviewed on both iOS and Android. The iPhone is the initial master platform; Android support is a first-class target using a separate platform adapter. Cross-platform protocol and trust-state formats remain identical, while hardware assurance is recorded per device.

## 8. Signed transition and proof-of-possession

A transition is accepted only when the current trusted signer is authorised for that exact purpose; canonical payload and detached signature validate; sequence increases; previous digest matches; no key is reactivated or reused; new role/suite/purpose match policy; proof-of-possession validates; owner explicitly approves with fresh verification; and the new state is atomically persisted.

A verifier key cannot sign its own introduction. A release key cannot replace the master. A master key cannot sign verifier reports or release authorisations.

## 9. Required negative tests

The protocol layer must test and reject:
- App-host-only roots, unsigned QR/API responses, unknown key IDs, wrong roles/purposes/algorithms.
- Duplicate JSON members/IDs, malformed public keys, non-canonical JCS/base64url, unknown critical fields.
- Lower sequence, same sequence with changed digest, wrong previous digest, expired/future-dated bundle.
- Revoked-key reactivation, key-ID reuse, retired-key use, invalid overlap.
- Invalid/replayed proof-of-possession challenge or wrong transcript.
- Owner/account mismatch, missing fresh user verification, interrupted persistence.
- Restored old backup, missing high-water mark, secure-storage invalidation.
- Verifier key presented before host qualification.
- Cross-role use of master, release, and verifier keys.

All ambiguous cases fail closed. Fixtures contain no production keys or private material.

## 10. Implementation sequence and gates

1. Implement platform-independent bundle parsing/validation and deterministic negative fixtures using maintained JCS/JOSE libraries; do not hand-roll cryptography.
2. Implement separate native adapters: iOS Secure Enclave/Keychain and Android Keystore (StrongBox preferred, qualified TEE fallback). Keep identical protocol semantics and role separation; expose the hardware security level to policy.
3. Implement protected trust-state persistence and rollback detection; document platform guarantees and limitations.
4. Implement owner confirmation UI and out-of-band fingerprint comparison.
5. Integrate maintained TUF bootstrap.
6. Keep verifier pinning pending until Phase 4 qualification and separate provisioning approval.
7. Add cross-language fixtures for native companion and PHP relay; PHP only stores/relays public signed objects.
8. Complete independent security review before production trust-root initialisation.

## 11. Explicit non-goals

No production or development private root keys are committed. No production trust state is initialised. No HelioHost service is provisioned. No user data, content roots, DRS, or MRAK are generated or migrated. No release or production deployment occurs. No PHP endpoint may declare trust based only on a server-side flag.

**Completion evidence:** The protocol validator, iOS and Android native adapters, protected persistence, owner ceremony, cross-platform fixtures, hardware-assurance tests, and negative tests must all be implemented and reviewed. This contract alone does not mark Phase 3.1 complete.
