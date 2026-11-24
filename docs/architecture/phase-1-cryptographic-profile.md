# Phase 1.3 — Cryptographic algorithm, key-size, identifier, rotation, and compromise profile

**Status:** Proposed cryptographic profile; owner/security review required before implementation.  
**Baseline:** `main` after Phase 1.2 merge.  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Scope:** Define the recommended cryptographic building blocks and parameter sizes for the phone-rooted, ciphertext-only target architecture. Distinguish existing repository formats from target formats and specify versioning, key identifiers, rotation, and compromise response. This document does not generate keys, change cryptographic code, or authorise production initialisation.

## 1. Decisions at a glance

| Purpose | Recommended target primitive | Key / output size | Status and constraints |
|---|---|---:|---|
| Password-based key derivation | Argon2id v1.3 via maintained libsodium implementation | 32-byte output; 16-byte random salt | Preserve existing Vault format for reads. Proposed new profile: opslimit 3, memlimit 64 MiB, subject to supported-phone performance and memory tests; never silently lower cost |
| Content encryption | AES-256-GCM | 32-byte key; 12-byte nonce; 16-byte tag | Use WebCrypto on supported clients. Fresh unique nonce for every encryption under a key; bind canonical context as AAD |
| Per-object data key | CSPRNG-generated independent DEK | 32 bytes | One DEK per independently encrypted object; do not reuse between objects or purposes |
| Key derivation / domain separation | HKDF-SHA-256 | 32-byte output; 32-byte random salt where a salt is required | Unique, versioned `info` label per purpose, protocol, owner, object, and key role |
| Device/master signatures | Ed25519 | 32-byte public key; 32-byte private seed; 64-byte signature | Separate key pair per authority/device. Use a maintained implementation; never reuse verifier or release-signing keys |
| Device-to-device key encapsulation | HPKE RFC 9180: DHKEM(X25519, HKDF-SHA-256) + HKDF-SHA-256 + AES-256-GCM | X25519 public/private keys: 32 bytes | Use a maintained, audited HPKE library. Do not hand-roll a hybrid encryption protocol. Browser/platform compatibility is a release gate |
| Existing Gallery DEK wrapping | RSA-OAEP-3072 with SHA-256 | RSA modulus 3072 bits; wrapped 32-byte DEK is 384 bytes | Retain for existing Gallery v1/v2 compatibility and current tested rotation design. Any future replacement requires explicit migration |
| Digests / identifiers of bytes | SHA-256 | 32-byte digest | Use for release, artifact, envelope revision and ciphertext integrity identifiers; a digest is not an authentication signature |
| Keyed token digests | HMAC-SHA-256 | 32-byte output | Use only with an independent secret key and a versioned purpose label |
| Random challenges / recovery secrets | Cryptographically secure random generator | 32 bytes (256 bits) | Single-use challenges; recovery secret displayed once and held offline |
| Release provenance | Existing Sigstore/GitHub attestation and TUF trust model | Determined by verified upstream metadata | Preserve independent trust roots and workflow identity checks; not a substitute for device/verifier signatures |
| Verifier reports | Ed25519 detached signature | 32-byte public key; 64-byte signature | Dedicated HelioHost key, independent from device, release, and application keys |

**Profile rule:** use established, maintained cryptographic libraries and standard protocols. Do not implement primitives, encodings, padding, key exchange, signatures, or authenticated-encryption composition manually. Unknown algorithm identifiers, malformed lengths, unsupported versions, missing bindings, and policy downgrade attempts fail closed.

## 2. Existing repository cryptography — observed baseline

### 2.1 Vault

- Vault envelope version is currently **3**; password key-wrap version is **1**.
- Password/recovery key derivation uses libsodium `sodium_crypto_pwhash` with Argon2id13, 32-byte derived key, 16-byte libsodium salt, default opslimit 3, and default memory limit 32 MiB.
- `VaultKdfPolicy` accepts at least libsodium's interactive opslimit, at most opslimit 10, and memory from 19 MiB through 64 MiB.
- VMK wrapping and Vault-record encryption use AES-256-GCM with 32-byte key, 12-byte nonce, and 16-byte tag.
- Vault and recovery wrappers have version fields and purpose-specific AAD strings. The Vault AAD includes Vault format, KDF metadata, and cipher/nonce/tag parameters.
- The recovery secret is generated from 32 random bytes and represented as 64 hexadecimal characters. The recovery wrapper has its own salt/KDF metadata and AES-GCM envelope.
- The current implementation derives and uses the VMK in PHP and stores it in the PHP session. These algorithms are useful building blocks, but the current server-side key boundary does not meet the Phase 1.1/1.2 target.

### 2.2 Vault passkey wrapper

- The Vault passkey path derives a 32-byte wrapping key using HKDF-SHA-256 from a 32-byte WebAuthn PRF output and a 32-byte PRF salt, with the purpose string `SentryIQ passkey vault key`.
- It wraps the 32-byte VMK with AES-256-GCM (12-byte nonce, 16-byte tag), binding the credential ID as AAD.
- The current Vault passkey endpoint receives PRF output in PHP and unwraps the VMK server-side. Preserve the wrapper only as a legacy compatibility format until a client-side replacement and migration exist.

### 2.3 Secure Gallery

- Gallery uses WebCrypto RSA-OAEP with a 3072-bit modulus and SHA-256 for the current wrapping identity.
- A random 32-byte Gallery root key encrypts the private RSA JWK using AES-GCM; Gallery passkey PRF and recovery wrappers use HKDF-SHA-256 and AES-GCM.
- Each object role uses a fresh random 32-byte AES-GCM DEK and 12-byte nonce; a 128-bit GCM tag is included in the ciphertext returned by WebCrypto. The DEK is wrapped with RSA-OAEP-256.
- The object AAD binds the Gallery object version, photo ID, and role. The envelope includes version, algorithm, key-wrap identifier, nonce, wrapped DEK, photo ID, role, and optional key ID.
- Gallery keyring version 2 supports immutable key IDs and multiple wrapping keys. Gallery RSA wrapping-key rotation re-wraps DEKs without changing photo ciphertext. The current Gallery rotation design retains the old key for a 24-hour rollback window and retires it only after a complete authoritative reference inventory.
- This Gallery profile is a current implementation and compatibility constraint, not a reason to reuse its RSA identity for master-device signatures, verifier reports, release signing, or every future key-wrapping role.

### 2.4 Release and integrity evidence

- The repository already uses Ed25519 detached signatures in legacy integrity-report code, with 32-byte public keys and 64-byte signatures. Those classes are tied to legacy node identities and must not be reused unchanged as the new HelioHost report contract.
- Release provenance uses a maintained Sigstore/GitHub attestation verification path and repository/workflow/ref/commit/digest policy checks. TUF root persistence enforces monotonic root versions locally, while the TUF implementation is responsible for signature and threshold verification.
- Release provenance, TUF root metadata, verifier reports, master-device signatures, and per-device signatures are separate trust domains. Do not merge their keys or policy.

## 3. Recommended target algorithm suite

### 3.1 Content encryption and authenticated context

- Use **AES-256-GCM** for Vault records, Documents, Gallery objects, private metadata, and encrypted key envelopes where WebCrypto support is available and validated.
- Keys are exactly 32 random bytes. Nonces are exactly 12 bytes. Authentication tags are exactly 16 bytes. Reject any other length for the selected suite.
- Generate a fresh nonce with the platform CSPRNG for every encryption. Never reuse a nonce with the same key. Prefer one independently generated DEK per object so a key has a very small encryption count.
- The authenticated additional data (AAD) must be a canonical, unambiguous encoding containing at least: protocol/domain label, envelope version, algorithm-suite identifier, owner/account identifier, object identifier, object role/purpose, and relevant key ID or epoch. Do not construct AAD by concatenating ambiguous user-controlled strings.
- Bind ciphertext to its intended object and purpose. Reject cross-object, cross-role, cross-account, wrong-key-ID, wrong-version, and wrong-epoch substitution.
- Never use AES-CBC, ECB, unauthenticated stream encryption, deterministic content encryption, or plaintext hashes as a substitute for AEAD.
- Ciphertext and tag must be verified before plaintext is exposed to application logic. Authentication failure is a hard failure; do not return partial plaintext or attempt a weaker fallback.

### 3.2 Password-derived wrapping

- Retain **Argon2id v1.3** through maintained libsodium for password-derived wrapping. Use a 16-byte cryptographically random salt and a 32-byte output key.
- Proposed new-format baseline: opslimit 3 and memlimit 64 MiB, subject to a measured latency/memory budget on the minimum supported iPhone/Safari and Android/browser devices. The existing 32 MiB format remains readable. A client that cannot meet the selected minimum must report unsupported capability; it must not silently downgrade to a weaker KDF.
- Record the KDF name/version, salt, opslimit, memlimit, output length, and KDF-profile identifier in the authenticated envelope metadata. Validate resource parameters against a strict allowlist before running the KDF to prevent attacker-controlled memory/CPU exhaustion.
- KDF parameters are public metadata, not secrets. Passwords, derived keys, and intermediate key material are secrets and must remain client-side in the target architecture.
- Do not use a fast hash (SHA-256, SHA-512, or plain HMAC) as a password KDF. Do not invent a custom password stretching construction.

### 3.3 HKDF and WebAuthn PRF

- Use **HKDF-SHA-256** only to derive purpose-specific keys from high-entropy input such as a WebAuthn PRF output or random root key. It is not a password KDF.
- Input key material and salt must be validated for exact expected lengths. Derive a 32-byte output for AES-256-GCM or other explicitly defined use.
- Every HKDF `info` value must be a fixed, versioned, domain-separated label, for example `SentryIQ/<protocol>/<version>/<purpose>`, with canonical owner/device/credential binding where needed.
- Never reuse the Vault PRF domain/salt for Gallery or device-authority keys. A credential's PRF output is credential-specific and must not be sent to PHP, the application host, the verifier, or logs.
- If the WebAuthn PRF extension is unavailable or fails, do not silently fall back to a weaker or server-derived key. Require an explicitly designed alternative credential/recovery ceremony.

### 3.4 Device identity, signatures, and key encapsulation

- Use a separate **Ed25519** signing key pair for the master phone and for each additional device. Public key: 32 bytes; private seed: 32 bytes; detached signature: 64 bytes.
- Master signatures authorise device enrolment, scope changes, revocation, and registry transitions. A device signs only its own proof-of-possession and permitted protocol messages. No additional device may sign master-authority operations.
- Use **HPKE (RFC 9180)** with DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256, and AES-256-GCM for new device-to-device or device-to-recipient key encapsulation where a vetted implementation is available. Use distinct X25519 key pairs, 32-byte public/private material, and a protocol-bound HPKE `info` and AAD.
- Do not derive an Ed25519 signing key and X25519 key by ad hoc conversion or reuse one key pair for both functions. Generate independent key pairs for signing and key agreement.
- Do not implement a bespoke X25519/HKDF/AES wrapper if a maintained HPKE implementation is available. The library, version, browser support matrix, test vectors, and update policy must be pinned and reviewed before implementation.
- Browser support is a gate, not an assumption. If Safari or another supported browser cannot safely execute the selected Ed25519/HPKE suite using a maintained library, evaluate a native companion or a standard supported alternative before weakening the security profile.

### 3.5 Hashes, MACs, and random values

- Use SHA-256 for artifact/ciphertext/envelope digests, release manifest entries, and compare-and-swap revision hashes. A digest proves byte equality only when the expected digest is trusted.
- Use HMAC-SHA-256 for keyed token fingerprints or integrity codes that require a shared secret; use a distinct key and domain label. Do not use unkeyed hashes of low-entropy secrets as token protection.
- Use the operating-system/platform cryptographic random generator (PHP `random_bytes`, WebCrypto `crypto.getRandomValues`, or maintained-library CSPRNG) for keys, salts, nonces, IDs, and challenges. Never use timestamps, counters, `Math.random`, or user input as key material.
- Use 32-byte (256-bit) random challenges and recovery secrets. Challenges are short-lived, single-use, bound to the intended origin, protocol, device, and operation, and rejected on replay.

## 4. Key sizes, identifiers, and envelope fields

### 4.1 Key and identifier sizes

| Item | Size / format | Rules |
|---|---|---|
| VMK / Vault data key | 32 random bytes | Distinct from password-derived KEK; client-held in target |
| Per-object DEK | 32 random bytes | Fresh per object; never shared across object roles |
| Gallery root key | 32 random bytes | Gallery-only; not the device master key or Vault key |
| Password KDF salt | 16 random bytes | New salt for each password-derived wrapper |
| WebAuthn PRF output | 32 bytes | Client-only; never sent to PHP |
| HKDF salt | 32 random bytes when a random salt is required | Public; unique to the wrapping context |
| AES-GCM nonce | 12 bytes | Unique for each encryption under a given key |
| AES-GCM tag | 16 bytes | Mandatory; reject truncated tags |
| Ed25519 public/private seed | 32 bytes each | Independent pair per authority/device |
| Ed25519 signature | 64 bytes | Verify exact canonical payload bytes |
| X25519 public/private key | 32 bytes each | Separate pair from signing key |
| RSA Gallery modulus | 3072 bits | Existing Gallery compatibility only; do not reuse identity for signing |
| HPKE encapsulated key | Suite-defined | Validate against the selected RFC 9180 suite and library |
| Recovery secret | 32 random bytes | 256 bits; one-time display; offline custody |
| Key ID / device ID / rotation ID | 16 random bytes encoded as unpadded base64url (22 characters) or a versioned prefixed form | Immutable, opaque, collision-resistant; never derived from username/email |
| Challenge / nonce token | 32 random bytes | Single-use; server stores only a protected digest where persistence is needed |
| SHA-256 digest | 32 bytes / 64 lowercase hex characters | Include algorithm identifier in signed formats |
| Registry epoch | Canonical unsigned decimal string | Monotonic; avoid JavaScript Number precision loss for 64-bit values |

Existing Gallery key IDs currently use a prefixed random identifier and accept 8–64 URL-safe characters. A migration may preserve valid existing IDs; all newly issued IDs should use at least 128 random bits. IDs identify keys but do not authenticate them.

### 4.2 Canonical envelope requirements

Every encrypted object/key wrapper must carry, or be unambiguously bound to:
- envelope schema version;
- immutable algorithm-suite identifier;
- key role/purpose and key ID;
- owner/account and object/record identifier;
- object role and protocol context;
- nonce/IV and authentication tag (or the exact library-defined combined ciphertext/tag representation);
- ciphertext or wrapped-key bytes;
- KDF name/version/parameters/salt when a password-derived wrapper is used;
- creation/version metadata required for migration, not secret material.

Use a canonical, deterministic serialization before signing or hashing. Reject duplicate JSON member names, ambiguous encodings, non-canonical base64/base64url, invalid UTF-8, unexpected fields where the schema is closed, and integer/string coercion. AAD must be reconstructed from validated canonical fields, not accepted as arbitrary attacker-controlled bytes.

### 4.3 Versioning and downgrade prevention

- Version the content envelope, key wrapper, KDF profile, device certificate, registry state, recovery wrapper, and signed report independently. A single global version number is insufficient when formats evolve at different rates.
- Use explicit suite IDs such as `SENTRYIQ-CE-v1-A256GCM` and `SENTRYIQ-HPKE-v1-X25519-HKDFSHA256-A256GCM`. Names are protocol identifiers, not a license to change parameters under the same ID.
- New formats must be additive and migration-aware. Preserve a read-only compatibility path for existing Vault v3 and Gallery v1/v2 data until conversion is verified and recoverable.
- Unknown suite IDs, unknown versions, unsupported critical fields, invalid lengths, stale registry epochs, and weaker legacy algorithms are rejected. Never try multiple algorithms until one decrypts.
- Migration must be explicit, logged without secrets, resumable, and tested against interrupted writes and rollback. Keep old key material only while authoritative references remain or an approved rollback window is open.
- A version change must not silently reinterpret old ciphertext, AAD, key IDs, or signatures.

## 5. Rotation and lifecycle rules

### 5.1 Routine content-key rotation

1. Generate a new independent key using the CSPRNG and assign a new immutable key ID.
2. For each object, use the authorised device to unwrap the existing DEK and wrap it to the new recipient/key. Do not send the DEK or plaintext content to PHP.
3. Replace only the wrapped DEK/envelope using a compare-and-swap hash of the exact prior envelope.
4. Keep both old and new keys available during migration. New writes use the explicitly activated key ID.
5. Derive migration progress from the authoritative object/key-reference inventory, including active objects, pending uploads, cancellation states, and any retained backup/version references. Do not trust a client-supplied completion count.
6. Retire the old key only after a complete locked inventory proves zero remaining references, a verified recovery path exists, and the approved rollback window has expired.
7. Gallery's existing 24-hour rollback window is a reasonable current Gallery-specific baseline. Do not generalise it to every key role without a threat/recovery analysis.

### 5.2 Root, master, device, and trust-root rotation

- **Gallery root-key rotation** is distinct from RSA wrapping-key rotation. It requires rewrapping every retained Gallery private-key envelope and every enrolled passkey/recovery envelope, with a staged proof that the new root can be recovered before activation.
- **Master-phone replacement** is an authority transition: require offline recovery, generate a new master signing/key-agreement pair, increment the registry epoch, issue a signed transition, revoke the old master and invalidate prior-epoch sessions/grants. It is not ordinary key rotation and cannot be performed by the application host.
- **Additional-device rotation** generates a new device identity, explicitly approves it from the master, issues new scoped credentials, and revokes the prior device key. No device may rotate itself into broader authority.
- **Verifier-key rotation** is performed under an independently controlled verifier trust-root procedure. The phone must authenticate the new verifier key through a separately trusted transition; the old key is revoked after an overlap period that cannot permit indefinite dual trust.
- **Release/TUF trust-root rotation** follows the signed TUF root-update process and its threshold rules. Never replace a TUF root merely because the application host supplies new bytes.
- **Recovery-secret rotation** occurs after use, suspected exposure, or owner-requested renewal. Stage and verify the new recovery wrapper before invalidating the old one. Never send the recovery secret to either server.

### 5.3 Rotation safety invariants

- At every committed state, every retained ciphertext object has at least one usable, authorised key path.
- No old key is deleted based only on a browser-reported progress percentage.
- Failed, interrupted, or aborted migrations leave both old and new material available until the owner resolves the migration.
- Concurrent upload, deletion, cancellation, envelope replacement, and key retirement are serialised or protected by versioned compare-and-swap.
- A rollback restores a coherent keyring and active-key selection; it must not erase objects already migrated to the new key.
- Backups and retained object versions count as key references if they may need to be restored.

## 6. Compromise response by key role

| Compromised material / event | Immediate response | Recovery and residual limits |
|---|---|---|
| Password or password-derived KEK | Owner changes password; rewrap VMK with new Argon2id salt/profile; invalidate sessions | If attacker also obtained VMK/plaintext while unlocked, password change alone cannot revoke copied data |
| VMK / Vault data key | Treat all Vault content encrypted under it as exposed; create new data-key hierarchy and re-encrypt client-side; revoke sessions | A compromised application process currently sees the VMK; target design removes this server-side exposure |
| Individual DEK | Re-encrypt the affected object under a new DEK and update its wrapped envelope; inspect access evidence | Previously copied plaintext/ciphertext plus DEK cannot be recalled |
| Gallery root/private key | Use a trusted device/recovery path to generate a new root and private identity, rewrap retained key envelopes and re-encrypt/re-wrap affected object keys as required | Root compromise may expose all Gallery objects accessible under that root; treat all corresponding DEKs as exposed |
| Master-phone signing key | Invoke offline master replacement, advance registry epoch, revoke master and reissue device certificates | Previously copied signed grants remain valid until epoch/expiry enforcement reaches relying devices |
| Additional-device key | Master revokes device ID/key ID, increments registry epoch, invalidates device sessions/grants | Already copied plaintext or exported data cannot be remotely erased |
| Recovery secret | Treat recovery authority as compromised; complete a new master/recovery ceremony and rotate recovery wrapper; invalidate old material | If attacker has already used it to replace the master, recovery and device registry must be reconciled from independent owner evidence |
| HelioHost verifier signing key | Stop accepting reports from that key; pin emergency replacement only through the trusted phone/recovery procedure; rotate and audit | Forged reports may have been accepted during the compromise window; review sensitive operations and release state |
| Release signing/workflow trust | Freeze releases; revoke compromised workflow identity/trust root; verify last known-good commit and artifact; publish a new independently verified trust transition | A malicious but validly attested release may already have reached clients; roll back only through explicit monotonic recovery policy |
| B2/service credential | Revoke/replace credential; review object access and signing activity; restrict bucket permissions | If ciphertext-only is maintained, credential compromise exposes object availability/metadata, not plaintext without user keys |
| Algorithm/library weakness | Freeze affected writes and key retirement; introduce a new suite/version; re-encrypt or rewrap all affected objects under a reviewed replacement | Migration scope depends on whether weakness affects confidentiality, integrity, key exchange, signatures, or only implementation |

Do not claim that rotation reverses prior disclosure. Rotation limits future use of compromised material; incident response must identify the exposure window and data/key versions at risk.

## 7. Implementation and compatibility gates

1. Pin the exact maintained crypto library and version for every non-native primitive. Record source, package integrity, provenance, update owner, vulnerability monitoring, and browser compatibility. No new cryptographic dependency is authorised by this design.
2. Verify that the minimum supported iOS Safari and Android browsers support the required WebCrypto operations, WebAuthn PRF, key import/export policy, secure random generation, and memory limits. If HPKE/Ed25519 support requires WASM, pin and verify the WASM artifact and its JavaScript loader as release-critical code.
3. Benchmark the proposed Argon2id 64 MiB profile on minimum supported phones. Retain existing 32 MiB envelopes for reads; no automatic weaker fallback. Select and record a single minimum profile before new-format writes ship.
4. Add known-answer tests for AES-GCM, Argon2id, HKDF, Ed25519, X25519/HPKE, RSA-OAEP Gallery compatibility, and canonical serialization. Use official test vectors and cross-language interoperability tests.
5. Add negative tests for nonce/tag/key length errors, nonce reuse detection where feasible, wrong AAD, cross-object substitution, invalid key IDs, unknown versions/suites, downgrade attempts, duplicate JSON keys, malformed encodings, replay, stale epoch, revoked key, and compromised trust roots.
6. Add migration tests for every legacy Vault/Gallery envelope, interrupted rotation, backup restore, concurrent mutation, and old-key retirement with outstanding references.
7. No production key generation, key migration, recovery ceremony, trust-root update, or release signing occurs as part of Phase 1.3 design work.

## 8. Explicit non-decisions carried forward

- Exact device certificate serialization and signed registry format: Phase 1.7.
- Final envelope schema, per-vault/per-object DEK hierarchy, and key-wrap transaction: Phase 1.6.
- Master-phone platform key storage and whether a native companion is required: Phase 1.5.
- Full recovery format, custody medium, lost-master ceremony and unrecoverable-loss procedure: Phase 1.8.
- Release/verifier trust-root distribution, emergency revocation and deployment protocol: Phase 2.
- The Argon2id 64 MiB performance profile remains proposed until supported-device benchmarks pass.
- Whether to retain RSA-OAEP for future Gallery generations or migrate to HPKE is not decided here. Existing Gallery ciphertext and keyring compatibility must remain readable; do not perform a speculative algorithm migration.

## 9. Completion checklist

- [x] Inventory existing Vault, passkey, Gallery, Ed25519, Sigstore and TUF cryptographic choices.
- [x] Define a proposed content-encryption, password-KDF, HKDF, device-signature, key-encapsulation and digest suite.
- [x] Specify key sizes, nonce/tag/salt/challenge sizes and opaque key-ID formats.
- [x] Define authenticated context, canonical serialization, independent format versions and downgrade rejection.
- [x] Define routine rotation, root/master/device/trust-root rotation boundaries and key retirement invariants.
- [x] Define compromise response for each material key role.
- [ ] Owner/security review of the proposed profile and Argon2id resource budget.
- [ ] Supported-device/library interoperability evidence before implementation.

**Conclusion:** Phase 1.3 defines a coherent proposed cryptographic profile grounded in existing repository primitives and standard protocols. It does not mean the target device-rooted key architecture is implemented or that any new key has been generated. Phase 1.4 should next formalise the separate key roles, ownership, custody, permitted operations, and non-sharing rules without changing code.
