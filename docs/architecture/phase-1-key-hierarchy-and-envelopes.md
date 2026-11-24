# Phase 1.6 — User-data key hierarchy, envelopes, device distribution, and synchronisation

**Status:** Proposed target data-key design; owner/security review required.  
**Baseline:** `main` after Phase 1.5 merge.  
**Application:** `https://sentryiq.bichet.co.za`  
**Application host:** Ciphertext and wrapped-envelope relay/storage only.  
**Master authority:** Owner's phone; native companion recommended for hardware-backed authority, subject to owner decision.  
**Scope:** Define the user-data key hierarchy, object encryption and key envelopes, device distribution, synchronisation, revocation, and migration rules. The master signing/key-agreement suite remains selectable by the Phase 1.5 platform decision; this document does not create keys or change code.

## 1. Design objectives and invariants

1. Vault, Documents, and Gallery content is encrypted on an authorised device before any content bytes reach PHP or the object-storage service.
2. The application host stores ciphertext, public keys, signed device grants, wrapped domain roots, wrapped DEKs, opaque identifiers, and minimum operational metadata only.
3. No PHP session, application configuration, log, backup manifest, or HelioHost process contains a usable Vault root, Documents root, Gallery root, DEK, master private key, passkey PRF output, or recovery secret.
4. Each data domain has a distinct root key and epoch. A Gallery compromise must not automatically expose Vault or Documents.
5. Each independently encrypted object has a fresh random DEK. A DEK is never reused for a different object or purpose.
6. Domain root keys are wrapped separately to each authorised device's key-agreement public key. The server cannot unwrap them.
7. Device authority and content decryption are separate: the master signing key authorises devices; it is not a content key.
8. Offline recovery is a distinct owner-held path. The server stores only encrypted recovery envelopes.
9. Every encrypted envelope is versioned, suite-labelled, bound to canonical AAD, and rejects unknown algorithms, stale epochs, malformed encodings, and downgrade attempts.
10. Revocation prevents future authorised access after the new epoch is accepted; it cannot recall plaintext, ciphertext, or keys already copied by a previously authorised device.

## 2. Target key hierarchy

### 2.1 Independent data domains

Create independent random 256-bit root keys for each data domain:

| Domain | Root key | Protects | Device scopes |
|---|---|---|---|
| Vault | **VRK** — Vault Root Key | Vault records and encrypted Vault metadata | `vault.read`, `vault.write`, plus later fine-grained scopes |
| Documents | **DRK** — Documents Root Key | Document bytes and private document metadata | `documents.read`, `documents.write` |
| Gallery | **GRK** — Gallery Root Key | Gallery original/preview/thumbnail objects and private photo metadata | `gallery.read`, `gallery.write` |

- Each root key is exactly 32 random bytes, has a unique immutable key ID, and belongs to a monotonically increasing domain epoch.
- VRK, DRK, and GRK are independent CSPRNG outputs. Do not derive one domain root from another.
- Each domain root is used only as input to a purpose-separated HKDF derivation for wrapping DEKs. It is not used directly as a content-encryption key, signing key, session secret, or service credential.
- A device receives a domain root only if its master-signed certificate includes that domain's scope.
- Future domains (e.g. exports or shared vaults) receive separate roots rather than reusing one of the three existing roots.

### 2.2 Per-object data keys

- Generate a fresh 32-byte DEK for every object. A Vault record, document, Gallery original, Gallery preview, Gallery thumbnail, and private metadata object each receive independent DEKs.
- Encrypt the object with AES-256-GCM: 32-byte DEK, 12-byte random nonce, and 16-byte authentication tag.
- The object ciphertext and tag are uploaded/stored without plaintext. The DEK is wrapped under a domain-specific key derived from the relevant domain root.
- Do not derive DEKs deterministically from object IDs. The object ID is public metadata and must never be key material.
- A DEK compromise is scoped to the object encrypted under that DEK. A domain-root compromise has a wider blast radius and requires domain-root rotation and object-key migration.

### 2.3 Domain-root to DEK wrapping

For each object, derive a dedicated wrapping key:

`wrapKey = HKDF-SHA-256(domainRootKey, randomWrapSalt, canonicalInfo, 32)`

Where:
- `domainRootKey` is the 32-byte VRK, DRK, or GRK for the object's current domain epoch;
- `randomWrapSalt` is a fresh 32-byte CSPRNG salt per DEK wrapper;
- `canonicalInfo` is a versioned, unambiguous domain-separated value binding protocol, owner, domain, object ID, object role, domain epoch, root key ID, and DEK key ID;
- output length is exactly 32 bytes.

Encrypt the DEK under `wrapKey` using AES-256-GCM with a fresh 12-byte wrapping nonce and 16-byte tag. The wrapping AAD binds the same object/domain/epoch/key identifiers and the wrapper schema version.

This is a two-layer envelope:
1. object ciphertext is encrypted under the independent DEK;
2. the DEK is encrypted under a derived wrapping key from the domain root.

The server stores both ciphertexts and the public envelope metadata. It never receives either plaintext key.

## 3. Device-to-device domain-root distribution

### 3.1 Recipient key suites

The recipient key-agreement suite is explicit in every device public-key record and envelope. Phase 1.5 identifies two candidate profiles:

| Profile | HPKE KEM | KDF | AEAD | Intended use |
|---|---|---|---|---|
| `HPKE-v1-X25519-HKDFSHA256-A256GCM` | DHKEM(X25519, HKDF-SHA-256), RFC 9180 KEM ID 0x0020 | HKDF-SHA-256 (0x0001) | AES-256-GCM (0x0002) | Browser-managed devices and platforms where the audited implementation and persistence tests pass |
| `HPKE-v1-P256-HKDFSHA256-A256GCM` | DHKEM(P-256, HKDF-SHA-256), RFC 9180 KEM ID 0x0010 | HKDF-SHA-256 (0x0001) | AES-256-GCM (0x0002) | Native iOS master companion candidate using a Secure Enclave P-256 key-agreement key |

- Use a maintained HPKE implementation conforming to RFC 9180. Do not hand-roll DH, HKDF, nonce handling, or AEAD composition.
- HPKE base mode provides recipient confidentiality but does not by itself authenticate the sender. The outer root-key envelope must also be signed by the current master signing key and bound to the signed device certificate and registry epoch.
- Master signing and key-agreement keys are independent. A Secure Enclave P-256 signing key and a separate Secure Enclave P-256 key-agreement key are required if both operations are hardware-backed.
- A device cannot advertise an unsupported suite and ask the server to downgrade it. The master selects only an explicitly supported, policy-approved suite.
- The final master signature suite (P-256 ECDSA/SHA-256 versus Ed25519) remains subject to the Phase 1.5 owner decision. The envelope carries an explicit signature-suite ID and never infers it from the key ID.

### 3.2 Root-key envelope

One root-key envelope is created per device, per data domain, and per root epoch. Its logical fields are:

| Field | Meaning |
|---|---|
| `schema_version` | Root-envelope schema version |
| `suite_id` | Exact HPKE KEM/KDF/AEAD suite |
| `owner_id` | Canonical account/owner identifier |
| `domain` | `vault`, `documents`, or `gallery` |
| `root_key_id` | Immutable random ID for this domain root |
| `domain_epoch` | Canonical monotonic decimal string |
| `recipient_device_id` | Device receiving the envelope |
| `recipient_key_id` | Exact recipient key-agreement public-key ID |
| `recipient_key_fingerprint` | SHA-256 fingerprint of canonical recipient public key |
| `enc` | HPKE encapsulated key, in the suite's defined encoding |
| `ciphertext` | HPKE ciphertext containing the 32-byte domain root and authentication tag |
| `registry_epoch` | Current master-signed device registry epoch |
| `certificate_digest` | Digest of the master-signed device certificate |
| `created_at` / `expires_at` | Bounded envelope freshness metadata |
| `master_signature_suite` | Explicit signature algorithm identifier |
| `master_signature` | Signature over the canonical envelope statement and HPKE ciphertext |

HPKE `info` and AAD bind the protocol name/version, owner, domain, root key ID, domain epoch, recipient device/key IDs, certificate digest, and registry epoch. The master signature binds the same values and the exact HPKE `enc` and ciphertext bytes. A recipient rejects a valid HPKE envelope if the master signature, device certificate, epoch, scope, or expiry is invalid.

### 3.3 Enrolment distribution sequence

1. A candidate device generates its own signing and key-agreement key pairs locally. The private keys never leave that device's protected key store.
2. The candidate sends only public keys, key-suite IDs, a random device ID, proof of possession, requested scopes, and a short-lived pairing challenge.
3. The master phone independently verifies the candidate request, displays the device identity and requested scopes, and requires fresh owner verification.
4. The master signs the device certificate/grant and creates one HPKE root-key envelope for each approved data domain.
5. The master signs each root-key envelope statement. The application host stores the certificate and envelopes as opaque signed data.
6. The candidate verifies the master signature, certificate digest, scope, recipient key ID, registry epoch, domain epoch, expiry, and HPKE suite before decrypting the root locally.
7. The candidate verifies a known-answer challenge using the new root before the enrolment is marked complete.
8. The application host cannot create a device grant, add a domain, change a scope, or replace the root envelope without invalidating the master signature.

Exact device certificate serialization, human-readable pairing UX, and wire protocol are Phase 1.7. This sequence defines the required cryptographic behaviour, not the final API paths.

## 4. Object envelope format

### 4.1 Logical envelope fields

| Field | Meaning |
|---|---|
| `schema_version` | Object envelope schema version |
| `content_suite_id` | Exact content-encryption suite, initially AES-256-GCM |
| `owner_id` | Canonical owner/account identifier |
| `domain` | Vault, Documents, or Gallery |
| `object_id` | Random opaque object ID (at least 128 bits) |
| `object_role` | Typed role, e.g. vault-record, document, original, preview, thumbnail, private-metadata |
| `object_revision` | Immutable revision identifier or monotonic revision string |
| `domain_epoch` | Domain-root epoch used to wrap the DEK |
| `root_key_id` | ID of the domain root used for DEK wrapping |
| `dek_key_id` | Random immutable ID for the DEK |
| `payload_nonce` | 12-byte AES-GCM nonce for content encryption |
| `ciphertext` | Encrypted content including the 16-byte GCM tag |
| `wrap_suite_id` | AES-256-GCM DEK-wrapping suite |
| `wrap_salt` | 32-byte random HKDF salt |
| `wrap_nonce` | 12-byte AES-GCM nonce for DEK wrapping |
| `wrapped_dek` | Encrypted 32-byte DEK including the 16-byte GCM tag |
| `aad_profile` | Versioned canonical AAD profile identifier |
| `created_at` | Non-authoritative operational timestamp |

### 4.2 Authenticated context

Content AAD must bind:
- protocol/domain label and envelope version;
- owner/account ID;
- domain and object ID;
- object role and revision;
- content suite ID and domain epoch.

DEK-wrap AAD must bind:
- protocol/domain label and wrapper version;
- owner/account ID, domain, object ID, and object role;
- root key ID, domain epoch, and DEK key ID;
- wrap suite ID and AAD profile.

Canonical serialization must reject duplicate JSON keys, non-canonical encodings, invalid UTF-8, unexpected critical fields, and type coercion. Never accept a caller-supplied AAD byte string as authoritative. Reconstruct it from validated fields using the canonical encoder.

### 4.3 Server-visible fields

The server may see:
- owner/device IDs and public keys;
- domain, object IDs, roles, revisions, epochs, key IDs, and envelope versions;
- ciphertext sizes, object counts, timestamps, and access patterns;
- wrapped DEKs, HPKE encapsulated keys, encrypted root envelopes, signatures, and certificates.

The server must not see:
- plaintext object bytes or private metadata;
- VRK, DRK, GRK, DEKs, or derived wrapping keys;
- passkey PRF output, passwords, or password-derived KEKs;
- device signing or key-agreement private keys;
- data-recovery secret or master-replacement recovery authority.

## 5. Synchronisation and authorisation model

### 5.1 Storage and relay

- The application host stores immutable ciphertext revisions and their signed/wrapped envelopes. It does not decrypt content or decide which root key is correct.
- Object writes are client-encrypted before upload. The server validates bounded sizes, envelope structure, object ownership, signed device certificate, scope, current registry epoch, and revision transition.
- Every mutation is bound to the device identity and a signed operation statement. Other clients verify the device signature and scope rather than trusting server-authored metadata.
- The server may maintain a query index containing opaque object IDs, domains, roles, sizes, and revisions. Filenames, document MIME details, Gallery album/caption metadata, and Vault record contents remain encrypted.
- Object revision updates use compare-and-swap against the exact prior revision digest. Concurrent writes must create a conflict or new immutable revision, not silently overwrite a newer envelope.
- Deletion uses a signed tombstone and an explicit retention policy. Removing a pointer does not prove object versions or backups are erased.

### 5.2 Scope semantics

- Domain roots provide cryptographic access to a whole data domain. A device with the Vault root can decrypt Vault objects in that domain; the root does not itself distinguish read from write.
- Read/write restrictions are enforced by signed device scopes and signed mutation operations. A read-only device must not receive authority to submit valid write operations. The application host is not the sole enforcement point; other clients verify the signed operation.
- If future requirements need folder/collection-level isolation, create separate subdomain roots or object-level key grants. Do not assume a single domain root provides per-folder cryptographic isolation.
- Scope changes are master-signed registry transitions. The application host may relay them but cannot widen a device's scopes.

### 5.3 Offline and stale devices

- A device whose certificate or registry epoch is stale must not perform sensitive writes or authority operations until it synchronises and verifies the current signed registry state.
- Offline access to already downloaded ciphertext and keys may continue only within the explicitly approved offline policy. It cannot be remotely revoked while the device remains disconnected.
- On reconnect, a revoked device is denied current root-key envelopes and must not receive new domain epochs.
- A device that misses a domain-root rotation must obtain the current root envelope from the master-authorised distribution path; it must not be allowed to roll back the domain epoch.

## 6. Rotation, revocation, and migration transactions

### 6.1 New device

- Enrolment adds a new device certificate and one root envelope per approved domain.
- Existing object ciphertext and DEK wrappers do not need to change merely because a new device was enrolled.
- The new device receives only roots for approved domains. No private key or plaintext root key is sent to PHP.

### 6.2 Device revocation

1. The master signs a revocation for the device ID and its signing/key-agreement key IDs.
2. The registry epoch advances. Relying clients reject old-epoch certificates and sessions.
3. For each domain from which the device is removed, generate a new random domain root and increment that domain epoch.
4. Rewrap every active DEK under the new root-derived wrapping key. Object ciphertext remains unchanged if no content key was exposed.
5. Create fresh HPKE root envelopes for the remaining authorised devices and master. The revoked device receives none.
6. Commit the new root envelopes, DEK wrappers, active epoch, and signed registry transition as one recoverable transaction. Use a journal and compare-and-swap for each object.
7. Keep old root material only during an explicitly approved rollback window; retire only after a complete reference inventory and verified recovery path.

Revocation cannot erase old root keys, DEKs, plaintext, or ciphertext already copied by the revoked device. It prevents access to future state and to current storage versions after the rotation is accepted. The security report must state this limitation.

### 6.3 Domain-root rotation

- For routine rotation without suspected compromise, generate a new root and rewrap all DEKs under it; ciphertext can remain unchanged.
- For suspected root-key compromise, assume every DEK wrapper under that root may have been read. Generate new DEKs and re-encrypt all affected content under the new root epoch. Old ciphertext copies may remain decryptable to an attacker who already obtained the old root and wrappers; rotation cannot undo prior disclosure.
- Root rotation must be resumable and idempotent. A server-side journal records source/target key IDs, epochs, start time, status, and transaction identity. Completion is derived from authoritative object inventory, not a browser counter.
- Old root keys remain available until all active objects and pending operations have been migrated and the rollback window has expired.

### 6.4 Object-DEK rotation

- For a DEK-only compromise, create a new random DEK and re-encrypt that object. Update its object revision and wrap the new DEK under the current domain root.
- If the content was already disclosed, re-encryption protects future stored versions only; it does not recall previously copied plaintext.
- Never replace a wrapped DEK without a conditional expected-revision check.

### 6.5 Interrupted transactions

- A failed transaction leaves the previous active epoch and key material usable until the new transaction has committed completely.
- Pending uploads are bound to the domain epoch and root key ID allocated when the upload begins. A rotation must either complete or cancel them; it must not silently reinterpret them under the new epoch.
- Cancellation closes the reservation before deleting object-store bytes. Cleanup is retryable and the journal remains until the operation is confirmed.
- Concurrent upload, delete, cancellation, DEK rewrap, domain-root activation, and key retirement are serialised by a shared lock or equivalent transactional compare-and-swap mechanism.

## 7. Recovery and backup interactions

- Each domain root has a separately encrypted data-recovery envelope for owner-controlled offline recovery. The recovery secret is never uploaded; only the authenticated ciphertext wrapper is stored.
- Master-replacement authority is a separate offline proof. It authorises a new master identity and registry epoch; it is not the data-recovery key and does not automatically decrypt content.
- Recovery of a lost master must restore domain roots on the replacement owner's device, then issue new device certificates and root envelopes. Old master and prior-epoch grants are revoked.
- Backup archives contain encrypted object ciphertext, object envelopes, signed registry state, public certificates, root-key envelopes, and B2 object-version inventory. They must not contain raw domain roots, DEKs, private device keys, or offline recovery secrets.
- A complete restore requires the correct encrypted object versions and a valid owner recovery path. Missing root wrappers, mismatched object versions, or missing offline recovery material must fail clearly rather than inventing a recovery bypass.

## 8. Compatibility and migration from current code

| Current implementation | Target transition |
|---|---|
| Vault v3 whole-file AES-256-GCM envelope with VMK wrapped by password/recovery | Preserve read-only legacy path; migrate records client-side into per-record/object DEKs and a Vault domain root. Do not have PHP decrypt and re-encrypt during migration |
| Vault passkey PRF sent to PHP and VMK unwrapped server-side | New client-only PRF wrapper; PHP receives only signed/opaque envelope metadata and ciphertext |
| Documents encrypted by PHP after multipart upload | Client encrypts before upload; PHP stores ciphertext and minimised encrypted metadata only |
| Gallery v1/v2 RSA-OAEP-wrapped DEKs and browser AES-GCM objects | Preserve current Gallery object ciphertext and keyring compatibility; root-key/device envelope transition is explicit. Do not rewrite existing Gallery data until tested migration exists |
| Legacy Gallery server-side image encryption/metadata classes | Keep code only until caller/test audit and replacement coverage complete; never use as an automatic plaintext/server-side fallback |
| PHP session contains VMK | Remove VMK and all plaintext content keys from session; session stores authentication state and short-lived challenges only |

Migration steps:
1. Create and verify new domain roots on an authorised device.
2. Create owner recovery envelopes and verify recovery locally before migration starts.
3. Enrol the current master device and any explicitly approved additional devices with root envelopes.
4. Read legacy ciphertext on the authorised device, decrypt locally, re-encrypt with fresh DEKs and new envelopes, then upload new ciphertext.
5. Verify every migrated object by decrypting it locally and comparing authenticated content/metadata digests.
6. Keep old ciphertext and old key paths until inventory and recovery checks pass and the owner approves retirement.
7. Remove legacy server-side decrypt paths only after replacement tests, migration verification, and recovery drills succeed.

## 9. Security tests required

- Wrong owner/domain/object/role/epoch/key ID/AAD cannot decrypt or replace an object.
- A server-side storage dump reveals no plaintext content, domain root, DEK, derived wrapping key, PRF output, or private device key.
- HPKE envelope substitution, replay, wrong recipient, wrong suite, invalid encapsulated key, and altered ciphertext fail.
- A valid HPKE ciphertext without the current master signature and certificate/epoch binding is rejected.
- A device without a domain scope cannot obtain that domain root envelope.
- A revoked device receives no new root envelope and stale-epoch writes fail on all relying clients.
- A read-only device cannot create a valid signed mutation.
- Root rotation, DEK rotation, and device revocation survive interruption at every transaction boundary.
- Old key retirement fails while any active, pending, cancelling, backup, or rollback reference remains.
- Concurrent upload/delete/rotation operations cannot produce an object encrypted under an unrecorded epoch.
- Restore tests prove ciphertext, envelopes, registry, object versions, and offline recovery material are mutually consistent.
- Legacy Vault/Documents/Gallery migration never sends plaintext or usable keys to PHP.

## 10. Open gates and completion

- Phase 1.5 owner decision on native companion and master authority algorithm remains open. The envelope schema carries an explicit HPKE suite ID so the recipient's P-256 or X25519 profile can be selected without guessing; final master signing profile must still be approved.
- Phase 1.7 will define exact signed device certificate, registry, operation, and revocation wire schemas.
- Phase 1.8 will define offline data-recovery and master-replacement ceremonies and formats.
- Phase 2 will define the HelioHost/release trust protocol and deployment integration.
- This is a design artifact only. No production keys, root keys, DEKs, recovery material, ciphertext migration, application code, configuration, or infrastructure were created or changed.

- [x] Define separate Vault, Documents, and Gallery root keys and per-object DEKs.
- [x] Define client-side encryption and DEK wrapping with canonical AAD.
- [x] Define device-specific HPKE root envelopes and master-signed binding.
- [x] Define device enrolment distribution, sync, stale-epoch, revocation, and rotation behaviour.
- [x] Define interruption-safe transactions and backup/recovery interactions.
- [x] Record compatibility/migration paths for Vault v3, Documents, and Gallery.
- [ ] Owner/security review of root-key hierarchy, scope granularity, and device suite selection.
- [ ] Confirm master companion and signing/key-agreement suite before implementation.

**Conclusion:** Phase 1.6 specifies a ciphertext-only, multi-device envelope hierarchy with independent data domains, per-object DEKs, and master-authorised device distribution. It preserves the platform key-suite choice as an explicit envelope field until the owner decides the master-phone custody model. No implementation should begin until the owner approves that model.
