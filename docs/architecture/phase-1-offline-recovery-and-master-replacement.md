# Phase 1.8 — Offline recovery authority, data recovery, and lost-master ceremony

**Status:** Proposed recovery design; owner/security review required.  
**Baseline:** Phase 1.6 key hierarchy and Phase 1.7 device-registry protocol.  
**Master authority:** Owner's phone; replacement only through offline recovery.  
**Recovery custody:** Owner-controlled offline materials, separate from both servers.  
**Scope:** Define separate data-recovery and master-replacement materials, their envelopes, custody, recovery flows, rotation, compromise response, and unrecoverable-loss rules. No recovery secret, key, backup, or production state was generated or changed.

## 1. Recovery objectives and separation

SentryIQ has two different recovery problems. They must not be solved by one shared secret:

1. **Data recovery:** recover the Vault, Documents, and Gallery domain roots (VRK, DRK, GRK) so the owner can decrypt existing ciphertext on a replacement authorised device.
2. **Master replacement:** authorise a new master signing/key-agreement identity, advance the authority epoch, revoke the lost master, and re-issue device certificates.

Use two independent offline materials:

| Material | Proposed name | Purpose | Must not be used for |
|---|---|---|---|
| Offline data recovery seed | **DRS** | Unwraps the separate encrypted recovery envelopes for VRK, DRK, and GRK | Signing device certificates, replacing master identity, routine login |
| Offline master-replacement authority key | **MRAK** | Signs a one-time master replacement transition | Decrypting user content, routine device enrolment, verifier/release signing |

Both materials are owner-controlled and stored offline. Neither is stored by the application host, HelioHost, a cloud drive, email, a password-reset provider, or an ordinary server backup.

**Full lost-master recovery requires both:** MRAK authorises the new master; DRS recovers the domain roots. Possessing only one is not sufficient to complete a full account restoration. This is intentional two-material separation.

## 2. Offline data recovery seed (DRS)

### 2.1 Entropy and representation

- Generate 32 bytes (256 bits) of cryptographically secure random entropy on a trusted recovery setup device.
- Display the entropy as a standard 24-word BIP-39 mnemonic with the standard checksum. Use the mnemonic as an encoding of the 256-bit entropy; do not add an optional BIP-39 passphrase.
- The mnemonic is a high-entropy recovery secret, not a human-chosen password. Do not use Argon2id or another password KDF as a substitute for random entropy; derive wrapping keys with HKDF-SHA-256.
- Show the mnemonic once, require the owner to confirm a subset of words, and provide an explicit offline write-down/secure-storage step. Never send it to PHP or log it.
- The owner stores the phrase offline in a protected physical or offline digital medium. Do not photograph it, paste it into chat, email it, sync it to a cloud note, or store it alongside an unencrypted backup archive.
- A recovery checksum detects transcription errors but does not provide secrecy. A person who obtains the phrase obtains the ability to unwrap all domain roots covered by the current recovery envelopes.

### 2.2 Recovery key derivation and envelope

For each domain root, derive an independent wrapping key:

`recoveryWrapKey = HKDF-SHA-256(DRS_entropy, randomSalt32, canonicalRecoveryInfo, 32)`

The `canonicalRecoveryInfo` is domain-separated and binds:
- fixed protocol and recovery-envelope version;
- owner/account ID;
- domain (`vault`, `documents`, or `gallery`);
- root key ID and domain epoch;
- exact recovery purpose and suite ID.

Encrypt the 32-byte domain root with AES-256-GCM using a fresh 12-byte nonce and 16-byte tag. The authenticated AAD binds the same owner/domain/root ID/epoch/version fields. The application host stores only the encrypted recovery envelope.

Logical fields:
- `schema_version`, `suite_id`, `owner_id`, `domain`;
- `root_key_id`, `domain_epoch`;
- `kdf_id=HKDF-SHA-256`, `salt` (32 bytes);
- `nonce` (12 bytes), `ciphertext` (32-byte root plus 16-byte tag);
- `aad_profile`, creation time, recovery-envelope ID.

The recovery seed itself, derived wrapping key, and unwrapped domain root exist only in the trusted recovery client while the ceremony is active. Authentication failure is terminal; no alternate KDF, root key, or legacy fallback is attempted automatically.

## 3. Offline master-replacement authority key (MRAK)

- Generate an independent offline Ed25519 signing key pair using a trusted offline recovery tool. Private seed: 32 bytes; public key: 32 bytes; signature: 64 bytes.
- The MRAK public key and key ID are pinned in the initial owner trust state and included in a master-signed recovery-authority record. It is not the master-phone key, verifier key, or release key.
- Keep the private seed in an owner-controlled offline signing medium/tool. It must not be imported into the SentryIQ PWA, application PHP process, HelioHost verifier, or a normal authenticated session.
- The offline signing tool receives a bounded recovery request (via QR or removable medium), displays the owner/account, old master key ID, new master public-key fingerprints, requested authority epoch, and expiry, and signs only the fixed `MASTER_REPLACEMENT` operation.
- The MRAK cannot sign ordinary device certificates, scope changes, releases, verifier reports, data objects, or arbitrary messages.
- A new master must also prove possession of its own newly generated signing key. An MRAK signature alone cannot nominate an arbitrary public key without the replacement device's proof-of-possession.
- Rotate the MRAK after use, suspected exposure, or owner-requested renewal. A new recovery public key is pinned through a transition signed by the old MRAK and accepted by the new master.

The exact offline signing-tool packaging, key-storage medium, and owner ceremony are implementation gates. The repository currently contains no offline recovery signer; no such tool is claimed to exist.

## 4. Initial setup and recovery readiness

Before the account is treated as recoverable:

1. Generate the DRS and MRAK independently using a trusted, reviewed setup tool.
2. Create one data-recovery envelope for each active domain root and verify each envelope locally by decrypting a test copy.
3. Pin the MRAK public key and key ID in the master-signed trust state.
4. Store DRS and MRAK private material separately from the master phone and separately from server-controlled backups. Prefer separate sealed envelopes/locations so one physical theft does not automatically expose both.
5. Record the recovery protocol version, recovery public-key fingerprint, date, and tested domain list without recording the secrets.
6. Run a recovery drill against a copy of the encrypted recovery bundle and verify that the resulting device can decrypt authenticated test objects from all three domains.
7. Confirm that the owner can identify the recovery materials and distinguish data recovery from master replacement.
8. Do not mark recovery ready until all three domain envelopes and the MRAK signature test pass.

A recovery kit that has never been tested is not a verified recovery path.

## 5. Full lost-master replacement ceremony

### 5.1 Preconditions

- The owner has the offline MRAK private material and DRS.
- A trusted replacement device/companion is available and has passed the platform key-custody gate in Phase 1.5.
- The recovery client/release is verified independently; the application host is only a ciphertext and signed-object relay.
- The owner has the latest available encrypted recovery bundle, signed registry state, and object-version inventory. A stale or incomplete server response is not accepted silently.

### 5.2 Ceremony

1. **Create new identity:** the replacement master generates a new signing key pair and separate key-agreement key pair locally. For iOS hardware-backed custody, use the owner-approved Secure Enclave profile; do not import an old private key.
2. **Create request:** the replacement device creates a canonical recovery request containing owner ID, old master key ID, new public keys and suite IDs, key IDs, next authority epoch, current registry digest, random 32-byte challenge, event ID, issued time, and short expiry.
3. **Offline authorisation:** transfer the request to the offline recovery signer. The offline tool displays all material fields, confirms the fixed operation is master replacement, and signs the canonical request with MRAK.
4. **Verify proof of possession:** the replacement device proves possession of its new master signing key. The recovery client verifies the MRAK signature against the pinned recovery public key and rejects wrong owner, stale challenge, old/new key collision, wrong epoch, unsupported suite, expiry, or replay.
5. **Recover domain roots:** use DRS locally to decrypt the current VRK, DRK, and GRK recovery envelopes. No phrase, root key, derived key, or plaintext content is sent to the server.
6. **Verify data recovery:** decrypt a known authenticated canary/test object from each domain and verify its content/envelope binding. If any domain fails, stop before declaring full recovery.
7. **Rotate authority:** advance `authority_epoch`, create a new master-signed registry, revoke the old master key ID, invalidate all old-epoch device certificates and sessions, and close outstanding pairing challenges.
8. **Rotate data roots:** because the old master may have been lost or stolen, create new domain roots and increment each domain epoch. Rewrap all active DEKs under the new roots; if root/DEK exposure is suspected, generate new DEKs and re-encrypt affected objects. Retain old versions only for the approved recovery/rollback period.
9. **Re-enrol devices:** issue fresh certificates and root envelopes to the devices the owner still approves. No old certificate is silently carried into the new authority epoch.
10. **Rotate recovery materials:** generate a new DRS, new domain recovery envelopes, and a new MRAK key pair. Verify the new DRS and new MRAK before revoking the old recovery materials.
11. **Commit and audit:** publish the signed recovery event, registry, root envelopes, and domain epochs. The audit event records IDs, timestamps, result, and key IDs only; never record secrets or decrypted data.
12. **Confirm completion:** the replacement master and each re-enrolled device verify the new registry and domain roots. The old master and old recovery materials are rejected.

The app host may persist and relay the signed recovery event but cannot create it, verify the DRS, decrypt roots, or approve a different replacement master.

## 6. Recovery variants and failure outcomes

| Situation | Permitted outcome |
|---|---|
| Master lost; MRAK and DRS available; recovery bundle intact | Full master replacement and data recovery |
| Master lost; MRAK available but DRS unavailable | Master authority can be replaced only if the owner explicitly chooses a new empty account/state. Existing encrypted content remains inaccessible; do not claim full recovery |
| Master lost; DRS available but MRAK unavailable | Data roots may be recoverable on a trusted device, but no new master authority can be established. No server-side reset or email override |
| Master lost; both MRAK and DRS unavailable; no authorised device remains | Account and encrypted data are unrecoverable by design. The server cannot bypass cryptography |
| Master still available; DRS lost or exposed | Master creates a new DRS, rewraps all domain roots, tests recovery, then retires the old DRS |
| Master still available; MRAK lost or exposed | Master rotates the MRAK public key through a signed trust transition and provisions a new offline key |
| MRAK suspected compromised; master unavailable | Treat master replacement authority as compromised. Do not trust an unsolicited recovery transition; require independent owner verification and follow incident procedure |
| DRS suspected compromised | Rotate DRS envelopes. If the attacker may have obtained domain roots, rotate domain roots and affected DEKs; prior disclosure cannot be undone |
| Both recovery materials compromised | Treat as full recovery-authority compromise; revoke/rotate while a trusted master remains. If no trusted master remains, no server override is permitted |

No email link, support ticket, application-host administrator, database edit, HelioHost report, or session reset may bypass the offline recovery requirements.

## 7. Data recovery without master replacement

If the master phone remains trusted but an additional device loses its local keys:
1. The master verifies the device identity and owner request.
2. The master reissues a device certificate or enrols a replacement device through Phase 1.7.
3. The replacement device receives fresh HPKE domain-root envelopes from the master.
4. The DRS is not required for ordinary additional-device enrolment when the master is available.
5. The replacement device proves it can decrypt a test object before being marked active.

If the master remains available and the DRS is lost, the master can generate a new DRS and rewrap the current domain roots. This does not require a master replacement.

## 8. Recovery-material rotation and custody

### 8.1 DRS rotation

1. Generate a new 256-bit DRS.
2. Create new recovery envelopes for the current VRK, DRK, and GRK.
3. Verify each new envelope locally and run a canary recovery test.
4. Commit the new envelopes and recovery version.
5. Only after successful verification, mark the previous DRS/envelopes retired.
6. If the old DRS may have been disclosed, rotate the affected domain roots and assess whether DEKs/content must also be rotated.

### 8.2 MRAK rotation

1. Generate a new offline MRAK key pair.
2. Verify its public key and proof-of-possession in the offline environment.
3. Create a recovery-authority transition binding old/new MRAK key IDs, public-key fingerprints, protocol version, and effective time.
4. The current master signs the transition; the old MRAK also signs it where the old key is still trusted.
5. Relying clients accept the new recovery public key and record the old key as retired.
6. Destroy or securely archive the old private key according to the incident/retention decision. It must no longer be accepted for new recovery events.

### 8.3 Physical and digital storage

- DRS and MRAK private material are not stored on the master phone, app host, verifier, cloud drive, email, or normal backup archive.
- Keep the two materials separate, clearly labelled by purpose, and protected from casual access. Use tamper-evident packaging or an owner-approved offline hardware medium.
- If duplicate copies are made, record the number and storage locations in an owner-controlled inventory that contains no secret bytes.
- Do not place both materials in the same unencrypted physical container or on the same removable device.
- The recovery bundle stored by SentryIQ contains encrypted root envelopes and signed public state only. It never contains raw DRS or MRAK private material.

## 9. Backup and restore interaction

- A complete backup contains encrypted object revisions, wrapped DEKs, domain-root recovery envelopes, signed device registry, public certificates, key IDs, and B2 object-version inventory.
- Backup encryption uses a separate backup encryption key. It is not DRS, MRAK, VMK, or any domain root.
- Encrypt the backup archive before it leaves the source failure domain. Keep the backup key separately from the backup archive and separately from the DRS/MRAK custody where practical.
- A restore verifies the backup manifest/digests, registry signature, root envelopes, object-version inventory, and recovery canaries before making restored state active.
- A backup missing its object versions or matching key envelopes is incomplete. A backup without DRS and MRAK does not by itself restore master authority or data access.
- The repository runbook currently states automated backup integration and verified restore are not implemented. This design does not change that status.

## 10. Required security and recovery tests

- Wrong DRS, wrong mnemonic word, checksum failure, tampered envelope, wrong domain/root ID/epoch, and altered AAD all fail closed.
- DRS can unwrap each domain root only for its bound owner/domain/root ID/epoch.
- DRS cannot sign a master replacement; MRAK cannot decrypt a domain root.
- An MRAK signature with wrong owner, old master ID, wrong new public keys, stale challenge, unsupported suite, wrong authority epoch, expired request, or replayed event is rejected.
- New master proof-of-possession is mandatory; MRAK cannot nominate a key whose private key is unavailable.
- A server administrator cannot reset the master, replace the recovery public key, or fabricate a recovery event.
- Recovery materials are never sent in HTTP request bodies, query strings, logs, analytics, PHP sessions, or backup archives.
- Full recovery verifies a canary object in every data domain before activation.
- Recovery rotation is interruption-safe; the old recovery path remains valid until the new one is tested and committed.
- Master replacement invalidates old authority epochs, device certificates, sessions, pairing challenges, and signed grants.
- Lost/compromised-device tests prove that old copied plaintext cannot be remotely recalled and that new epochs protect future state.
- Backup restore tests prove that encrypted objects and envelopes are version-consistent and recoverable without application-host secrets.

## 11. Compatibility with current repository recovery

- The current Vault v3 recovery wrapper uses a 32-byte random recovery value represented as 64 hexadecimal characters. It is stored in a PHP session during first-run display and its wrapper is persisted in the Vault envelope.
- The current Gallery has a separate user-held recovery wrapper for its Gallery root key. It must not be assumed to be the same secret or format as Vault recovery.
- Migration to the unified DRS/BIP-39 representation must be an explicit client-side rewrap ceremony. Existing Vault and Gallery recovery wrappers remain readable until the owner verifies the new recovery bundle.
- No PHP endpoint may receive the new DRS or MRAK private material. Existing first-run session display of the legacy Vault recovery value is a legacy compatibility path to be removed when the client-side recovery flow replaces it.

## 12. Completion and open decisions

- [x] Separate data recovery from master-replacement authority.
- [x] Define DRS entropy, representation, derivation, and per-domain recovery envelopes.
- [x] Define MRAK signing role and owner-only custody.
- [x] Define full lost-master ceremony, data recovery proof, authority-epoch transition, root rotation, and device re-enrolment.
- [x] Define recovery rotation, compromise outcomes, backup interactions, and unrecoverable-loss behaviour.
- [x] Record legacy Vault and Gallery recovery compatibility.
- [ ] Owner approval of two-material full recovery requirement and physical custody approach.
- [ ] Decide whether 24-word BIP-39 representation is acceptable or retain 64-hex recovery codes with stronger transcription UX.
- [ ] Select and test the offline recovery signer implementation and recovery client before production use.

**Conclusion:** Full recovery requires two independent offline materials: one to replace master authority and one to recover content roots. If either is lost, full recovery is not guaranteed; if both and all authorised devices are lost, the data is unrecoverable. No server-side reset can bypass this.
