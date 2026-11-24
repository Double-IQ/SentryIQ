# Phase 1.10 — Consolidated security design baseline and owner-review decisions

**Status:** Consolidated design baseline complete; implementation is not yet authorised.  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Application host:** Existing SentryIQ host.  
**Independent security node:** One specialised HelioHost verifier; not a second SentryIQ application.  
**Master authority:** Owner's phone; sole normal device-enrolment authority.  
**Scope:** Consolidate Phase 0/1 decisions, repository evidence, target security requirements, unresolved owner choices, and implementation gates into one review baseline.

## 1. Executive disposition

The repository-backed Phase 1 design work is complete as a set of linked architecture artifacts. It defines the data-flow/trust boundaries, protected-data classification, cryptographic profile, key-role separation, platform custody assessment, data-key hierarchy, device certificate/registry protocol, offline recovery, and runtime/supply-chain threat model.

**The design is not yet accepted for implementation.** Several owner decisions remain open, most importantly whether the master phone will use a small native companion for hardware-backed key custody or remain PWA-only. That decision changes the master signing/key-agreement profile and must be settled before production key creation or device enrolment.

The current repository is not the target architecture:
- Vault content is still decrypted in PHP and the VMK is stored in PHP session state.
- The Vault passkey flow currently sends PRF output to PHP for VMK unwrapping.
- Documents are still encrypted/decrypted by PHP; plaintext exists in PHP upload temp/memory and download processing.
- The current Gallery browser-encryption path is the intended zero-knowledge direction, but older server-side Gallery classes remain and require a safe, tested retirement path.
- No tracked PWA manifest/service-worker shell or native companion exists.
- The PHP session save handler/path is not selected by application code.
- Automated backup integration and verified restore are not implemented.
- HelioHost is proposed, not provisioned or qualified. The owner confirmed that no legacy nodes were ever provisioned; all old node code is repository-only.
- No production keys, trust baseline, backup, deployment, or release were created by Phase 1.

## 2. Architecture baseline

### 2.1 System roles

| Component | Role | Must not become |
|---|---|---|
| SentryIQ application at the canonical origin | User-facing app, encrypted data relay/storage interface, authentication/session service, public asset delivery | User-data decryption authority or master-device authority |
| Owner's master phone | Sole normal device enrolment, scope change, and revocation authority | Server-controlled or shared master identity |
| Additional devices | Individually certified and explicitly scoped clients | Independent device administrators or second masters |
| HelioHost | One independent read-only security verifier with a dedicated report-signing key | Second SentryIQ app, content store, device authority, or release signer |
| Release pipeline/TUF/Sigstore | Build provenance, artifact integrity, release trust | Device enrolment or content-key custodian |
| Offline recovery | Emergency master replacement and data recovery through separate materials | Routine login or a server-side reset path |
| Backblaze B2 | Ciphertext object storage and narrowly scoped object transfer | Plaintext processor or key custodian |

### 2.2 Non-negotiable invariants

1. The owner phone is the only normal master and only normal device-enrolment authority.
2. Additional devices have individual keys, explicit scopes, expiry, proof of possession, and master-signed certificates.
3. The application host and HelioHost never receive usable Vault/Documents/Gallery roots, DEKs, master private keys, PRF output, or recovery secrets.
4. User content is encrypted on an authorised device before upload; server storage is ciphertext plus wrapped keys and minimal operational metadata.
5. Master signing, device signing, key agreement, content encryption, recovery, verifier signing, release provenance, session credentials, and service credentials are separate roles.
6. Every security-relevant state change is signed and versioned; clients reject tampering, replay, stale epochs, and downgrade attempts.
7. Offline recovery is separate from routine master authority. Full recovery uses separate data-recovery and master-replacement materials.
8. The verifier measures release/deployment evidence only; it cannot prove a browser/OS is uncompromised or that measured code is benign.
9. Revocation cannot recall plaintext or keys already copied by an authorised device.
10. No production key generation, migration, baseline initialisation, release publication, or deployment occurs without explicit owner authorisation.

## 3. Phase 1 artifacts

| Phase | Artifact | Result |
|---|---|---|
| 1.0 | [Repository dependency map](phase-1-repository-dependency-map.md) | Tracked include/dynamic-dispatch sweep, legacy symbol/caller/test/workflow matrix, config inventory, and code-preservation rules |
| 1.1 | [Data-flow and trust-boundary design](phase-1-data-flow-and-trust-boundaries.md) | Six trust domains, data flows, authority limits, failure cases, browser/PWA limits, and HelioHost qualification gate |
| 1.2 | [Protected-data and plaintext-location policy](phase-1-protected-data-and-plaintext-policy.md) | Data classification, current plaintext paths, metadata exposure, session/log/backup limitations, and ciphertext-only target policy |
| 1.3 | [Cryptographic profile](phase-1-cryptographic-profile.md) | Existing algorithm inventory, proposed suites, sizes, versioning, rotation, downgrade prevention, and compromise response |
| 1.4 | [Key-role separation](phase-1-key-role-separation.md) | Owners, custody, permitted/forbidden operations, key hierarchy, rotation, and negative security tests |
| 1.5 | [Platform key-protection assessment](phase-1-platform-key-protection.md) | WebAuthn PRF/WebCrypto limits, Secure Enclave constraints, PWA/native comparison, and native master companion recommendation |
| 1.6 | [Key hierarchy and envelopes](phase-1-key-hierarchy-and-envelopes.md) | Separate Vault/Documents/Gallery roots, per-object DEKs, HPKE device envelopes, sync, revocation, migration, and recovery interactions |
| 1.7 | [Device certificate and registry protocol](phase-1-device-certificate-and-registry-protocol.md) | Master-signed certificates/registry, scopes, authority epoch, registry version, proof-of-possession, replay protection, and revocation |
| 1.8 | [Offline recovery and master replacement](phase-1-offline-recovery-and-master-replacement.md) | Separate DRS/MRAK, per-domain recovery envelopes, full lost-master ceremony, rotation, and unrecoverable-loss outcomes |
| 1.9 | [Runtime and supply-chain threat model](phase-1-runtime-and-supply-chain-threat-model.md) | STRIDE, same-origin/browser/OS/service-worker/supply-chain/verifier/release/device/recovery threats, residual risk, and validation tests |

All Phase 1 artifacts are design/audit documentation. They do not imply the target architecture is already implemented.

## 4. Owner decisions required

The following defaults are recommendations, not silent approvals.

| Decision | Recommended default | Why it matters |
|---|---|---|
| **Master phone: PWA-only or native companion?** | **Native master companion** for authority operations; keep the PWA as UI/data client | A PWA cannot directly hold a Secure Enclave key. Same-origin JavaScript can misuse page-accessible keys and PRF output |
| **Master signing/key-agreement profile** | Separate Secure Enclave P-256 signing and P-256 key-agreement keys if native companion is approved | Apple's Secure Enclave supports P-256, not Ed25519/X25519. The Phase 1.3 Ed25519/X25519 proposal must be adjusted for hardware-backed master custody |
| **Additional-device profile** | Permit WebCrypto-managed keys only as an explicitly lower assurance tier; evaluate native keys for higher assurance | Additional devices need individual identities, but browser key storage is not hardware-backed by default |
| **Full recovery requirement** | Require both independent offline materials: DRS for data roots and MRAK for master replacement | One secret must not simultaneously decrypt all content and authorise a new master |
| **Recovery phrase format** | 24-word BIP-39 encoding of 256-bit random DRS entropy, with existing 64-hex recovery formats read-only during migration | More transcription-friendly with checksum; owner may prefer existing hex format |
| **Password KDF new profile** | Argon2id v1.3, opslimit 3, 64 MiB memory, 32-byte output, 16-byte salt; retain existing 32 MiB reads | Must be benchmarked on minimum supported phones; never silently downgrade |
| **Minimum browser/platform versions** | Safari 18+ for WebAuthn PRF; exact Android/browser floor determined by real-device matrix | PRF and crypto API support vary by authenticator, browser, OS, and device |
| **Data key hierarchy** | Separate VRK/DRK/GRK roots, one random DEK per object, client-side AES-256-GCM | Limits blast radius and keeps PHP/B2 from decrypting content |
| **Initial scope granularity** | Domain-level read/write scopes for Vault, Documents, Gallery | Simpler to verify; finer folder/collection scopes require separate roots or object grants |
| **Device certificate lifetime** | Maximum 30 days; fresh master approval to renew | Bounds stale device credentials |
| **Registry freshness** | Current proposal: no more than 24 hours old for online sensitive writes; review whether a shorter window is required | Controls how long a connected device might be served stale revocation state |
| **HelioHost qualification** | One isolated, read-only verifier with dedicated key; no user-data access | Prevents verifier compromise from becoming application or content compromise |

### 4.1 Recommended decision set

The recommended coherent baseline is:
- approve a native master companion;
- use separate Secure Enclave P-256 signing and key-agreement keys for the master phone;
- keep PWA browser keys as a lower-assurance tier for additional devices, unless a native companion is also required for them;
- retain AES-256-GCM content encryption and HPKE with explicit P-256/X25519 recipient suites;
- use separate DRS and MRAK materials and require both for full recovery;
- retain the 24-word DRS proposal subject to owner preference;
- benchmark Argon2id before selecting the final minimum profile.

If the owner chooses PWA-only master authority, the design must explicitly downgrade the custody claim and accept software/browser-key risks. It must not call those keys Secure Enclave-backed.

## 5. Current implementation gaps to carry into remediation

| Area | Verified current state | Required target change |
|---|---|---|
| Vault | PHP decrypts records; VMK stored in PHP session | Client-side unlock/decrypt; remove VMK and plaintext records from PHP/session |
| Vault passkeys | PRF output submitted to PHP; PHP unwraps VMK | Keep PRF output and unwrap entirely on authorised client |
| Documents | PHP receives plaintext upload and decrypts for download | Client-side encrypt/decrypt; server handles ciphertext only |
| Gallery | Browser-encrypted path exists; legacy server-side classes remain | Complete caller/test audit, migrate, prove old path unreachable, then retire safely |
| Sessions | Secure cookie flags/timeouts exist; save handler/path is not set by app | Session contains auth state/challenges only; qualify protected server session storage |
| Browser shell | No tracked PWA manifest/service worker or native companion | Build reviewed PWA shell; add service worker only after Phase 1.9 controls; decide native master companion |
| Logs/metadata | App logs include operational identifiers and some exception/filename data | Typed allowlists, redaction tests, retention, provider-log review |
| Backups | Runbook exists; automated backup and verified restore do not | Implement encrypted consistent backup and isolated restore test |
| Device authority | Existing passkeys are not the new master-signed device registry | Implement master-signed certificates, registry, scopes, epochs, and revocation |
| Verifier | HelioHost is proposed, not provisioned/qualified | Complete Phase 2 design and Phase 4 qualification before any deployment |

## 6. Implementation readiness and sequencing

<badge color="warning">Not ready for production implementation</badge>

Before implementation:
1. Owner decides native companion and master key suite.
2. Owner approves recovery material separation and representation.
3. Minimum supported browser/device matrix and Argon2id resource budget are tested.
4. Phase 0.6 reconciliation is completed: release-attestation policy, private-host contract, Node 4 event contract, docs, workflows, and configuration are reconciled to the new origin/trust topology.
5. Phase 2 designs and tests release manifest, trust-root distribution, HelioHost verifier, browser-delivered asset measurement, freshness, replay protection, and phone-side fail-closed gate.
6. Phase 4 qualifies HelioHost capabilities and isolation before a non-production verifier is considered.
7. Phase 5 implements and tests client-side Vault/Document migration, Gallery legacy retirement, device lifecycle, recovery, backups, and rollback.
8. Owner separately authorises production key initialisation, migration, release, and deployment.

Do not jump from design completion to production provisioning. A passing repository CI run validates the tested repository workflows; it does not prove browser runtime integrity, host isolation, backup recoverability, or deployed verifier independence.

## 7. Immediate next work

The next planned task is **Phase 0.6 reconciliation**, which remains unchecked in the implementation plan. It must close the remaining contract/document/workflow/configuration reconciliation against the agreed origin and trust topology. After that, resolve the owner decisions above and proceed to Phase 2 design. No legacy source is to be deleted merely to make the new plan look clean; preserve it until replacement tests and migration evidence exist.

## 8. Owner review checklist

- [ ] Approve or reject the native master companion recommendation.
- [ ] Confirm the master signing/key-agreement algorithm profile.
- [ ] Approve the two-material full recovery requirement (DRS + MRAK).
- [ ] Choose 24-word BIP-39 or existing 64-hex DRS representation.
- [ ] Approve Argon2id target after supported-device benchmark.
- [ ] Confirm minimum supported iOS/Safari and Android/browser versions.
- [ ] Confirm initial domain-level read/write scope model.
- [ ] Review device certificate lifetime and registry freshness.
- [ ] Approve the residual browser/OS and same-origin JavaScript risks.

**Conclusion:** Phase 1 has produced a coherent, repository-backed security design. The remaining blocker is owner acceptance of the platform and recovery decisions, followed by Phase 0.6 reconciliation and Phase 2 release/verifier design. No production implementation or deployment is authorised by this document.
