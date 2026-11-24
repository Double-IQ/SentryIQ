# Phase 1.9 — Threat model: browser runtime, supply chain, verifier, release, and device compromise

**Status:** Repository-backed threat model; owner/security review required.  
**Baseline:** Phase 1.1–1.8 proposed trust, data, key, device, and recovery designs.  
**Application:** `https://sentryiq.bichet.co.za`  
**Application host:** Untrusted for user-data confidentiality, device authority, and release truth.  
**Verifier:** One independent specialised HelioHost security verifier; not a second application installation.  
**Scope:** Threat-model malicious same-origin JavaScript, service-worker replacement, dependency compromise, browser/OS compromise, verifier compromise, release-signer compromise, application-host/storage compromise, device loss, and recovery abuse. This is a design artifact; no live node or production deployment was inspected or changed.

## 1. Executive risk statement

The highest-impact confidentiality threat is malicious code executing in the trusted SentryIQ origin while an authorised user unlocks or uses the application. Such code can read plaintext displayed to the page, observe WebAuthn PRF output delivered to JavaScript, invoke page-accessible WebCrypto keys, alter what the user sees, and exfiltrate data. Encryption at rest and a server-side hash check do not protect data from malicious code at the moment it is used.

The highest-impact authority threat is compromise of the master phone or its master signing key. The target design limits this with a native hardware-backed master companion, explicit user-visible approvals, signed device certificates, independent offline recovery, and monotonic authority epochs. A PWA-only master key cannot claim Secure Enclave custody.

The highest-impact supply-chain threat is a malicious but validly released client: a compromised dependency or release workflow may produce code with valid provenance. Sigstore/TUF and the independent verifier help establish source/build/deployment identity, but they do not prove that the code is benign or that the browser executed only the measured bytes.

The independent HelioHost verifier reduces the application host's ability to lie about deployment evidence. It must not become a second application authority, a user-data key custodian, or a release signer.

## 2. Assets and security objectives

| Asset | Required security property | Primary impact if compromised |
|---|---|---|
| Vault, Documents, Gallery plaintext | Confidentiality and integrity on authorised devices | Disclosure, modification, extortion, privacy loss |
| VRK, DRK, GRK and per-object DEKs | Confidentiality, role separation, controlled rotation | Broad or object-specific content disclosure |
| Master signing key | Authenticity and exclusive device authority | Rogue device enrolment, scope expansion, master takeover |
| Per-device signing/key-agreement keys | Device identity and scoped access | Device impersonation and access within granted domains |
| Offline DRS and MRAK | Recovery confidentiality and integrity | Content recovery theft or master replacement takeover |
| Device certificates and signed registry | Authenticity, freshness, anti-rollback | Unauthorised device or stale/revoked device acceptance |
| Release artifacts and trust metadata | Integrity, provenance, anti-rollback | Malicious client code or forged release |
| HelioHost verifier key and policy | Authenticity of independent measurement reports | False deployment evidence and user deception |
| Session credentials and challenges | Authentication, replay resistance | Session impersonation or request replay |
| B2 and other service credentials | Least privilege and availability | Object-store access, deletion, metadata exposure |
| Logs, metadata, backups | Confidentiality, integrity, controlled retention | Account/activity disclosure or bulk compromise |

Security objectives:
- application-host compromise alone must not decrypt protected user content;
- no server, verifier, release pipeline, or additional device can mint master authority;
- all device enrolment/revocation and key distribution are verifiable independently of the application host;
- clients detect tampering, replay, stale registry state, and downgrade attempts;
- key and recovery compromise is scoped and has a defined response;
- availability limitations and irreversible exposure are stated honestly.

## 3. Adversaries and capabilities

| Adversary | Assumed capabilities | Important limits |
|---|---|---|
| Internet attacker | Phishing, credential stuffing, network interception attempts, malicious requests, replay | Cannot break sound cryptography or TLS directly |
| Compromised application host/operator | Read/alter app files, database, sessions, logs, object indexes, responses; deny service; serve malicious same-origin code | Must not possess user-data keys or master/verifier/release private keys in target design |
| Malicious same-origin script | Execute with SentryIQ origin privileges; inspect DOM and user input; call permitted WebCrypto operations; read PRF output and plaintext in page memory | Cannot extract a true Secure Enclave private key held only by a native companion, but may trick the companion unless the native approval UI validates the request |
| Compromised dependency/CDN | Supply modified JS/WASM/package code or build-time payload | Provenance can identify source/workflow but cannot establish benign intent |
| Compromised browser/OS/extension | Read or alter page memory, intercept input/output, access browser profile, use device privileges | Hardware isolation can protect selected private keys, not all plaintext or screen content |
| Stolen/lost additional device | Use locally cached keys and plaintext, act under its certificate while valid | Remote revocation cannot erase copied plaintext or work while offline |
| Stolen/lost master phone | Attempt master signing, access locally cached roots, approve rogue devices | Offline recovery and authority epoch can replace master; prior copied data cannot be recalled |
| Compromised HelioHost verifier | Sign false reports, leak verifier private key, deny service | Must have no user-data keys, app write credentials, or device authority |
| Compromised release workflow/signer | Publish malicious code with valid provenance or sign a malicious artifact | Independent review and verifier may detect unexpected bytes, not prove intent |
| Compromised B2/service credential | Read/delete/replace ciphertext objects, issue URLs, inspect metadata | Ciphertext-only design limits plaintext disclosure without user keys |
| Insider/physical attacker | Access recovery materials, devices, backups, or host accounts | Separate custody, least privilege, audit and tamper-evident storage reduce risk but do not eliminate it |

## 4. Trust boundaries and attack surfaces

1. **Browser/PWA origin:** highest-risk boundary for plaintext and PRF output. It is trusted only while its delivered code, runtime, browser, and OS remain trustworthy.
2. **Application host:** can serve code and relay/store data. It is not a trusted key authority or content decryption boundary.
3. **Master phone/native companion:** sole normal authority for device approval. The native approval surface must display and validate exactly what it signs.
4. **Additional devices:** individually certified and scoped. Every authorised device can still copy data it is allowed to decrypt.
5. **HelioHost verifier:** independent measurement and report signing only. Its key and host are separate from application credentials and user data.
6. **Release pipeline and trust roots:** build provenance, artifact signing, and TUF root updates are separate from master/device authority.
7. **Backblaze B2/object storage:** ciphertext store and signed-URL service; exposes size/timing/object access metadata.
8. **Offline recovery:** DRS and MRAK are outside both online servers and ordinary backup archives.

## 5. Threat scenarios and required controls

### 5.1 Malicious same-origin JavaScript / XSS

**Attack path**
1. Attacker exploits XSS, compromised first-party code, template injection, malicious update, or compromised dependency.
2. Malicious script runs under the SentryIQ origin while the owner unlocks Vault/Gallery or approves a device.
3. Script reads plaintext from the DOM or application state, captures user input, reads WebAuthn PRF output returned to JavaScript, or invokes a page-accessible non-extractable CryptoKey.
4. Script exfiltrates content/keys or changes the approval screen/request before the user confirms.

**Impact:** Critical confidentiality and integrity loss for data used during the compromised session; possible device-enrolment deception if approval UI is also compromised.

**Controls**
- strict CSP with nonces/hashes, no unsafe inline script, no unreviewed remote scripts, and no third-party analytics/tag managers on key-handling pages;
- self-host security-critical JS/WASM and pin dependency versions/digests; use SRI for externally loaded scripts where appropriate;
- minimise the amount of JS loaded on unlock, recovery, and device-approval screens;
- short-lived client key use, best-effort memory clearing, no plaintext persistent browser storage, and explicit lock/logout;
- native companion displays candidate device identity, public-key fingerprints, scopes, operation, and challenge itself; it rejects unknown operations and does not sign arbitrary PWA-supplied bytes;
- independent release manifest/provenance and verifier measurement of deployed assets;
- synthetic canary tests that demonstrate what injected code can access, so the residual risk is measured rather than denied.

**Residual risk:** A malicious first-party script executing while data is unlocked can access plaintext and page-visible PRF output. CSP/SRI/release verification reduce injection paths but do not prove that legitimate signed code is safe. The native companion can protect the master private key, but a compromised PWA may still request or misuse content operations unless the companion validates them independently.

### 5.2 Service-worker replacement and offline-cache persistence

**Current state:** The repository audit found no tracked PWA manifest, service-worker entrypoint, or service-worker registration in the audited browser scripts. There is no current service-worker runtime to claim as protected.

**Future attack path**
- An attacker who controls the origin or an update path registers/replaces a service worker.
- The worker intercepts navigations and fetches, serves malicious cached JS, persists after the page closes, or serves stale application code after a security fix.
- A malicious worker may cache protected responses or replay stale protocol state.

**Controls before any service worker is introduced**
- keep service-worker scope and cached content minimal; cache only public, content-addressed shell assets;
- never cache plaintext Vault/Document/Gallery content, recovery pages, session responses, signed URLs, or usable key material;
- pin worker script digest in release metadata and test update/rollback lifecycle;
- require a reviewed worker update, safe activation, old-worker retirement, and immediate security revocation procedure;
- use `no-store` for authenticated/key-sensitive endpoints and verify that browser cache rules cannot override it;
- ensure a stale worker cannot bypass release/registry freshness checks.

**Residual risk:** Browser service-worker execution is controlled by the browser origin. A server-side verifier can measure the worker file but cannot prove which worker instance a compromised browser is currently executing.

### 5.3 Dependency and build-supply-chain compromise

**Attack path**
- A package, CDN script, GitHub Action, Composer dependency, compiler, or build runner is compromised.
- Malicious code enters a build or runtime artifact and is shipped with a plausible version or valid workflow attestation.

**Controls**
- pin GitHub Actions to immutable commit SHAs; keep dependency lockfiles and hashes;
- use a minimal, reviewed dependency set; inventory PHP, JS, WASM, and native dependencies;
- generate SBOM/provenance for release artifacts; verify source repository, workflow identity, ref, commit, and artifact digest;
- use reproducible or independently repeatable builds where practical;
- review dependency changes, maintain vulnerability monitoring, and test rollback;
- no external script may be loaded into the key-handling origin without explicit security review.

**Residual risk:** A compromised but authorised dependency or build tool can create a malicious, correctly attested release. Provenance proves where/how it was built, not that the code is safe.

### 5.4 Browser, OS, extension, and physical-device compromise

**Attack path**
- Malware, jailbreak/root access, malicious browser extension, remote debugging, OS compromise, malicious profile sync, backup extraction, or physical access observes plaintext and local key use.

**Controls**
- use platform key stores and hardware-backed keys for master authority where available;
- prefer Secure Enclave P-256 for native iOS master signing/key-agreement if approved; do not describe browser CryptoKey as hardware-backed;
- require local user verification for master approvals and sensitive key operations;
- lock on idle, logout, device loss, and registry revocation; minimise plaintext lifetime;
- provide per-device revocation and domain-root rotation;
- test backup/restore and device migration; do not silently export master private keys.

**Residual risk:** An OS-level attacker or malicious extension may observe plaintext, screen contents, input, or active PWA data. Hardware-backed signing keys do not protect content already decrypted into application memory.

### 5.5 Application-host compromise or malicious administrator

**Attack path**
- Attacker changes PHP, JS, data indexes, device registry responses, object envelopes, sessions, or logs; withholds current registry; serves malicious assets; or denies service.

**Controls**
- client-side content encryption before upload; server stores ciphertext and wrapped keys only;
- master-signed certificates/registry and device-signed mutations; clients verify rather than trust server fields;
- monotonic authority/registry/domain/release versions and anti-rollback;
- independent HelioHost measurement and report signing;
- least-privilege service credentials and separate verifier host;
- short-lived object-scoped B2 URLs and private runtime config;
- no user-data key in PHP sessions/configuration.

**Residual risk:** Host compromise can deny service, expose metadata/ciphertext, serve malicious code, and replay state within freshness windows. The current Vault and Documents implementations still perform server-side decryption; Phase 1.2 records these as gaps until client-side migration is implemented. No live host inspection has been performed.

### 5.6 HelioHost verifier compromise

**Attack path**
- Attacker steals verifier signing key, changes verifier policy, tampers with measurement inputs, or causes a false report to be signed.

**Controls**
- verifier private key and host identity separate from application host, release signer, and master keys;
- read-only deployment evidence inputs; no user-data store access, B2 write credential, PHP session, or app-host write credential;
- challenge-bound, expiring reports with release identity, digest, policy version, timestamp, and decision;
- owner phone pins verifier public key and validates every signature/binding;
- verifier cannot rotate its own trust key or install a replacement without owner-authorised trust transition;
- emergency key revocation and report-audit procedure.

**Residual risk:** A compromised verifier may forge reports during the compromise window or deny service. It must not be able to decrypt user data or approve devices. A signed verifier report is evidence under a pinned key, not proof of runtime browser integrity.

### 5.7 Release-signer / CI workflow compromise

**Attack path**
- Attacker compromises repository permissions, workflow token, OIDC trust policy, build runner, release signing, or TUF root process.
- Malicious code or release metadata is published under a trusted workflow identity.

**Controls**
- immutable workflow references and narrowly scoped permissions;
- short-lived OIDC/Sigstore identity, no long-lived release private key on application host;
- TUF root threshold and monotonic version verification;
- independent release review and artifact digest checks;
- verifier independently measures deployed bytes; master phone validates release identity before high-risk actions;
- emergency freeze, trust-root revocation, and last-known-good rollback policy.

**Residual risk:** A compromised authorised workflow can attest to malicious code. Release attestation proves provenance, not benign behaviour. If malicious code executes in the PWA, it can still target plaintext and page-accessible keys.

### 5.8 Device theft, malicious authorised device, and revocation

**Attack path**
- A device is stolen while unlocked or has copied domain roots/DEKs/plaintext.
- An authorised device intentionally exfiltrates content within its scope.
- A disconnected device misses a revocation and later reconnects with stale state.

**Controls**
- unique per-device keys and explicit scopes; no shared device identity;
- short-lived device certificates and signed registry freshness;
- master-signed revocation, session invalidation, domain-root rotation, and re-enrolment;
- device-side encryption and per-object DEKs;
- stale devices fail closed for online writes and authority operations.

**Residual risk:** A device that already copied plaintext, keys, or ciphertext plus keys cannot be remotely made to forget them. An offline device cannot receive revocation until it reconnects. An authorised malicious device can exfiltrate data it is legitimately allowed to decrypt.

### 5.9 Offline recovery material compromise or loss

**Attack path**
- DRS is photographed/cloud-synced/stolen; MRAK is copied; recovery materials are stored together; or owner loses one/both materials.

**Controls**
- separate DRS and MRAK roles and physical custody;
- no server receives either secret;
- signed one-time master replacement and independent data recovery envelopes;
- recovery rotation after use or suspected exposure;
- tested offline recovery drills and owner-controlled inventory.

**Residual risk:** Anyone obtaining DRS can unwrap domain roots; anyone obtaining MRAK may authorise a master replacement. If both and all authorised devices are lost, data and authority are unrecoverable. No help-desk bypass is permitted.

### 5.10 B2/service credential and object-store compromise

**Attack path**
- Attacker obtains B2 application key or signed URL, reads/deletes/replaces objects, or infers user activity from object metadata and access patterns.

**Controls**
- least-privilege B2 capabilities and separate credentials from all user-data keys;
- short-lived, object-scoped signed URLs; credentials never sent to browser;
- ciphertext-only uploads with authenticated envelope and object ID/role binding;
- integrity verification and object-version inventory; rotate/revoke service credential on suspicion.

**Residual risk:** Availability, ciphertext integrity, object sizes, access patterns, and metadata may be exposed. Ciphertext-only encryption limits content disclosure unless user keys are also compromised.

## 6. STRIDE summary

| STRIDE category | SentryIQ examples | Primary controls |
|---|---|---|
| **Spoofing** | Fake master, device, verifier, release, or recovery identity | Pinned keys, signed certificates, role-specific key IDs, proof of possession |
| **Tampering** | Modify object envelope, registry, release, service worker, or ciphertext | AEAD/AAD, signatures, canonical payloads, digests, epochs, verifier measurement |
| **Repudiation** | Deny device approval, revocation, or object mutation | Signed master/device statements, bounded audit events, immutable revision IDs |
| **Information disclosure** | XSS, PRF capture, PHP plaintext, session leak, metadata/log/backup exposure | Client-side encryption, native master key, CSP, no-store, data minimisation, secret-free logs |
| **Denial of service** | Host/verifier/B2 outage, stale registry withholding, recovery lockout | Backups, independent verifier, cached signed state, restore drills; no cryptographic availability guarantee |
| **Elevation of privilege** | Additional device grants itself scopes, session becomes master, recovery bypass | Master-only operations, signed scope allowlist, epochs, separate recovery authority, negative tests |

## 7. Risk register and residual acceptance

| Threat | Inherent severity | Target residual severity | Acceptance condition |
|---|---|---|---|
| Malicious same-origin JS while unlocked | Critical | High | Owner explicitly accepts browser runtime limitation; native master authority and strict release controls are in place |
| PWA/service-worker replacement | Critical | High | No service worker until update/integrity controls and negative tests pass |
| Browser/OS compromise | Critical | High | Device platform controls, limited key lifetime, recovery and revocation; residual stated |
| App-host compromise | Critical | Medium–High | Server has no user-data keys; client signatures/epochs detect tampering; availability loss accepted |
| Release workflow compromise | Critical | High | Independent review, provenance, TUF, verifier measurement, emergency trust revocation |
| Verifier compromise | High | Medium | Independent key custody, owner pinning, no user-data access, rotation procedure |
| Additional-device compromise | High | Medium | Least scope, revocation, domain-root rotation; copied data cannot be recalled |
| Recovery-material compromise | Critical | High | Separate offline custody, dual-material ceremony, rotation and drill |
| B2 credential compromise | High | Medium | Ciphertext-only objects, least privilege, short URLs, credential rotation |
| Metadata/log leakage | Medium–High | Medium | Field minimisation, allowlisted logs, access control and retention |

“Residual severity” is not a statement that the threat is eliminated. It is the remaining risk after the proposed controls and owner acceptance conditions.

## 8. Security assumptions and non-goals

- The owner controls the master phone and offline recovery materials.
- Cryptographic libraries, browser engines, OS key stores, and release build systems are not assumed infallible; they are versioned, tested, and monitored.
- HelioHost is independent only after its filesystem, process, credentials, network, and deployment boundaries are technically qualified. The repository design does not prove that qualification.
- A verifier report cannot attest that a browser is uncompromised, that an OS is clean, that a human saw an unaltered screen, or that code is benign.
- A signed release attestation proves provenance under a trust policy, not correctness or safety.
- Encryption cannot prevent an authorised device from copying plaintext it has decrypted.
- Revocation cannot erase previously copied content or operate on a disconnected device.
- No production deployment, live node, host cron, or private runtime config has been inspected; owner confirmed legacy nodes were never provisioned.

## 9. Required validation and acceptance tests

### Browser/runtime
- Inject a synthetic malicious same-origin script in a test build and document access to plaintext, PRF output, and page-accessible CryptoKeys.
- Verify CSP blocks unapproved inline/eval/remote scripts and SRI detects changed external assets.
- Verify no analytics/tag manager/remote widget executes on unlock, recovery, or device approval pages.
- When a service worker is introduced, test malicious replacement, stale worker rollback, cache poisoning, and update interruption.

### Supply chain/release
- Modify a dependency or build artifact and verify provenance/digest checks reject it.
- Verify every GitHub Action uses immutable references and least-privilege permissions.
- Test a validly signed but unapproved release and ensure master/verifier policy rejects it.
- Test emergency release trust-root revocation and last-known-good recovery.

### Host/verifier
- Tamper with device registry, object envelopes, domain epochs, and release metadata; clients must reject.
- Replay stale signed registry/release state; clients must enforce monotonic version and freshness.
- Simulate verifier key compromise and verify phone-side revocation/re-pin path.
- Prove verifier credentials cannot read user-data stores, PHP sessions, B2 write credentials, or application secrets.

### Device/recovery
- Steal/revoke a synthetic additional device; verify session invalidation, root rotation, and stale-device rejection.
- Attempt additional-device scope escalation and master replacement without MRAK; reject.
- Test lost master with DRS+MRAK, each single-material failure, and both-material loss.
- Verify no recovery secret is sent to server or written to logs/backups.

### Data and metadata
- Inspect server storage dump and verify only ciphertext/wrapped keys/public metadata exist for migrated domains.
- Test log redaction with synthetic passwords, filenames, tokens, PRF output, signed URLs, and exception messages.
- Test B2 credential rotation and verify object integrity and metadata exposure boundaries.
- Test backup/restore and verify encrypted recovery envelopes and object versions match.

## 10. Phase 1.9 completion and implementation gates

- [x] Identify adversaries, assets, objectives, and trust boundaries.
- [x] Threat-model malicious same-origin JavaScript, XSS, service-worker replacement, dependencies, browser/OS, app host, verifier, release signer, devices, recovery, and B2.
- [x] Record STRIDE threats, inherent/residual severity, mitigations, and acceptance conditions.
- [x] Define validation tests and explicit residual-risk statements.
- [ ] Owner/security review of high residual risks, especially same-origin JavaScript and browser/OS compromise.
- [ ] Native companion and master-key platform decision from Phase 1.5.
- [ ] Implementation test harness and independent security review before production rollout.

**Conclusion:** SentryIQ's most important unresolved risk is not the choice of AES key size; it is the trustworthiness of the code executing on the authorised device while plaintext is available. The design therefore combines client-side encryption, a protected master-authority surface, signed device state, independent release/deployment evidence, and explicit acceptance of browser/OS residual risk. None of these controls alone proves the whole runtime safe.
