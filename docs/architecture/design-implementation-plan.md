# SentryIQ — Design and Implementation Plan From the New Baseline

**Canonical application:** `https://sentryiq.bichet.co.za`  
**Application host:** existing SentryIQ host serving that origin  
**Security node:** HelioHost  
**Master device:** owner's phone  
**Status:** planning baseline; no production deployment or key initialisation authorised.

This plan supersedes the former Cloudflare Node A operational deployment plan. It starts from the agreed device-rooted architecture and does not restart completed application/security work without evidence that it must change.

## Operating rules
- Work in small, evidence-backed repository changes; update this plan after each completed item.
- Do not ask the owner to repeat established architecture decisions.
- Do not provision accounts, alter production, generate production keys, initialise a trust baseline, publish a release, or delete source until separately authorised.
- Never put secrets, private keys, recovery material, or production tokens in Git, issues, or chat.
- Preserve useful existing code and tests until dependency and reuse analysis proves they are obsolete.
- A design statement or passing unit test is not proof of host isolation or production acceptance.
- The master phone is the sole normal device-enrolment authority. Emergency replacement uses the offline recovery ceremony.

## Phase 0 — Freeze and reconcile the architecture
- [x] 0.1 Record canonical origin as `https://sentryiq.bichet.co.za`.
- [x] 0.2 Record SentryIQ as the application at that origin; HelioHost is the separate security node, not the application host and not a second full SentryIQ installation.
- [x] 0.3 Remove Cloudflare, Val Town, and the previous A/B/C deployment topology from the target architecture.
- [x] 0.4 Define master phone, authorised devices, independent verifier, and offline recovery roles.
- [x] 0.5 Repository baseline and legacy-topology disposition recorded in [legacy topology disposition](legacy-topology-disposition.md). The owner confirmed that no legacy nodes were ever provisioned and all SentryIQ components exist only in the repository. The old endpoints, runners, and workflows are repository code only; live-node cron, external-node caller, deployment-hook, and private-node-config investigations are **not applicable**. The focused audit identified the legacy CLI/endpoint coupling, missing PWA shell, and Apache/PHP Referrer-Policy disagreement. No source was removed and no deployment or key initialisation occurred. Broader dependency tracing and source remediation are carried forward as explicit implementation prerequisites.
- [ ] 0.6 Reconcile release-attestation policy, private-host contract, Node 4 event contract, docs, workflows, and configuration to the new origin and trust topology.
- [x] 0.7 Reviewed and closed PR #150 without merging; it targeted the retired Cloudflare Node A source branch. Generic release packaging steps may be reused after review.

## Phase 1 — Threat model and trust/key design
- [x] 1.0 Build the implementation-grade repository dependency map. Initial high-risk runtime, legacy verifier, passkey/device, report-signing, and CI dependency clusters are documented in [Phase 1 repository dependency map](phase-1-repository-dependency-map.md). The 2026-11-24 third pass completed the include/require and dynamic-dispatch sweep across all 132 tracked non-test PHP files (200 PHP files total, including 68 tests). It records private vault-engine includes, first-run/document dynamic includes, private Composer autoloaders, legacy CLI/config entrypoints, Node 4 alert callables, optional-extension checks, and the lack of normal-app edges into legacy verifier code. The full tracked non-test PHP sweep (132 files), legacy symbol-to-caller/test/workflow matrix, workflow classification, and private-config inventory are documented in Sections 9–10 of the dependency map. All five relevant PR workflow runs and all reported jobs passed on source commit 0811fc64252806c35c606cd92ac49dd0635e0057; the two later commits changed only audit/plan Markdown files. Phase 1.0 is closed.
- [x] 1.1 Produce the data-flow and trust-boundary design in [Phase 1 data-flow and trust-boundary design](phase-1-data-flow-and-trust-boundaries.md). It maps the application host, single HelioHost verifier, master phone, individually authorised devices, release pipeline, and offline recovery; records data/secret boundaries, authenticated flows, authority limits, compromise cases, browser/PWA limitations, fail-closed conditions, and HelioHost independence qualification. This is a proposed design artifact only; owner/design review remains required before treating the model as accepted. No provisioning, production key generation, baseline initialisation, release publication, or deployment occurred.
- [x] 1.2 Classify protected data and define where plaintext may exist in [Phase 1.2 protected-data and plaintext-location policy](phase-1-protected-data-and-plaintext-policy.md). The repository-backed audit distinguishes current Vault/Document server-side decryption from the browser-encrypted Gallery path; classifies user content, operational metadata, secrets, recovery/backup material; maps transient plaintext, sessions, logs, configuration and backup limitations; and defines target ciphertext-only server handling. This is a design artifact only; owner/design review remains required. No source implementation, production data, credentials, keys, backups, or deployment changed.
- [x] 1.3 Specify cryptographic algorithms, key sizes, key identifiers, rotation, versioning, and compromise response in [Phase 1.3 cryptographic profile](phase-1-cryptographic-profile.md). The profile inventories current Vault/passkey/Gallery/Ed25519/Sigstore/TUF primitives; proposes AES-256-GCM, Argon2id, HKDF-SHA-256, Ed25519, HPKE/X25519 and SHA-256 profiles; defines sizes, canonical AAD, format versioning, downgrade rejection, rotation invariants, and compromise response. Argon2id resource budget and browser/library interoperability remain review gates. Design-only; no keys generated or code changed.
- [x] 1.4 Specify distinct release-signing, verifier-signing, master-device, per-device, DEK, recovery, and session key roles in [Phase 1.4 key-role separation](phase-1-key-role-separation.md). The design assigns owners/custody, allowed and forbidden operations, key hierarchies, app-host/verifier/release boundaries, role-specific rotation/revocation, and negative security tests. It explicitly separates data recovery from master-replacement authority. Owner/security review remains required; design-only.
- [x] 1.5 Assess supported phone/browser key protection and whether a native companion is required in [Phase 1.5 platform key-protection assessment](phase-1-platform-key-protection.md). The assessment distinguishes WebAuthn PRF and non-extractable WebCrypto keys from Secure Enclave custody; records Safari PRF/WebCrypto/IndexedDB constraints; compares PWA-only, native, and hybrid models; and recommends a native master companion if hardware-backed authority is required. Owner decisions on companion adoption, P-256 versus Ed25519/X25519 master keys, and minimum platform versions remain required before implementation. The existing repository has no tracked PWA manifest/service worker; include the missing PWA shell in the target design.
- [ ] 1.6 Define envelope encryption and per-purpose/per-vault DEK wrapping; ensure server stores ciphertext and wrapped keys only.
- [ ] 1.7 Define device certificate format, permission scopes, expiry, registry epoch, enrolment and revocation protocol.
- [ ] 1.8 Define offline recovery ceremony, recovery-material format, lost-phone revocation, key rotation, and unrecoverable-loss behaviour.
- [ ] 1.9 Threat-model malicious same-origin JavaScript, service-worker replacement, dependency compromise, browser/OS compromise, verifier compromise, and release-signer compromise.

## Phase 2 — Release and deployed-code verification
- [ ] 2.1 Inventory current release builder, manifest, GitHub/Sigstore provenance, release policy, asset delivery, and deployment paths.
- [ ] 2.2 Define canonical signed release manifest covering HTML, JS, CSS, PWA manifest, icons, service worker, and relevant server-side runtime inventory.
- [ ] 2.3 Define independent trust-root distribution and key rotation for release verification.
- [ ] 2.4 Design HelioHost verifier as a read-only, isolated service with a dedicated signing key and no application-write authority.
- [ ] 2.5 Verify actual browser-delivered asset bytes, including redirects, cache variants, unexpected files, and response headers.
- [ ] 2.6 Determine what private server-side files HelioHost can safely inspect; do not claim public HTTP checks prove private PHP/config integrity.
- [ ] 2.7 Define nonce/challenge, report schema, freshness, expiry, replay protection, signed pass/fail evidence, and outage behaviour.
- [ ] 2.8 Define the phone-side verification gate and fail-closed behaviour before sensitive operations.
- [ ] 2.9 Add tamper, injection, stale report, forged signature, replay, missing asset, unexpected asset, and verifier-outage tests.

## Phase 3 — Master phone and device lifecycle
- [ ] 3.1 Design trusted first-run initialisation and secure bootstrap of release/verifier trust roots.
- [ ] 3.2 Implement master-device identity creation and protected local key storage.
- [ ] 3.3 Implement QR/challenge-based candidate-device pairing.
- [ ] 3.4 Implement explicit master approval with device identity, permission review, and fresh user verification.
- [ ] 3.5 Implement per-device certificates, scopes, renewal, revocation, and audit evidence.
- [ ] 3.6 Enforce that non-master devices cannot enrol/promote other devices or change trust roots.
- [ ] 3.7 Implement lost-phone recovery, master rotation, old-master revocation, and recovery event evidence.
- [ ] 3.8 Test theft, duplicate pairing, replay, revoked device, offline device, lost master, and recovery-material loss.

## Phase 4 — HelioHost security-node qualification
- [ ] 4.1 Confirm HelioHost plan/account capabilities and acceptable-use terms for the intended verifier workload.
- [ ] 4.2 Confirm PHP/CLI/runtime availability, scheduler, outbound HTTPS, TLS validation, filesystem permissions, process isolation, service supervision, and log access.
- [ ] 4.3 Determine whether a persistent service is permitted; if not, design a bounded scheduled verifier without weakening isolation or freshness.
- [ ] 4.4 Establish separate credentials and a protected signing-key boundary.
- [ ] 4.5 Demonstrate that the application host cannot read or modify verifier policy, signing keys, or evidence.
- [ ] 4.6 Build and test a non-production verifier instance only after qualification and explicit approval.

## Phase 5 — Integration, acceptance, and migration
- [ ] 5.1 Map existing SentryIQ vault encryption, passkeys, sessions, audit logging, and first-run installer to the target design; implement the PWA shell defined in Phase 1.
- [ ] 5.2 Reuse existing release-manifest, Sigstore, Ed25519, nonce, and file-inventory components only after reviewing trust assumptions and adapting contracts.
- [ ] 5.3 Remove obsolete Cloudflare-specific deployment workflows, configs, dependencies, and docs only after confirming no active consumer; preserve a concise historical archive where needed.
- [ ] 5.4 Update canonical origin and identity bindings consistently; resolve the `.htaccess` / PHP Referrer-Policy disagreement by selecting one policy and add tests that enforce consistency.
- [ ] 5.5 Run full repository tests, security tests, static checks, dependency audit, and PWA/service-worker review.
- [ ] 5.6 Conduct independent design review and threat-model review.
- [ ] 5.7 Perform non-production deployment and adversarial acceptance tests.
- [ ] 5.8 Prepare rollback and recovery rehearsal; verify backups contain ciphertext and no usable private keys.
- [ ] 5.9 Obtain explicit owner approval before production key initialisation, migration, release, or deployment.

## Current next action

Phase 1 items 1.0, 1.1, and 1.2 have repository-backed design artifacts: the implementation-grade dependency map, [Phase 1 data-flow and trust-boundary design](phase-1-data-flow-and-trust-boundaries.md), and [Phase 1.2 protected-data and plaintext-location policy](phase-1-protected-data-and-plaintext-policy.md). Phase 1.2 records current data stores and plaintext paths, distinguishes current implementation from target policy, classifies content/metadata/secrets/recovery material, and defines ciphertext-only server requirements. Phase 1.1 and 1.2 remain subject to owner/design review before the models are treated as accepted. The next planned task is Phase 1.6: define the concrete user-data key hierarchy, envelope formats, device-to-device key distribution, wrapping, synchronisation, and re-encryption/migration transactions. Phase 1.6 must preserve the platform-custody decision recorded in Phase 1.5; no implementation may assume browser-only master-key custody without owner approval. No legacy source has been deleted; preserve it until replacement contracts and tests exist. No production keys, baselines, releases, backups, or deployments have been created.
