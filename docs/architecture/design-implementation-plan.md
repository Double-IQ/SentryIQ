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
- [~] 0.5 Expanded tree and component inventory documented in [legacy topology disposition](legacy-topology-disposition.md). Focused entrypoint trace completed: the app front controller/security bootstrap do not directly invoke the old node classes; dedicated CLI runners and the public Node 4 endpoint do. Live cron, dynamic includes, external callers and private host configuration still need owner-host evidence.
- [ ] 0.6 Reconcile release-attestation policy, private-host contract, Node 4 event contract, docs, workflows, and configuration to the new origin and trust topology.
- [x] 0.7 Reviewed and closed PR #150 without merging; it targeted the retired Cloudflare Node A source branch. Generic release packaging steps may be reused after review.

## Phase 1 — Threat model and trust/key design
- [ ] 1.1 Produce a data-flow and trust-boundary diagram for app host, HelioHost verifier, master phone, other devices, release pipeline, and recovery material.
- [ ] 1.2 Classify protected data and define where plaintext may exist.
- [ ] 1.3 Specify cryptographic algorithms, key sizes, key identifiers, rotation, versioning, and compromise response; use established libraries and protocols rather than custom cryptography.
- [ ] 1.4 Specify distinct release-signing, verifier-signing, master-device, per-device, DEK, recovery, and session key roles.
- [ ] 1.5 Decide how client keys are protected on supported phone/browser platforms; document WebCrypto non-extractability limitations and whether a native companion is required.
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
- [ ] 5.1 Map existing SentryIQ vault encryption, passkeys, sessions, audit logging, first-run installer, and PWA/service-worker code to the target design.
- [ ] 5.2 Reuse existing release-manifest, Sigstore, Ed25519, nonce, and file-inventory components only after reviewing trust assumptions and adapting contracts.
- [ ] 5.3 Remove obsolete Cloudflare-specific deployment workflows, configs, dependencies, and docs only after confirming no active consumer; preserve a concise historical archive where needed.
- [ ] 5.4 Update canonical origin and identity bindings consistently; add tests to prevent drift.
- [ ] 5.5 Run full repository tests, security tests, static checks, dependency audit, and PWA/service-worker review.
- [ ] 5.6 Conduct independent design review and threat-model review.
- [ ] 5.7 Perform non-production deployment and adversarial acceptance tests.
- [ ] 5.8 Prepare rollback and recovery rehearsal; verify backups contain ciphertext and no usable private keys.
- [ ] 5.9 Obtain explicit owner approval before production key initialisation, migration, release, or deployment.

## Current next action

Continue Phase 0.5: trace all runtime call sites and configuration for A/B/C, Node 4, private-host collector and release workflows. Node C plus generic report-signing, evidence, release-state, public-asset and Sigstore components are the leading reuse candidates; confirm through call-graph and tests before refactoring. Do not delete source yet.
