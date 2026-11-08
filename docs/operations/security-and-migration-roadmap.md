# SentryIQ Security and Migration Roadmap

**Status:** Active planning document  
**Last reviewed:** 2026-11-08  
**Canonical target origin:** `https://sentryiq.bichet.co.za`  
**Current production origin:** `https://bichet.co.za/SentryIQ`

This document is the project-level execution plan for security hardening, zero-knowledge work, independent integrity verification, and the eventual subdomain migration. It complements the detailed implementation issues and operational runbooks linked below.

## How to read status

- **Complete** means the change is merged or the configuration step is confirmed.
- **In progress** means implementation has started but acceptance criteria are not all met.
- **Pending** means not implemented or not verified.
- A merged PR is not evidence that production has been deployed or that runtime testing passed.
- Never mark a phase complete based only on code review or CI syntax checks.

## Current baseline

| Area | Current state |
|---|---|
| Subdomain DNS and HTTPS | Confirmed resolving with a valid certificate |
| New public document root | Created; directory listing disabled |
| New protected data directory | Created but empty; runtime provisioning not complete |
| Migration preparation | PR #15 merged |
| Backblaze B2 CORS | Exact old and new origins configured; browser-level verification still required |
| Gallery encryption design | PR #11 merged; end-to-end acceptance testing pending |
| Zero-knowledge password vault and documents | Not complete; PHP currently handles the master key and document crypto |
| Signed release verification | Not implemented end-to-end |
| Integrity Node 1 (BTM-SA) | Not deployed |
| Integrity Node 2 (Cloudflare Workers) | Not deployed |
| Production subdomain cutover | Not approved or performed |

## Guardrails

1. **Production safety:** Do not change production files, runtime configuration, DNS, credentials, passkeys, vault data, or object storage as part of roadmap documentation or code-only preparation. Production actions require an explicit approval and a reviewed step-by-step plan.
2. **Preserve rollback:** Keep the old origin and its protected data intact until the new origin has passed every required acceptance test and the rollback window has elapsed.
3. **Protect secrets:** Never commit private keys, recovery secrets, B2 application keys, signed URLs, session material, or runtime configuration. Do not request secrets in chat.
4. **Separate code, deployment, and verification:** Track each independently. A successful workflow is not a production deployment; an HTTP 200 is not a security test.
5. **No silent lockouts:** Integrity alerts must not automatically disable accounts, invalidate passkeys, or lock users out. Incident response requires corroboration and a documented operator decision.
6. **Threat-model the browser:** Client-side encryption protects stored data from a compromised storage/backend path, but a malicious same-origin JavaScript release can still capture plaintext or keys when users unlock the app. Release integrity and origin compromise resistance are therefore part of the zero-knowledge security boundary.

## Workstream 1 — Safe subdomain readiness

**Tracking:** [Migration issue #14](https://github.com/Double-IQ/SentryIQ/issues/14)  
**Operational guide:** [Subdomain migration runbook](./sentryiq-subdomain-migration.md)  
**Status:** Preparation merged; new deployment and cutover pending.

### Tasks

- [x] Confirm new subdomain DNS and HTTPS.
- [x] Disable directory listing in the new public root.
- [x] Configure B2 CORS for the exact old and new origins.
- [x] Merge migration preparation and document the first-run path hazard (PR #15).
- [ ] Review the complete application/runtime file inventory and deployment packaging.
- [ ] Provision the new protected runtime directory from a verified, recoverable source; verify ownership, PHP access, `open_basedir`, and restrictive permissions.
- [ ] Create and review the new root pointer configuration before the first public request. Do not run first-run setup on the new host: its default path calculation can resolve to the wrong directory.
- [ ] Verify all required runtime files and configuration references without copying or modifying the old installation.
- [ ] Confirm the intended WebAuthn RP ID and document the passkey re-enrolment plan. Passkeys registered for `bichet.co.za` do not automatically become credentials for `sentryiq.bichet.co.za`.
- [ ] Test login, 2FA, passkey enrolment/login, recovery, vault lock/logout, CSRF, and Gallery flows on the new origin.
- [ ] Test browser-origin B2 PUT/GET/DELETE from the new origin.
- [ ] Complete backup and restore rehearsal, rollback plan, and explicit cutover approval.
- [ ] Cut over only after all gates pass; retain the old origin during the agreed rollback window.

### Exit criteria

The new origin is independently recoverable, uses the intended protected data directory, passes the full functional/security smoke suite, has a tested rollback path, and has explicit approval for cutover. No old-origin data or credentials are removed as part of cutover.

## Workstream 2 — Gallery security completion

**Tracking:** [Gallery zero-knowledge issue #10](https://github.com/Double-IQ/SentryIQ/issues/10)  
**Status:** Client-side encryption architecture merged; runtime and end-to-end validation pending.

### Tasks

- [ ] Build repeatable browser tests for key creation, passkey PRF unlock, recovery-envelope unlock, and multi-device enrolment.
- [ ] Test key rotation, account/device removal, photo deletion, and recovery-secret lifecycle.
- [ ] Verify PHP receives only authorization metadata and ciphertext—not image plaintext, filenames, captions, thumbnails, or encryption keys.
- [ ] Verify B2 object authorization, short-lived URL expiry, and denial of cross-user/object access.
- [ ] Verify CORS and PUT/GET/DELETE from supported browsers and the new origin.
- [ ] Test iPhone Safari upload, preview, download, lock, and page lifecycle behavior, including WebP fallback and `createImageBitmap` compatibility.
- [ ] Verify temporary plaintext Blob URLs are revoked on lock/pagehide and that browser caches do not retain decrypted media unexpectedly.
- [ ] Review CSP, XSS exposure, dependency loading, and error/log paths for accidental plaintext or key disclosure.
- [ ] Document recovery limitations and the consequence of losing all passkeys and the recovery secret.

### Exit criteria

Automated and manual tests demonstrate that only ciphertext reaches the server/storage, authorized users can recover and decrypt on supported devices, unauthorized access is denied, and the documented browser/device support matrix passes.

## Workstream 3 — Full zero-knowledge vault and documents

**Tracking:** [Zero-knowledge vault issue #12](https://github.com/Double-IQ/SentryIQ/issues/12)  
**Status:** Not complete. Current PHP session-based master-key handling is not zero-knowledge.

### Tasks

- [ ] Produce a data-flow and threat-model inventory for passwords, notes, attachments, documents, backups, logs, sessions, and recovery.
- [ ] Define versioned client-side key hierarchy, authenticated encryption formats, key wrapping, rotation, and recovery before implementation.
- [ ] Implement a browser crypto/key-management foundation with test vectors and cross-browser tests.
- [ ] Design a backward-compatible vault migration that never sends plaintext or unwrapped master keys to PHP.
- [ ] Move vault encryption/decryption and key custody to the client; remove master keys and plaintext from PHP sessions and server memory.
- [ ] Move document encryption/decryption and preview generation to the client; ensure server-side processing handles ciphertext only.
- [ ] Define safe migration, rollback, backup, and recovery behavior for existing encrypted records.
- [ ] Add tests that inspect network requests, database values, sessions, logs, and backup artifacts for plaintext/key leakage.
- [ ] Complete independent security review and recovery drills before declaring zero-knowledge.

### Exit criteria

The server cannot decrypt vault or document content using its database, runtime files, logs, backups, or session state alone. Client-side tests and an independent data-flow review support that claim. Recovery and migration are tested and documented.

## Workstream 4 — Signed releases and independent Integrity Nodes

**Tracking:** [Integrity Nodes and signed releases issue #13](https://github.com/Double-IQ/SentryIQ/issues/13)  
**Status:** Design/issue defined; signing pipeline and both nodes pending.

### Release trust chain

- [ ] Confirm the authoritative source repository and updater target. The updater currently references `BTM-SA/SentryIQ`, while the working repository is `Double-IQ/SentryIQ`; resolve this before changing update behavior.
- [ ] Define a versioned release manifest containing release identity, monotonic sequence/anti-rollback data, commit/build identity, file paths, sizes, SHA-256 hashes, timestamp, and signing-key ID.
- [ ] Establish an offline or hardware-backed signing process. The signing private key must never be stored on production hosting or either verifier.
- [ ] Sign release manifests and verify signatures in the update client before accepting an update; a checksum alone is not authenticity.
- [ ] Make builds reproducible or otherwise attest the exact build inputs and artifact identity.
- [ ] Add CI security gates for tests, dependency review/scanning, secret scanning, and release artifact validation.
- [ ] Protect release tags/branches and separate build, signing, and deployment permissions.

### Independent verifiers

- [ ] Implement Node 1 on BTM-SA infrastructure, isolated from the production host.
- [ ] Implement Node 2 on Cloudflare Workers, independently administered from Node 1 and production.
- [ ] Give both nodes pinned public trust roots and independent schedules/configuration; neither node should trust the other's verdict.
- [ ] Verify the signed manifest and deployed public resources, including HTML, JavaScript, CSS, service worker/manifest if introduced, redirects, TLS, response headers, and unexpected external scripts/domains.
- [ ] Define a separate authenticated, read-only deployment attestation for private server-side files. Public HTTP scanning cannot prove the integrity of private PHP source or protected runtime configuration.
- [ ] Compare signed node reports and alert on disagreement, stale checks, missed checks, target unavailability, or verifier failure.
- [ ] Keep alert destinations and verifier credentials outside production control.
- [ ] Document common-mode risks: source-control compromise, signing-key compromise, DNS/account compromise, and malicious same-origin JavaScript.
- [ ] Perform adversarial tests, including stale/rolled-back releases, altered assets, unavailable nodes, forged reports, and compromised-origin simulations.

### Exit criteria

A release can be accepted only after cryptographic signature verification and policy checks. Both independent nodes produce fresh, independently verifiable reports; disagreement and missed-check alerts are exercised; incident response is documented. The nodes are detection and evidence systems, not a guarantee that a compromised origin cannot serve malicious code before detection.

## Workstream 5 — Origin hardening and incident readiness

### Tasks

- [ ] Review and remove unsafe inline script requirements; move toward nonce/hash-based CSP and eliminate `unsafe-inline` where feasible.
- [ ] Audit XSS sinks, HTML rendering, upload handling, authentication/session boundaries, CSRF, and security headers.
- [ ] Review cookies, session rotation, rate limits, authentication recovery, and least-privilege file permissions.
- [ ] Add dependency and secret scanning plus security-focused CI gates on the protected default branch.
- [ ] Establish independent alert routing, severity levels, response ownership, evidence preservation, and user communication templates.
- [ ] Write incident playbooks for signing-key compromise, production-origin compromise, verifier disagreement, data exposure, and recovery failure.
- [ ] Conduct a tabletop exercise and record corrective actions.

### Exit criteria

High-risk findings are fixed or explicitly accepted with compensating controls; alerts are tested end-to-end; operators can follow incident playbooks without relying on the potentially compromised production origin.

## Recommended execution sequence

The workstreams overlap, but the following order minimises migration risk:

1. **Gallery verification:** complete the existing client-side design and test it on desktop and iPhone Safari.
2. **Zero-knowledge foundation:** map data flows, agree the key hierarchy, and implement/test the browser crypto foundation.
3. **Vault and document migration:** move existing encrypted data safely and prove the server cannot decrypt it.
4. **Release trust chain:** implement signed manifests and client-side verification before depending on the integrity monitors.
5. **Integrity Nodes:** deploy and exercise both independent verifiers and alerting.
6. **Origin hardening:** close CSP/XSS and operational gaps; perform adversarial testing.
7. **Subdomain cutover:** provision the new protected runtime, complete all acceptance tests, rehearse rollback, and obtain explicit approval.

If a critical vulnerability is discovered, address it immediately rather than waiting for this sequence.

## Release and phase tracking

Update this section whenever a phase changes. Link the PR, workflow run, test evidence, and deployment evidence. Do not mark a task complete without its relevant evidence.

| Phase | Status | Completion evidence |
|---|---|---|
| Migration preparation | Complete (PR #15 merged) | [PR #15](https://github.com/Double-IQ/SentryIQ/pull/15) |
| Gallery architecture | Complete (PR #11 merged) | [PR #11](https://github.com/Double-IQ/SentryIQ/pull/11) |
| Gallery end-to-end validation | Pending | Test report and supported-device results |
| Client crypto/key foundation | Pending | Design review, test vectors, cross-browser results |
| Zero-knowledge vault/documents | Pending | Migration and no-plaintext/no-key-leak test evidence |
| Signed release pipeline | Pending | Signed artifact and verifier test |
| Integrity Node 1 | Pending | Independent deployment and signed report |
| Integrity Node 2 | Pending | Independent deployment and signed report |
| Origin hardening/incident exercise | Pending | Security test report and exercise record |
| New-origin deployment/cutover | Pending | Acceptance checklist, restore/rollback evidence, approval |

## Related documents and issues

- [Subdomain migration runbook](./sentryiq-subdomain-migration.md)
- [Backblaze B2 Gallery setup](./backblaze-b2-gallery-setup.md)
- [Issue #10 — Zero-knowledge Gallery](https://github.com/Double-IQ/SentryIQ/issues/10)
- [Issue #12 — Full zero-knowledge vault](https://github.com/Double-IQ/SentryIQ/issues/12)
- [Issue #13 — Signed releases and Integrity Nodes](https://github.com/Double-IQ/SentryIQ/issues/13)
- [Issue #14 — Safe subdomain migration](https://github.com/Double-IQ/SentryIQ/issues/14)
