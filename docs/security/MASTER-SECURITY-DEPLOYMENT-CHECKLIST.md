# SentryIQ — Master Security & Deployment Checklist

**Document status:** Active execution tracker  
**Baseline branch:** `main`  
**Repository:** `Double-IQ/SentryIQ`  
**Last updated:** 2026-11-18  
**Execution rule:** Complete one numbered item at a time. Stop for review after each item. Do not begin the next item until its acceptance evidence is recorded.

This document is the single working checklist for the reset security review and subsequent four-node deployment. It is intentionally separate from the broader historical security/migration roadmap. Where older planning documents describe a different sequence, follow this checklist for the current execution.

## How status is recorded

- `[x]` means the item has been completed and its acceptance evidence is recorded below.
- `[ ]` means pending, in progress, blocked, or not yet verified.
- A code change on a branch or an open pull request is **not** a completed fix.
- CI success is not production deployment or runtime verification.
- Do not change a checkbox based on intention, an unverified assumption, or a code review alone.
- For each security finding, record the affected file/component, risk, correction, tests, PR/commit, and any deployment verification.
- Work from the actual `main` branch baseline. Do not mix in BTM-SA or unfinished node prototype work during Phase 1 unless a finding in the existing SentryIQ application directly requires it.

## Current progress

**Phase 1: 1/30 findings/tasks completed.**

- Completed: 1.1 — identified the public installation diagnostic endpoint as an exposure requiring protection.
- In progress, not counted complete: 1.2 — an authentication-protection change is proposed in [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53). It is not merged and runtime tests have not yet been recorded.
- Current active item: **1.2**. Review and test this change before proceeding to 1.3.
- No four-node deployment task is marked complete by this document.

---

# Phase 1 — Examine and secure the existing SentryIQ application

All findings must be verified against `main`. The existing application is the baseline; preserve its working functionality while fixing security defects.

## 1. Installation diagnostics

- [x] **1.1** Identify publicly accessible diagnostic endpoints.
- [ ] **1.2** Protect post-install diagnostic with authentication.
  - Proposed change: [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53), commit `197b0901535459aa6a181b47fde3876c3ce3e1d6`.
  - Status: code submitted for review; not merged; authenticated/unauthenticated/CLI runtime tests not yet evidenced.
- [ ] **1.3** Test authenticated, unauthenticated and CLI access.
- [ ] **1.4** Review and merge the correction after successful testing.

## 2. JavaScript and browser security

- [ ] **2.1** Audit Content Security Policy, especially `unsafe-inline`.
- [ ] **2.2** Identify inline JavaScript dependencies and remove unsafe inline execution where feasible; use nonces or hashes where appropriate.
- [ ] **2.3** Audit XSS sinks, DOM insertion, templates, and output escaping.
- [ ] **2.4** Audit CSRF protections on every state-changing action.
- [ ] **2.5** Verify browser security headers, HTTPS behaviour, and cookie attributes.

## 3. PHP application security

- [ ] **3.1** Audit the security bootstrap and every public application entry point.
- [ ] **3.2** Review password authentication, password recovery, throttling, and 2FA.
- [ ] **3.3** Review WebAuthn/passkey registration, authentication, challenge validation, and origin/RP binding.
- [ ] **3.4** Review session creation, rotation, expiry, fixation protection, and logout/lock behaviour.
- [ ] **3.5** Audit authorization and privilege boundaries for every sensitive operation.
- [ ] **3.6** Review database access, input validation, file uploads, filesystem operations, and error handling.

## 4. Private data and encryption

- [ ] **4.1** Verify private runtime/data directories are outside the public web root.
- [ ] **4.2** Review filesystem ownership and permissions, symlink handling, path traversal, and atomic writes.
- [ ] **4.3** Audit vault encryption, key derivation, key lifecycle, and recovery paths.
- [ ] **4.4** Audit Gallery and document encryption, storage authorization, and signed-URL lifecycle.
- [ ] **4.5** Review backups, restore procedures, secret exposure, and sensitive-data leakage.

## 5. Updates and software integrity

- [ ] **5.1** Verify the updater's configured GitHub repository and intended release source.
- [ ] **5.2** Review release authenticity, signatures, checksums, and trust-root handling.
- [ ] **5.3** Audit archive extraction, path traversal, symlinks, and overwrite protections.
- [ ] **5.4** Review update rollback, partial failure handling, and recovery.
- [ ] **5.5** Test the update process safely in a non-production environment.

## 6. Dependencies and operational security

- [ ] **6.1** Audit Composer and JavaScript dependencies for known vulnerabilities and unnecessary packages.
- [ ] **6.2** Review PHP configuration, web-server configuration, TLS, and least-privilege runtime settings.
- [ ] **6.3** Review logging, exception handling, diagnostic output, and information disclosure.
- [ ] **6.4** Run the complete diagnostic and automated test suites after fixes.
- [ ] **6.5** Complete a final security review and document unresolved risks and accepted limitations.

### Phase 1 acceptance gate

Phase 1 is complete only when every item above has evidence, all high-risk findings are fixed or explicitly accepted with documented compensating controls, the relevant tests pass, and the reviewed changes are merged. A merge alone does not establish production deployment.

---

# Phase 2 — Introduce and connect the four security nodes

**Do not start Phase 2 until Phase 1 passes its acceptance gate.** Each node must be provisioned, connected, exercised, and verified individually. A code prototype or hosting assignment is not an operational node.

## Node assignments

| Node | Intended infrastructure | Current known position | Required outcome |
|---|---|---|---|
| Node A | Independent security host | Provider/host assignment not confirmed in this tracker | Confirm host and independent administrative/failure boundary, then deploy and verify |
| Node B | Val Town | Hosting assignment confirmed; live app/runtime not verified | Deploy/configure and verify |
| Node C | HelioHost | Intended host; live provisioning/runtime not verified | Deploy/configure and verify |
| Node 4 | BTM-SA, on the same host as SentryIQ | Shared host; not an independent infrastructure failure domain | Deploy as a separately identified and isolated logical service |

## Node-by-node deployment

- [ ] **2.1** Confirm and document each node's responsibility, trust boundary, host, owner, and failure-domain limitations.
- [ ] **2.2** Confirm Node A's actual provider and independent administrative boundary.
- [ ] **2.3** Inspect and provision Node A; configure private secrets, pinned trust roots, unique credentials, schedule, private state/baseline, and direct owner alerts.
- [ ] **2.4** Inspect and provision Node B on Val Town; configure private secrets, pinned trust roots, unique credentials, independent schedule, private state/baseline, and direct owner alerts.
- [ ] **2.5** Inspect and provision Node C on HelioHost; confirm supported runtime and configure its verifier, keys, private evidence storage, schedule, and direct owner alerts.
- [ ] **2.6** Configure Node 4 on the BTM-SA/SentryIQ host with a separate logical identity, private storage, A/B public keys, unique tokens, replay-safe state, and tested alert sender.
- [ ] **2.7** Establish authenticated node-to-origin communication and verify TLS/origin restrictions.
- [ ] **2.8** Implement and verify signed integrity reports and pinned trust-root validation.
- [ ] **2.9** Implement cross-node comparison, stale/missed-check detection, disagreement alerts, and independent alert delivery.
- [ ] **2.10** Test each node's normal operation, restart, missed schedule, unavailable target, invalid signature, replay, and recovery.
- [ ] **2.11** Verify the complete four-node architecture and document common-mode risks.

### Phase 2 acceptance gate

Each node must produce a fresh report that can be independently verified. Credentials, state, schedules, and alert paths must be configured and tested. Node A and Node B must be genuinely independent; Node 4's shared-host limitation must remain explicit. No node is complete merely because its code exists or its host account exists.

---

# Phase 3 — Final integration and production verification

- [ ] **3.1** Verify all accepted security corrections are present in the production release.
- [ ] **3.2** Verify all four nodes are deployed, connected, scheduled, and reporting.
- [ ] **3.3** Test realistic attack and failure scenarios, including compromised or altered browser assets.
- [ ] **3.4** Confirm alerts reach the intended owner-controlled destination without relying on the monitored origin.
- [ ] **3.5** Document backup, restore, recovery, incident response, and maintenance procedures.
- [ ] **3.6** Produce the final security and deployment report with evidence and residual risks.

## Execution log

Add one entry after each item is reviewed. Keep entries factual and link to commits, pull requests, test runs, or deployment evidence.

| Date | Checklist item | Change / evidence | Result | Reviewed |
|---|---|---|---|---|
| 2026-11-18 | 1.1 | Identified `diagnostics/post_install_diagnostic.php` as a publicly accessible diagnostic requiring protection | Finding recorded | Yes |
| 2026-11-18 | 1.2 | [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53), commit `197b090` | Proposed code change; tests and merge pending | Pending |

## Working rules

1. Work on exactly one checklist item at a time.
2. Before changing code, inspect the relevant implementation on `main` and identify the concrete weakness.
3. Make the smallest safe correction that addresses that weakness.
4. Run focused tests, then relevant regression tests.
5. Record the exact commit/PR and test evidence in this document.
6. Stop and present the result for review. Do not silently continue to the next item.
7. Never claim a change is merged, deployed, or operational unless that state has been directly verified.
8. Do not modify production data, credentials, DNS, or hosting configuration without explicit approval for that specific operation.
9. Do not revive, merge, or deploy unfinished node prototypes as a substitute for completing this checklist.
10. This document is the execution source of truth. Update it whenever work is completed, blocked, or re-scoped.
