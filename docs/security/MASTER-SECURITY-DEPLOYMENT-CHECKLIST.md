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

**Phase 1: 7/30 findings/tasks completed.**

- Completed: 1.1 — identified the public installation diagnostic endpoint as an exposure requiring protection.
- Completed: 1.2 — authentication protection merged in [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53); production deployment/runtime verification remains outstanding and is not claimed.
- Completed: 1.3 — all four focused access-control scenarios pass in CI.
- Completed: 1.4 — PR #53 reviewed, marked ready, and squash-merged into `main` as `2ca8accf882e52f7bbeebcf9f49e81b1891a0910`.
- Completed: 2.1 — audited CSP emission points on `main`; both the central and Gallery policies permit inline scripts and inline styles. See findings below.
- Completed: 2.2 — inventoried inline script blocks, event-handler attributes, and JavaScript dependencies on `main`; migration plan recorded below.
- Completed: 2.3 — reviewed server-rendered output, record-card serialization, diagnostic JSON embedding, and DOM insertion sinks; findings and hardening actions recorded below.
- Next item, pending user review: **2.4** — audit CSRF protections on every state-changing action.
- No four-node deployment task is marked complete by this document.

---

# Phase 1 — Examine and secure the existing SentryIQ application

All findings must be verified against `main`. The existing application is the baseline; preserve its working functionality while fixing security defects.

## 1. Installation diagnostics

- [x] **1.1** Identify publicly accessible diagnostic endpoints.
- [x] **1.2** Protect post-install diagnostic with authentication.
  - Correction: [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53), implementation commit `197b0901535459aa6a181b47fde3876c3ce3e1d6`.
  - Merged into `main` by squash commit `2ca8accf882e52f7bbeebcf9f49e81b1891a0910` on 2026-11-18. Production deployment/runtime verification is not yet performed.
- [x] **1.3** Test authenticated, unauthenticated and CLI access.
  - Added `tests/post_install_diagnostic_access.test.php`, an isolated PHP built-in-server integration test covering unauthenticated installed web access (302, no diagnostic body), authenticated web access (200 JSON), uninstalled web access (404, no diagnostic body), and CLI access (successful JSON).
  - CI: [PHP Syntax Check run](https://github.com/Double-IQ/SentryIQ/actions/runs/44291043980) passed, including the focused access-control test; [Gallery Security Checks run](https://github.com/Double-IQ/SentryIQ/actions/runs/44291044080) also passed.
- [x] **1.4** Review and merge the correction after successful testing.
  - Reviewed PR #53, verified the latest head `3759d5e3e405c2d700dc0a4f38c95cc27e35fb77`, confirmed both CI checks passed, marked the PR ready for review, and squash-merged it. [Merge commit](https://github.com/Double-IQ/SentryIQ/commit/2ca8accf882e52f7bbeebcf9f49e81b1891a0910).

## 2. JavaScript and browser security

- [x] **2.1** Audit Content Security Policy, especially `unsafe-inline`.
  - Audited `app/Security/SecurityBootstrap.php`, `app/Gallery/SecurePage.php`, `.htaccess`, and `.user.ini` on `main`.
  - Central policy in `sentryiq_security_bootstrap()` includes `script-src 'self' 'unsafe-inline'` and `style-src 'self' 'unsafe-inline'`. It also sets `default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`, `form-action 'self'`, and `img-src 'self' data:`.
  - `app/Gallery/SecurePage.php` emits a second CSP after the central bootstrap. It repeats both `unsafe-inline` allowances and adds `img-src ... blob:` plus `connect-src 'self'` and the configured Backblaze B2 HTTPS host when B2 is configured. Multiple CSP headers are enforced cumulatively by browsers; the Gallery header does not relax/replace the central policy.
  - `.htaccess` and `.user.ini` contain no additional CSP header configuration.
  - Finding: inline JavaScript is currently permitted across normal bootstrap-protected pages; this weakens CSP as a mitigation for script injection. Inline CSS is also permitted. Removing `unsafe-inline` immediately would risk breaking existing pages; item 2.2 must first inventory inline script blocks and event-handler attributes and design the migration (external scripts/nonces and event-listener bindings). No policy change was made in this audit item.
  - No production headers or files were changed. This is an audit result, not a remediation.
- [x] **2.2** Identify inline JavaScript dependencies and remove unsafe inline execution where feasible; use nonces or hashes where appropriate.
  - Audited rendered PHP templates and browser assets on `main`, including dashboard partials, authentication pages, the document page, Gallery pages, and diagnostic pages.
  - Inline script blocks found in: `index.php` (2 blocks: dashboard globals/helpers and page initialization/CSRF/form wiring); `app/Vault/DashboardList.php` (1: folder/category UI helpers and options-panel setup); `app/Vault/DashboardActions.php` (1: record edit/copy/passkey UI handlers); `documents.php` (1: mobile menu and file-selection label); `welcome.php` (1: welcome transition/redirect); `app/Auth/PasskeyLogin.php` (1: WebAuthn login ceremony); `app/Auth/PasskeySetup.php` (1: WebAuthn registration ceremony); `gallery_b2_diagnostic.php` (1: authenticated B2 browser diagnostic); and `diagnostics/self_test.php` (1: browser-side diagnostics). Total: 10 inline script blocks across 9 PHP files.
  - Inline event-handler attributes found in 5 templates: `app/Vault/DashboardList.php` (`onclick`, `onkeydown`, image `onerror`); `app/Vault/DashboardActions.php` (`onclick`, form `onsubmit` confirmation); `documents.php` (navigation `onclick`, delete `onsubmit` confirmation); `app/Gallery/SecurePage.php` (navigation `onclick`); and `gallery_b2_settings.php` (navigation `onclick`, disconnect `onsubmit` confirmation).
  - JavaScript coupling: `assets/js/records_view.js` reads a card's `onclick` attribute; `assets/js/vault_folders.js` selects the create-folder button using `[onclick="showCreateFolderForm()"]`. Replace these with stable IDs or `data-*` selectors as part of migration. Dashboard record cards currently pass serialized record data through inline handlers; preserve data safely using correctly encoded data attributes or a non-executable JSON data block, never executable markup.
  - Existing same-origin external assets cover Gallery workflows (`gallery_crypto.js`, `gallery_secure.js`, `gallery_storage.js`, `gallery_secure_ui.js`) and vault/folder features (`vault_folders.js`, `records_view.js`, `safari.js`). No `eval()` or `new Function()` dependency was identified in the inspected browser assets. Include `diagnostics/self_test.php` in CSP migration/testing despite it not being a normal user workflow.
  - Migration/test order: (1) move inline script blocks into dedicated same-origin external files; (2) replace inline event attributes with `addEventListener`; (3) replace attribute-string selectors with IDs/data attributes; (4) preserve server-generated values through safely encoded data attributes or non-executable JSON; (5) add regression coverage for password/2FA login, passkey login/setup, dashboard navigation and record actions, folder/category controls, document upload/delete confirmations, Gallery workflows, B2 diagnostics, and self-test; (6) only then remove `unsafe-inline` from `script-src` and verify effective response headers. Inline styles are a separate `style-src` migration and are outside this item.
  - Inventory and migration plan only: no application code, CSP, or production configuration was changed.
- [x] **2.3** Audit XSS sinks, DOM insertion, templates, and output escaping.
  - Reviewed on `main`: `index.php`, `app/Vault/DashboardList.php`, `app/Vault/DashboardActions.php`, `documents.php`, `welcome.php`, `app/Auth/PasskeyLogin.php`, `app/Auth/PasskeySetup.php`, `gallery_b2_diagnostic.php`, `diagnostics/self_test.php`, `app/Gallery/SecurePage.php`, and the related Vault/Gallery browser assets (`records_view.js`, `vault_folders.js`, `gallery_secure_ui.js`, `gallery_secure.js`, `gallery_storage.js`, `gallery_crypto.js`).
  - Vault record-card output: record fields are serialized with `json_encode(..., JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)` and then HTML-attribute encoded before use in the inline handler. This is context-safe against HTML/script breakout in the inspected path. Visible labels, usernames, category/folder values, form values, and passkey labels/IDs are HTML-escaped; query-derived category/folder values are constrained against the stored category/folder lists before rendering. The record detail UI uses `textContent` and validates destination links as HTTPS before assigning `href`.
  - Documents page: document names and IDs are HTML-escaped or constrained to the expected hexadecimal identifier format; the icon helper returns a fixed emoji allowlist; status messages are selected from fixed strings. No unescaped document metadata sink was identified in the inspected template.
  - Passkey and Gallery UI: inspected message/metadata insertion uses `textContent`, DOM element creation, and property assignment rather than parsing untrusted strings as HTML. Gallery filenames/albums are displayed through `textContent`; thumbnail/preview URLs are generated as object URLs from decrypted image bytes.
  - DOM HTML sinks found: `DashboardList.php` builds the System Tools panel with `innerHTML`, but the inserted markup is a fixed, developer-authored string with no user/config/request data; `vault_folders.js` assigns fixed option markup to `select.innerHTML`; `diagnostics/self_test.php` uses `innerHTML` for table rows and summary markup, with dynamic fields passed through its `esc()` HTML-escaping helper. No `eval`, `new Function`, or `document.write` sink was identified in the inspected browser assets.
  - **Hardening finding (not confirmed exploitable XSS):** `diagnostics/self_test.php` embeds `$browserTests` and `$results` into executable `<script>` blocks using `json_encode()` without `JSON_HEX_TAG` (and embeds `$csrf`/build metadata without a uniform script-data encoding helper). `$results` can include environment/configuration-derived strings, including the request Host value and configuration exception details. JSON string encoding alone does not neutralize a literal `</script>` for the HTML parser. This is a context-encoding weakness; exploitability depends on an attacker being able to influence one of those diagnostic values and induce an authenticated diagnostic request. Correct it by using a single script-context encoder with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR` for every PHP-to-JavaScript value, or move data into non-executable JSON with equivalent safe encoding. Add a regression test using a `</script><script>` payload in a controlled diagnostic value.
  - Context note: `htmlspecialchars()` defaults are used in a few older output expressions without explicit flags/charset, while newer adjacent expressions specify `ENT_QUOTES, 'UTF-8'`. PHP 8.3's defaults include quote escaping, so no concrete bypass was demonstrated, but standardize all HTML text/attribute output to explicit `ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'` during remediation.
  - No application code or production configuration was changed during this audit. This item records the audit and the exact hardening target; the actual remediation is tracked as a follow-up implementation before CSP tightening. No confirmed exploitable XSS was established in the inspected paths.
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
| 2026-11-18 | 1.2 | [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53), implementation commit `197b090`, merge commit `2ca8acc` | Authentication gate merged into `main`; not deployed to production | Yes |
| 2026-11-18 | 1.3 | `tests/post_install_diagnostic_access.test.php`; CI runs [44291043980](https://github.com/Double-IQ/SentryIQ/actions/runs/44291043980) and [44291044080](https://github.com/Double-IQ/SentryIQ/actions/runs/44291044080) on PR head `3759d5e` | Four access scenarios pass in CI | Yes |
| 2026-11-18 | 1.4 | [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53), [merge commit `2ca8acc`](https://github.com/Double-IQ/SentryIQ/commit/2ca8accf882e52f7bbeebcf9f49e81b1891a0910) | Reviewed and squash-merged into `main`; production deployment not performed | Yes |
| 2026-11-18 | 2.1 | `app/Security/SecurityBootstrap.php`, `app/Gallery/SecurePage.php`, `.htaccess`, `.user.ini` on `main` | Found two CSP emission points; both permit `unsafe-inline` for scripts and styles. Recorded migration dependencies; no policy changed | Yes |
| 2026-11-18 | 2.2 | Inline script/handler inventory across PHP templates and JS assets on `main` | Recorded 10 inline script blocks in 9 PHP files, inline event attributes in 5 templates, JavaScript selector coupling, and staged migration/test plan; no code changed | Yes |
| 2026-11-18 | 2.3 | Reviewed Vault, Documents, Passkey, Gallery, and diagnostic templates/assets on `main` | No confirmed exploitable XSS in inspected paths; recorded a script-context JSON-encoding hardening finding in `diagnostics/self_test.php`, verified safe fixed-markup/escaped DOM sinks, and documented remediation/test requirements; no code changed | Yes |

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
