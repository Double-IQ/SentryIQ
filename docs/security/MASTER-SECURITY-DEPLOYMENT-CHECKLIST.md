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

**Phase 1: 10/30 findings/tasks completed.**

- Completed: 1.1 — identified the public installation diagnostic endpoint as an exposure requiring protection.
- Completed: 1.2 — authentication protection merged in [PR #53](https://github.com/Double-IQ/SentryIQ/pull/53); production deployment/runtime verification remains outstanding and is not claimed.
- Completed: 1.3 — all four focused access-control scenarios pass in CI.
- Completed: 1.4 — PR #53 reviewed, marked ready, and squash-merged into `main` as `2ca8accf882e52f7bbeebcf9f49e81b1891a0910`.
- Completed: 2.1 — audited CSP emission points on `main`; both the central and Gallery policies permit inline scripts and inline styles. See findings below.
- Completed: 2.2 — inventoried inline script blocks, event-handler attributes, and JavaScript dependencies on `main`; migration plan recorded below.
- Completed: 2.3 — reviewed server-rendered output, record-card serialization, diagnostic JSON embedding, and DOM insertion sinks; findings and hardening actions recorded below.
- Completed: 2.4 — audited CSRF enforcement across authentication, vault, documents, Gallery settings/diagnostics, passkeys, and first-run setup.
- Completed: 2.5 — reviewed central response headers, HTTPS enforcement, session cookie parameters, logout cookie invalidation, and page-specific header overrides.
- Completed: 3.1 — audited the central security bootstrap, root application routes, rewritten application handlers, diagnostics, and public utility endpoints on `main`; recorded an unauthenticated diagnostic endpoint exposure and a pre-install diagnostic information-disclosure condition.
- Next audit item: **3.2** — review password authentication, password recovery, throttling, and 2FA.
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
- [x] **2.4** Audit CSRF protections on every state-changing action.
  - Audited `app/Security/SecurityBootstrap.php`, `index.php`, `app/Auth/AuthFlow.php`, `app/Auth/PasskeyAuth.php`, `app/Security/FirstRun.php`, Vault action handlers (`app/Vault/Actions.php`, `CategoryActions.php`, `RecordActions.php`), document handlers (`app/Documents/Upload.php`, `Delete.php`), Gallery settings/diagnostic handlers (`app/Gallery/Settings.php`, `gallery_b2_settings.php`, `gallery_b2_diagnostic.php`), and the retired Gallery server endpoints.
  - Central CSRF implementation: `sentryiq_csrf_token()` creates a 256-bit random hex token in the session. `sentryiq_require_csrf()` accepts POST only, supports form field or `X-CSRF-Token`, rejects missing/mismatched tokens with 403, and uses `hash_equals()`. The session cookie is configured `SameSite=Strict`, `HttpOnly`, and `Secure`; session IDs use strict mode. Authentication success regenerates the session ID and rotates the CSRF token.
  - Covered state-changing operations: password/recovery login steps and first-run completion call `sentryiq_require_csrf()`; vault add/edit/delete/category/settings/folder handlers call it; document upload/delete call it after authentication; Gallery settings save/disconnect call it and additionally require fresh authentication; Gallery B2 diagnostic `prepare` validates the session token manually before issuing short-lived B2 operation URLs; passkey register/delete validate the JSON request token manually with `hash_equals()` and require authentication. Vault lock POST validates CSRF in both the bootstrap lock hook and the index entry point. Legacy server-side Gallery upload/delete/album endpoints return 410 and do not mutate state.
  - Forms on the index page receive a token from the meta tag via the page initializer; explicit forms on first-run, Gallery, and B2 settings pages render a hidden token. Passkey browser requests carry the token in JSON. The B2 diagnostic fetch sends the token in JSON. No state-changing GET operation was identified in the inspected flows; passkey GET options endpoints only create short-lived session challenges and do not mutate account or stored application data.
  - Findings/limitations: (1) CSRF enforcement is not centralized automatically at the HTTP router; each handler must remember to invoke it. Current audited mutation handlers do so, but future endpoints need regression coverage. (2) Passkey register/delete and B2 diagnostic duplicate the token comparison instead of using one shared JSON-request verifier, creating drift risk. (3) The index page's automatic token injection depends on its JavaScript initializer; any newly introduced POST form on that page must include a token explicitly or be covered by the initializer. (4) The login passkey assertion POST does not use a CSRF token, but it is an unauthenticated login ceremony bound to a session challenge, WebAuthn origin/RP ID, and authenticator signature; no authenticated state-changing action is exposed through that operation.
  - No missing CSRF check was confirmed in the reviewed state-changing handlers. No application code or production configuration was changed; this is an audit result, not a remediation.
- [x] **2.5** Verify browser security headers, HTTPS behaviour, and cookie attributes.
  - Reviewed `app/Security/SecurityBootstrap.php`, `app/Gallery/SecurePage.php`, `gallery_b2_diagnostic.php`, `gallery_b2_settings.php`, and the root `.htaccess` / `.user.ini` files on `main`.
  - Central bootstrap emits `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, `Pragma: no-cache`, `Expires: 0`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`, and a restrictive baseline CSP (`default-src 'self'`, `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`, `form-action 'self'`; `img-src 'self' data:`). CSP still allows `unsafe-inline` for script/style, already recorded under 2.1/2.2.
  - HTTPS enforcement: non-CLI requests are rejected unless `$_SERVER['HTTPS'] === 'on'` or `SERVER_PORT === '443'`. This prevents ordinary direct HTTP requests, but relies on server-provided HTTPS/port values; reverse-proxy deployments must preserve a trustworthy HTTPS indicator. Do not trust arbitrary forwarded headers without a configured trusted-proxy boundary.
  - Session cookie: lifetime 0, path `/`, Secure, HttpOnly, SameSite=Strict; strict session mode and cookie-only sessions enabled. No explicit cookie domain is set, so the cookie remains host-only. Logout/lock expires the cookie using the active path/domain/Secure/HttpOnly attributes before destroying the session.
  - **Confirmed hardening gap:** no `Strict-Transport-Security` (HSTS) header is emitted by the central bootstrap or the inspected page-specific handlers/config files. Once the production hostname and all relevant subdomains are confirmed HTTPS-only, add HSTS at the trusted TLS termination/web-server layer (or central app layer if appropriate), initially with a conservative max-age; do not enable `includeSubDomains` or preload until every covered hostname is verified HTTPS-capable.
  - **Header consistency gap:** `gallery_b2_diagnostic.php` and `gallery_b2_settings.php` emit some defensive headers again, but the Gallery settings page does not independently emit `X-Frame-Options` / `Permissions-Policy` / CSP; it currently inherits them from bootstrap. `app/Gallery/SecurePage.php` and `gallery_b2_diagnostic.php` emit a second CSP in addition to the central CSP. Browsers enforce multiple CSP policies cumulatively, which can cause functional restrictions (for example, Gallery's `blob:` image allowance is not present in the central policy); reconcile to one centrally generated, route-aware policy during CSP remediation. The diagnostic/settings pages inherit baseline clickjacking protections from bootstrap when the bootstrap reaches its normal header-emission stage.
  - **Ordering note:** the bootstrap's lock-vault POST handling and several redirect branches occur before its common security-header block. Those early redirect responses may therefore omit the baseline response headers; move common header emission earlier in the bootstrap as part of remediation, while preserving the HTTPS rejection and session initialization order.
  - No production headers, TLS configuration, or application code were changed. No live response/header test or production proxy configuration was available in this repository-only audit; actual deployed TLS/HSTS behaviour remains unverified.

## 3. PHP application security

- [x] **3.1** Audit the security bootstrap and every public application entry point.
  - Reviewed `app/Security/SecurityBootstrap.php`, the root `.htaccess` rewrite map, root PHP routes (`index.php`, `documents.php`, `storage.php`, `update.php`, `update_apply.php`, `update_check.php`, `welcome.php`, `first_run.php`, Gallery/passkey wrappers, and public icon/OG image handlers), the rewritten `app/` handlers, and the `diagnostics/` endpoints on `main`.
  - Most application routes inspected load the central bootstrap before doing work; sensitive pages/actions additionally require an authenticated session, fresh authentication, and/or CSRF. The `first_run.php` wrapper delegates to `app/Security/FirstRun.php`, which loads the bootstrap and rejects access once the installation pointer config exists. The retired Gallery mutation handlers return HTTP 410. Public icon/OG image endpoints serve fixed image assets and do not expose private application state.
  - **Confirmed unauthenticated diagnostic exposure:** `diagnostics/post_install_write_diagnostic.php` does not load `SecurityBootstrap`, check authentication, restrict the HTTP method, or apply a one-time capability. A direct web request performs a write probe in the public web root (then attempts to delete it), returns absolute web-root/parent paths, directory permissions and writability, PHP version/SAPI, configuration-file state, and probe errors; it also appends diagnostic data to `private_data/install_postmortem.log` when that directory exists. The root `.htaccess` contains no rule denying this endpoint. This creates unauthenticated information disclosure and an unauthenticated filesystem-write/logging side effect that can be repeatedly triggered. **Risk: Medium (potentially higher depending on deployment permissions and log handling).** Remediation: remove the endpoint from the deployed web surface or make it CLI-only; if a web workflow is genuinely required, gate it behind a short-lived, one-time installer capability and strict method/rate controls, minimize returned details, and test that unauthenticated requests cannot create probes or append logs.
  - **Pre-install diagnostic exposure:** `diagnostics/vault_runtime_diagnostic.php` loads the bootstrap and returns 404 once installation is complete, but while the first-run marker exists and the config pointer is absent it is reachable without an authenticated account. It reports the inferred private-data path, directory/file permissions, file size/readability, and the private config's data-directory value, and appends a diagnostic log entry. This may be intentional for installation troubleshooting, but it exposes filesystem layout during the pre-install window. Record as a lower-priority information-disclosure hardening item; prefer CLI-only access or an explicit one-time setup capability if browser access is not essential.
  - `diagnostics/post_install_diagnostic.php` was verified to include the central bootstrap, return 404 when installed config is missing for web requests, and require an authenticated session for installed web access; its CLI path remains available. `diagnostics/self_test.php` requires an unlocked vault when installed. `diagnostics/vault_save_diagnostic.php` requires authentication. `diagnostics/copy-code.php` uses a 64-hex one-time bearer token and atomically renames the token file before displaying the code; its bearer-token lifecycle remains part of the authentication/2FA audit in 3.2.
  - Bootstrap review reconfirmed that HTTPS rejection, lock handling, and several redirect/error paths can exit before the common response-header block; this is already recorded under 2.5 for remediation and is not counted as a new finding here. The bootstrap is loaded by the principal root application pages and rewritten sensitive handlers reviewed.
  - Scope limitation: this was a source-level repository audit. No production web-server request, filesystem permission, or deployed `.htaccess` behaviour was available to verify. No code or production configuration was changed in this item.
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
| 2026-11-18 | 2.4 | Audited central CSRF helper and authentication, Vault, Documents, Gallery, passkey, and first-run mutation handlers on `main` | No missing CSRF check confirmed in reviewed state-changing handlers; recorded decentralized enforcement, duplicated JSON token checks, and JS-dependent index form injection as maintenance risks; no code changed | Yes |
| 2026-11-18 | 2.5 | Reviewed central security bootstrap, Gallery page-specific headers, HTTPS gate, session cookie setup/invalidation, `.htaccess`, and `.user.ini` on `main` | Recorded missing HSTS, CSP duplication/reconciliation, early-redirect header ordering, and trusted-proxy verification requirements; no code or production TLS configuration changed; live headers remain unverified | Yes |
| 2026-11-18 | 3.1 | Audited root routes, `.htaccess` rewrites, central bootstrap, app handlers, and diagnostic endpoints on `main` | Found unauthenticated `diagnostics/post_install_write_diagnostic.php` with filesystem probe/logging and path/permission disclosure; recorded pre-install-only disclosure in `vault_runtime_diagnostic.php`; no code changed | Yes |

## Working rules

1. Complete Phase 1 audit items 3.1 through 6.5 sequentially, recording each item and its evidence before moving on; do not pause for user review after every audit item.
2. After 6.5, present the consolidated findings, test results, limitations, and prioritized remediation plan; wait for user review before starting remediation.
3. Before changing code, inspect the relevant implementation on `main` and identify the concrete weakness.
4. Make the smallest safe correction that addresses that weakness.
5. Run focused tests, then relevant regression tests.
6. Record the exact commit/PR and test evidence in this document.
7. Never claim a change is merged, deployed, or operational unless that state has been directly verified.
8. Do not modify production data, credentials, DNS, or hosting configuration without explicit approval for that specific operation.
9. Do not revive, merge, or deploy unfinished node prototypes as a substitute for completing this checklist.
10. This document is the execution source of truth. Update it whenever work is completed, blocked, or re-scoped.
