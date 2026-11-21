# SentryIQ Owner Acceptance Handover

**Status:** Prepared for owner execution — no owner/production controls have been changed by this document.  
**Date:** 2026-11-21  
**Repository:** `Double-IQ/SentryIQ`

This handover separates repository remediation from operational acceptance. It is intended to be completed by a repository administrator and the administrator responsible for the production host and Backblaze B2 account. Do not paste credentials, private keys, recovery material, access tokens, or decrypted data into this document, GitHub issues, or pull-request comments.

## 0. Preconditions and change boundary

- [x] Consolidated security remediation [PR #56](https://github.com/Double-IQ/SentryIQ/pull/56) merged on 2026-11-19 as `b413b1ebf1204972e84a0994c19f05079c9efcde`.
- [x] Master checklist and this handover [PR #54](https://github.com/Double-IQ/SentryIQ/pull/54) merged on 2026-11-19 as `fd4ff7a6236e60df6fb84e178693ed91bc1f695e`.
- [x] Post-merge checks on `main` commit `fd4ff7a6236e60df6fb84e178693ed91bc1f695e`: PHP Syntax Check and Gallery Security Checks passed (runs `44466000329` and `44466000270`). Release Attestation Verification has not yet been confirmed on this exact merge commit.
- [ ] Confirm a maintenance window and rollback contact before any production change.
- [ ] Confirm the production administrator has a current, verified recovery path before changing the application or host.
- [ ] Record approval for each production change in the normal change-management system.

**Merge stage is complete. Do not deploy, publish a release, change DNS, rotate credentials, or alter production hosting solely because this handover exists.** The merges do not constitute production acceptance or deployment.

## 1. GitHub repository controls — repository administrator

### 1.1 Protect `main`

- [x] Enable and verify the active `SentryIQ - Protect main` repository ruleset targeting `main` (ruleset ID `27621562`; see `REPOSITORY-SECURITY-SETTINGS.md`).
- [x] Require pull requests before merging.
- [ ] Configure and verify at least one required approving review. The active ruleset read-back explicitly reports `required_approving_review_count: 0`; stale approvals are dismissed on new commits.
- [ ] Decide whether Code Owner review is required and enable it if appropriate. The active ruleset explicitly reports `require_code_owner_review: false`.
- [x] Require the observed job checks `php-lint` and `gallery-security` (active ruleset read-back). `release-manifest` and `Verify release attestation and dual-node report contract` are not currently required by the ruleset; assess adding them only after verifying stable successful runs and dependencies.
- [x] Require branches to be up to date with required checks.
- [x] Block force pushes and branch deletion.
- [x] No bypass actors are configured; API read-back reports the connected user cannot bypass.

**Evidence:** active ruleset names/IDs, target refs, required checks, up-to-date requirement, force-push/deletion restrictions, and bypass state are recorded in `REPOSITORY-SECURITY-SETTINGS.md` from the 2026-11-19 API read-back. The active ruleset currently requires **zero** approving reviews and does **not** require Code Owner review; stale approvals are dismissed on new commits. These are explicit configuration gaps, not unknowns. Required review-thread resolution is enabled.

### 1.2 Protect release tags

- [x] Create and verify active `SentryIQ - Protect release tags` ruleset targeting `v*` (ruleset ID `27621577`).
- [x] Prevent updates and deletion of published release tags (active ruleset read-back).
- [x] Read-only ruleset inspection completed; no test tag was created.

**Evidence to record:** ruleset name/ID, tag pattern, enforcement status, and date verified.

### 1.3 Platform security settings

- [x] Owner-confirmed enabled (2026-11-19); not independently API-verified.
- [x] Owner-confirmed enabled (2026-11-19); not independently API-verified.
- [x] Owner-confirmed enabled (2026-11-19); not independently API-verified.
- [x] Owner-confirmed enabled (2026-11-19); not independently API-verified.
- [ ] Review repository write/admin collaborators and remove stale access through the normal access-review process.
- [ ] Confirm Actions' default token permissions are read-only and review any workflow-specific write permissions.

**Evidence to record:** enabled/disabled/not-available status for each control, date checked, and administrator. Do not record secret values or personal access tokens.

## 2. Backup and restore — production/storage administrator

Use the companion [Backup and Restore Runbook](backup-restore-runbook.md). It remains a procedure template until the steps below have actually been completed.

- [x] Select MEGA as the off-host destination (owner decision, 2026-11-19); account-reported capacity is 20 GB and still needs live quota/transfer verification. Selection does not mean configured or accepted.
- [ ] Approve backup encryption and keep the encryption key separate from the archive, with named-administrator custody.
- [ ] Approve recovery-point and recovery-time objectives and retention; do not assume unapproved retention periods.
- [ ] Configure a scheduled, monitored backup covering the exact deployed application release/provenance, sensitive root configuration, the complete protected runtime data directory, and the matching encrypted B2 Gallery objects.
- [ ] Document and explicitly accept MEGA's account-level deletion risk: unlike independently administered object-lock storage, a compromised MEGAcmd account session may delete retained backups. Use unique dated generations and a tested retention process; do not claim immutable retention.
- [ ] Verify archive integrity after transfer.
- [ ] Perform a restore to an isolated recovery host; do not overwrite production for the first exercise.
- [ ] Verify the restored private path is outside the document root and permissions are restrictive.
- [ ] Verify an authorised Vault recovery/decryption check and a Gallery object retrieval/decryption check without logging secrets or plaintext.
- [ ] Record restore duration, recovery point/data-loss window, missing dependencies, and residual limitations.

**Evidence to record:** MEGA account quota/transfer capacity (not credentials), MEGAcmd version/session and persistent-server support, schedule, retention/deletion-risk acceptance, encryption/key-custody reference, archive checksum, source release SHA, backup result, restore date/result, and recovery measurements.

## 3. Production host acceptance — hosting administrator

Complete only against the actual production host, with a maintenance/change record. Do not infer these properties from CI or a local Apache fixture.

- [ ] Verify Apache is version 2.4.8 or newer; the hardened rewrite flow uses the `[END]` flag.
- [ ] Verify PHP web-SAPI version and effective settings, not only CLI PHP settings.
- [ ] Verify PHP errors are not displayed to visitors and are logged to a protected server-side destination.
- [ ] Verify session cookie Secure/HttpOnly/SameSite settings and strict session handling under the actual HTTPS proxy topology.
- [ ] Verify TLS certificate chain, hostname coverage, renewal, HTTPS redirect behavior, and HSTS policy. Do not enable HSTS until every service on the affected hostname/subdomain scope is confirmed HTTPS-ready.
- [ ] Verify reverse-proxy headers and HTTPS detection cannot be spoofed by untrusted clients.
- [ ] Verify web-root and private-data ownership, group membership, ACLs, symlink boundaries, and write permissions. The web process must not have unnecessary write access to application source.
- [ ] Verify direct and encoded HTTP requests cannot retrieve private runtime/configuration/source files.
- [ ] Verify access and error logs do not retain sensitive query parameters or bearer tokens.
- [ ] Verify the updater's administrator-controlled `SENTRYIQ_GH_BINARY` points to a supported absolute GitHub CLI executable and that its execution identity/permissions are constrained.
- [ ] Run the installed authenticated self-diagnostic and application smoke tests after an approved deployment, recording the exact release SHA.

**Evidence to record:** host/service versions, effective non-secret configuration outcomes, TLS test result, filesystem ownership/mode summary, HTTP test results, log-redaction result, updater binary version/path validation (path may be redacted), and date.

## 4. Backblaze B2 acceptance — storage administrator

- [ ] Verify the production bucket is private and public access is not unintentionally enabled.
- [ ] Verify CORS allows only the required application origins and methods.
- [ ] Verify application keys are least-privilege and scoped to the required bucket/prefix and operations.
- [ ] Verify key rotation/revocation procedure and administrator custody.
- [ ] Verify object versioning/lifecycle/retention settings are compatible with backup and recovery requirements.
- [ ] Verify signed request behavior and provider-side object-size checks against the actual configured account using a controlled test object.
- [ ] Verify the backup/restore exercise includes the matching encrypted Gallery objects.

**Evidence to record:** bucket privacy, CORS policy review result, key scope (never key material), version/lifecycle policy, controlled object test result, and date.

## 5. Release and updater readiness

- [x] [PR #63](https://github.com/Double-IQ/SentryIQ/pull/63) merged as `894f05ac1f4063399ea17df23bc79ea32327bbbf`; it prevents overwriting existing release assets, rejects prerelease tags from the stable release workflow, and requires the existing tag. Post-merge PHP Syntax Check ([44467440693](https://github.com/Double-IQ/SentryIQ/actions/runs/44467440693)), Gallery Security Checks ([44467440690](https://github.com/Double-IQ/SentryIQ/actions/runs/44467440690)), and Release Manifest Tests ([44467440706](https://github.com/Double-IQ/SentryIQ/actions/runs/44467440706)) all passed.
- [x] [PR #65](https://github.com/Double-IQ/SentryIQ/pull/65) merged as `a8ed98977514fb99cb7c20f3be1410a1b1c2f4ce`, setting `VERSION` to `0.1.3`. PHP lint, Gallery Security, and Release Manifest Tests passed on its exact PR head; post-merge PHP lint and Gallery Security passed. No tag or release was created.
- [x] Verify the existing v0.1.2 fixture's genuine GitHub attestation and pinned native verifier dependency installation in CI (run 44873385969). This validates the fixture only; v0.1.2 is not approved for the new updater path.
- [x] Build and publish the private cPanel dependency artifact from main: `sentryiq-sigstore-vendor-php`, artifact ID `14695700420`, 854,394 bytes, archive SHA-256 `971213245f12dfa2f583be23aa943252b73db10864373a82b2cfdfd39f0bf121`, expiry 2026-12-21 06:12 UTC. Download from GitHub Actions run [44874394130](https://github.com/Double-IQ/SentryIQ/actions/runs/44874394130). PR #110 makes the inner ZIP checksum portable and CI verifies it with `sha256sum --check`; verify the included `.sha256` file again after downloading. The artifact has not been installed.
- [ ] Do not use the previously published v0.1.2 release for the new updater path: it predates the required embedded canonical manifest and KDF runtime policy.
- [ ] Generate a new release from the merged `main` source using the updated release workflow; PR #56 is already merged.
- [ ] Verify the new release ZIP checksum and genuine GitHub Sigstore attestation/provenance against the expected repository, workflow, ref, and commit.
- [ ] Verify the embedded canonical manifest covers the expected release inventory.
- [ ] Confirm release-tag immutability is active before publishing.
- [ ] Configure and test `SENTRYIQ_GH_BINARY` on the production host only after host approval.
- [ ] Test updater installation against a non-production copy first, including rollback and backup retention.
- [ ] Obtain explicit production deployment approval and a verified pre-update backup before any live updater run.

## 6. Four-node deployment gate

Phase 2 is not authorised by completion of this checklist alone.

**Signing-key generator follow-up:** PR [#117](https://github.com/Double-IQ/SentryIQ/pull/117) has passed all 13 CI checks on head `abf872f30642e63eeb951d518af089a21b0b54eb`. It hardens temporary key-file creation and fsyncs contents before publication; it remains open and unmerged. This is repository-level validation only. No production node keys have been generated, registered, or deployed, and the implementation does not claim directory-entry power-loss atomicity.

**Code/CI integration status (2026-11-21):** Node 4 event-plane and private-host attestation components are merged through [PR #99](https://github.com/Double-IQ/SentryIQ/pull/99). Native Sigstore Integrity Node Tests passed on main in [run 44873287657](https://github.com/Double-IQ/SentryIQ/actions/runs/44873287657), PHP 8.1–8.5. Native PHP Release Attestation passed on current main in [run 44873385969](https://github.com/Double-IQ/SentryIQ/actions/runs/44873385969), including the v0.1.2 end-to-end GitHub attestation check and private dependency packaging. The latest cPanel artifact is `sentryiq-sigstore-vendor-php` (artifact ID `14695700420`, 854,394 bytes, archive SHA-256 `971213245f12dfa2f583be23aa943252b73db10864373a82b2cfdfd39f0bf121`, expires 2026-12-21 06:12 UTC); it has not been installed. The earlier artifact ID `14695325067` is superseded. These results validate repository code and CI only. They do not provision any node, key, token, private state directory, baseline, cron job, listener, alert destination, or production monitor.

- [x] Node A platform selected: Cloudflare Workers (owner-confirmed). [ ] Implement and validate the Worker-native service; the existing PHP Node A CLI cannot run unchanged on Workers. Follow [the Cloudflare Workers implementation and acceptance boundary](integrity-node-a-cloudflare-workers.md), including real-runtime Sigstore/TUF verification, Durable Object persistence, Cron Trigger, secret bindings and direct owner alerts. Platform selection is not deployment acceptance.
- [ ] Verify Node B's Val Town assignment, deployed service/runtime, secrets custody, pinned trust material, private baseline/state, schedule, and direct owner-alert path. Hosting assignment is known; deployment/runtime acceptance is not.
- [ ] Verify Node C's HelioHost assignment, deployed native verifier/runtime, independent signing key, private evidence store/baseline, schedule, and direct owner-alert path. Compatibility code exists; deployment/runtime acceptance is not.
- [ ] Provision Node 4 (BTM-SA) as a separate logical service with private 0700 storage, pre-provisioned 0600 lock file, A/B bearer tokens and public keys, durable alert sender, monitor schedule, and tested replay/retention behavior. It shares a physical host with SentryIQ and is not an independent infrastructure failure domain.
- [ ] Provision the production private-host collector only if the host can provide a dedicated OS/service identity or equivalent isolation, read-only filesystem access, protected signing key, independently derived policy baselines, durable nonce store, and a separately wired HTTPS listener/reverse proxy. Do not expose the collector signing key to ordinary SentryIQ web-PHP.
- [ ] Configure each node with its own private signing key, unique credentials, pinned trust roots, independent state/baseline and schedule. Never share mutable state or private keys between nodes.
- [ ] Define service-to-service authentication, network boundaries, timeouts, retry/idempotency behavior, monitoring, and incident ownership for each node.
- [ ] Complete failure-mode, replay, stale-report, disagreement, alert-delivery, retention, and recovery exercises for each genuinely independent failure domain.
- [ ] Obtain explicit approval for the deployment plan and each production cutover.

## Completion record

Keep this section free of secrets.

| Gate | Owner/role | Status (pending / passed / blocked) | Evidence reference | Date |
|---|---|---|---|---|
| GitHub main protection | Repository administrator | Pending | Ruleset 27621562 active; 0 required approvals and Code Owner review disabled; see REPOSITORY-SECURITY-SETTINGS.md | 2026-11-21 |
| Release tag protection | Repository administrator | Passed | Active ruleset 27621577 protects refs/tags/v* against update and deletion | 2026-11-21 |
| GitHub platform security | Repository administrator | Pending | Owner-confirmed enabled; not independently API-verified | 2026-11-21 |
| Off-host backup + restore | Production/storage administrator | Pending | | |
| Production host acceptance | Hosting administrator | Pending | | |
| B2 acceptance | Storage administrator | Pending | | |
| New signed release + updater validation | Release/hosting administrator | Blocked pending owner gates and new release | | |
| Four-node deployment | Project owner/operations | Blocked pending all preceding gates | | |

**Security rule:** never mark a gate passed based only on a configuration intention, source-code change, or CI run. Record the observed result and evidence reference.