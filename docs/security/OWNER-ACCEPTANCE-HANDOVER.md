# SentryIQ Owner Acceptance Handover

**Status:** Prepared for owner execution — no owner/production controls have been changed by this document.  
**Date:** 2026-11-19  
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

- [ ] Enable a branch protection rule or repository ruleset targeting `main`.
- [ ] Require pull requests before merging.
- [ ] Require at least one approving review and dismiss stale approvals when new commits are pushed.
- [ ] Require Code Owner review.
- [ ] Require these exact GitHub Actions job status checks (job/check names, not workflow display names): `php-lint`, `gallery-security`, `release-manifest`, and `Verify release attestation and dual-node report contract`. Reconfirm the names in GitHub's protection UI when configuring the rule.
- [ ] Require branches to be up to date before merging, if compatible with the team's workflow.
- [ ] Block force pushes and branch deletion.
- [ ] Apply protections to administrators unless an explicitly documented emergency bypass is approved.

**Evidence to record:** ruleset/protection name and ID, target branch, selected required checks, review requirements, bypass policy, administrator who configured it, and date verified. Do not include tokens or private account data.

### 1.2 Protect release tags

- [ ] Create a tag ruleset targeting `v*`.
- [ ] Prevent updates and deletion of published release tags.
- [ ] Verify the rule with a non-production test tag or read-only ruleset inspection before relying on it for a release.

**Evidence to record:** ruleset name/ID, tag pattern, enforcement status, and date verified.

### 1.3 Platform security settings

- [ ] Verify secret scanning is enabled where available for this repository/plan.
- [ ] Verify push protection is enabled where available.
- [ ] Verify Dependabot alerts and security updates are enabled.
- [ ] Verify private vulnerability reporting is enabled.
- [ ] Review repository write/admin collaborators and remove stale access through the normal access-review process.
- [ ] Confirm Actions' default token permissions are read-only and review any workflow-specific write permissions.

**Evidence to record:** enabled/disabled/not-available status for each control, date checked, and administrator. Do not record secret values or personal access tokens.

## 2. Backup and restore — production/storage administrator

Use the companion [Backup and Restore Runbook](backup-restore-runbook.md). It remains a procedure template until the steps below have actually been completed.

- [ ] Approve an off-host destination in a separate infrastructure failure domain from the SentryIQ host.
- [ ] Approve backup encryption and keep the encryption key separate from the archive, with named-administrator custody.
- [ ] Approve recovery-point and recovery-time objectives and retention; do not assume unapproved retention periods.
- [ ] Configure a scheduled, monitored backup covering the exact deployed application release/provenance, sensitive root configuration, the complete protected runtime data directory, and the matching encrypted B2 Gallery objects.
- [ ] Ensure the destination has versioning or immutable retention where available and that the origin cannot silently overwrite every retained copy.
- [ ] Verify archive integrity after transfer.
- [ ] Perform a restore to an isolated recovery host; do not overwrite production for the first exercise.
- [ ] Verify the restored private path is outside the document root and permissions are restrictive.
- [ ] Verify an authorised Vault recovery/decryption check and a Gallery object retrieval/decryption check without logging secrets or plaintext.
- [ ] Record restore duration, recovery point/data-loss window, missing dependencies, and residual limitations.

**Evidence to record:** destination class/provider (not credentials), schedule, retention, encryption/key-custody reference, archive checksum, source release SHA, backup result, restore date/result, and recovery measurements.

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

- [ ] Confirm Node A provider/host assignment and failure domain; it remains unconfirmed in the current architecture record.
- [ ] Confirm Node B (Val Town) service ownership, endpoint, secrets custody, and health checks.
- [ ] Confirm Node C (HelioHost) service ownership, endpoint, secrets custody, and health checks.
- [ ] Confirm Node 4 (BTM-SA) is a logically separate service but shares a physical host with SentryIQ; do not count it as an independent infrastructure failure domain.
- [ ] Define service-to-service authentication, network boundaries, timeouts, retry/idempotency behavior, monitoring, and incident ownership for each node.
- [ ] Complete a failure-mode test and recovery exercise for each genuinely independent failure domain.
- [ ] Obtain explicit approval for the deployment plan and each production cutover.

## Completion record

Keep this section free of secrets.

| Gate | Owner/role | Status (pending / passed / blocked) | Evidence reference | Date |
|---|---|---|---|---|
| GitHub main protection | Repository administrator | Pending | | |
| Release tag protection | Repository administrator | Pending | | |
| GitHub platform security | Repository administrator | Pending | | |
| Off-host backup + restore | Production/storage administrator | Pending | | |
| Production host acceptance | Hosting administrator | Pending | | |
| B2 acceptance | Storage administrator | Pending | | |
| New signed release + updater validation | Release/hosting administrator | Blocked pending owner gates and new release | | |
| Four-node deployment | Project owner/operations | Blocked pending all preceding gates | | |

**Security rule:** never mark a gate passed based only on a configuration intention, source-code change, or CI run. Record the observed result and evidence reference.