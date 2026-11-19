# SentryIQ clean subdomain deployment plan

**Target:** `https://sentryiq.bichet.co.za`  
**Hosting:** cPanel; no shell/SSH access confirmed.  
**Deployment model:** clean installation from the reviewed GitHub release. The owner has explicitly declined to preserve or migrate the existing installation.  
**Current status:** subdomain and TLS are owner-confirmed; deployment is not started. No application files, runtime configuration, DNS, or production data have been changed by this plan.

## Scope and non-goals

- Deploy the reviewed SentryIQ application source to the cPanel subdomain document root.
- Create fresh protected runtime storage and fresh credentials/configuration for the new installation.
- Do not copy the old installation's files, runtime directory, users, passkeys, vault, documents, Gallery records, albums, or Backblaze B2 objects.
- Do not create a full cPanel account backup for the old installation.
- Do not redirect, delete, or modify the old origin as part of initial deployment. Its retirement is a separate, later action requiring explicit approval.
- Backups for the new installation must be designed and tested before it accepts valuable production data.

## Confirmed hosting facts

- Canonical hostname: `sentryiq.bichet.co.za`.
- cPanel document root previously recorded by the owner: `/home/bicheveb/sentryiq.bichet.co.za`.
- Protected runtime directory previously reserved: `/home/bicheveb/sentryiq-private`.
- The hostname resolves and HTTPS loads without a browser certificate warning (owner-confirmed).
- Directory indexing was disabled in the empty document root (owner-confirmed).
- cPanel Backup / Backup Wizard and Cron Jobs are visible, but neither is needed for the legacy installation.
- The owner has no shell/SSH access. All host-side steps must be achievable through cPanel or the hosting provider.

These facts must be rechecked in cPanel immediately before deployment. Do not assume that a previously recorded path or permission remains unchanged.

## Blocking code issue: first-run private path

The current `app/Security/FirstRun.php` computes its default private directory using `dirname(__DIR__, 4) . '/private_data'`. With the repository deployed at `/home/bicheveb/sentryiq.bichet.co.za`, this resolves outside the hosting account's intended protected directory. The installer also expects source templates under the deployed repository's `private_data/` directory and has cleanup logic tied to that source path.

**Do not expose or execute first-run setup until this behavior is corrected and tested.**

Required engineering work before deployment:

1. Refactor first-run setup to use an explicit, validated deployment target for the protected runtime directory. It must not infer the target by walking parent directories.
2. Keep the protected runtime directory outside the document root and reject symlinks, web-accessible paths, and paths outside the permitted account boundary.
3. Ensure the installer copies only the required runtime support files from the reviewed release into the protected directory, with owner-only permissions where supported.
4. Ensure the root pointer configuration is written atomically, permissioned restrictively, validated by reloading it, and never exposes secrets in errors or logs.
5. Ensure the installer fails closed if the configured path is missing, unwritable, inside the document root, or disallowed by `open_basedir`.
6. Add automated tests for the exact cPanel path shape and for rejection of unsafe paths.
7. Ensure the installer cannot be re-entered after successful installation and that partial failures do not leave a usable, half-installed application.

Do not work around this bug by creating `/home/private_data`, copying old runtime files, or manually pointing the new installation at legacy data.

## Deployment layout

Expected layout, subject to cPanel path verification:

```text
/home/bicheveb/
├── sentryiq.bichet.co.za/     # public document root; reviewed release only
└── sentryiq-private/          # protected runtime; never web-served
```

The document root may contain public entry points, application source required at runtime, static assets, and hardened web-server rules. It must not contain runtime secrets, vault data, passkey records, session data, private logs, or generated user files.

The protected directory must be outside the document root, non-symlinked, owned by the account, and permissioned as restrictively as the host supports. Verify PHP can read/write it and that `open_basedir` permits access. Do not weaken host-wide restrictions merely to make deployment pass.

## Configuration requirements

Fresh configuration only:

- Canonical `base_url`: `https://sentryiq.bichet.co.za`.
- Protected `data_dir`: verified absolute path outside document root.
- Fresh administrator identity and 2FA destination.
- Fresh vault master password and newly generated recovery key, stored offline by the owner.
- Fresh B2 credentials/configuration only if the new Gallery is enabled. Use a private bucket and a least-privilege application key; keep backup credentials separate.
- Do not reuse, copy, or commit old installation secrets, passkeys, cookies, session files, or runtime configuration.

## Release and cPanel deployment sequence

1. Complete the first-run installer code fix and its tests in a reviewed pull request.
2. Confirm the release/commit intended for deployment and verify all required CI checks pass.
3. In cPanel, re-confirm the subdomain document root and the protected directory path, ownership, permissions, available storage, and PHP `open_basedir` constraints.
4. Confirm the selected PHP version and required extensions against the release's documented runtime requirements.
5. Upload the reviewed release archive into the document root using cPanel File Manager or another approved deployment mechanism. Do not upload a working tree containing secrets, local runtime files, test artifacts, or Git metadata.
6. Before making the app publicly usable, install the corrected root pointer/configuration and verify that it references only the new protected directory. Do not expose first-run setup while its target path is unresolved.
7. Run the corrected fresh-install flow once, using a strong unique master password. Save the generated recovery key offline before continuing.
8. Configure fresh 2FA email delivery and verify delivery without exposing codes in logs.
9. Configure Gallery/B2 only after the bucket, key scope, CORS, lifecycle/versioning, and browser transfer checks are reviewed.
10. Run the full acceptance suite against the new origin. Do not treat a successful homepage response as deployment acceptance.

## Acceptance gates

### Host and web server
- [ ] DNS resolves to the intended hosting account.
- [ ] HTTPS certificate is valid for the subdomain.
- [ ] HTTP redirects to HTTPS without redirect loops.
- [ ] Apache version supports the repository's rewrite flags (including `[END]`), or rules are adjusted and tested.
- [ ] Directory listing is disabled; source, tests, docs, scripts, VCS, and private paths are not directly retrievable.
- [ ] PHP version, extensions, limits, and `open_basedir` are compatible.
- [ ] Error display is disabled; logs are private and do not contain credentials, tokens, or plaintext vault data.

### Application and protected storage
- [ ] Corrected first-run path logic is merged and tested.
- [ ] Document root contains no runtime data or secrets.
- [ ] Protected directory is outside document root, non-symlinked, private, and PHP-readable/writable.
- [ ] Root pointer and protected config are restrictive, valid, and agree on base URL and data directory.
- [ ] Fresh first-run completes exactly once and creates a verifiable encrypted vault.
- [ ] Recovery key is saved offline and recovery is tested before valuable data is stored.
- [ ] Password + 2FA, lock/logout, CSRF, throttling, and session-cookie behavior pass.
- [ ] Passkey registration/login works with the new host's RP ID `sentryiq.bichet.co.za`; no old credentials are imported.
- [ ] Diagnostics pass without disclosing secrets.

### Gallery and external services (if enabled)
- [ ] Fresh B2 application key is least-privilege and distinct from any backup identity.
- [ ] Bucket remains private and exact-origin CORS is configured.
- [ ] Browser upload, preview, download, and delete work from the new origin.
- [ ] Encryption/decryption and key-envelope recovery tests pass.
- [ ] New Gallery objects and metadata are included in the new backup/restore design.

### Operations
- [ ] Backup scope, encryption, key custody, retention, and MEGA transfer are implemented for the new runtime before production data is stored.
- [ ] Isolated restore from the selected backup destination succeeds.
- [ ] Integrity monitoring targets and signed-release verification are deployed and tested where required by the master checklist.
- [ ] Rollback and incident contacts/procedure are documented.
- [ ] Owner explicitly approves production cutover.

## Rollback and legacy retirement

The initial deployment does not modify the old application. Keep it untouched while the new origin is tested. Do not redirect the old URL, delete the old files, revoke old credentials, or change shared DNS until the new deployment passes acceptance and the owner explicitly approves the cutover/retirement step.

## Current outstanding owner action

No cPanel action is required yet. The next owner interaction should occur only after the first-run path correction and deployment package are reviewed. At that point, the owner will be asked to verify the current document-root/protected-directory details in cPanel and perform the controlled upload/initialization steps that cannot be executed without hosting access.
