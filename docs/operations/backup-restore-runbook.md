# SentryIQ Backup and Restore Runbook

**Status:** Procedure template only — no backup job or restore has been executed.  
**Selected off-site destination:** MEGA account (owner decision, 2026-11-19; owner reports 20 GB available, not yet independently measured).  
**Scope:** SentryIQ application source/configuration, protected runtime data, and encrypted Backblaze B2 Gallery objects.

This runbook is not evidence that backups exist. MEGA has been selected as the destination, but available quota, transfer allowance, MEGAcmd installation/session, encryption/key custody, retention, automation, and restore exercise remain unverified or unconfigured. The reported 20 GB account capacity must be checked against a measured encrypted recovery-set size before acceptance.

## Data that must be recoverable

1. **Application release:** the exact deployed SentryIQ release and its verified provenance. Keep the release identifier and commit SHA with the backup record. Do not treat a live web-root copy as the only source of application code.
2. **Root configuration:** `sentryiq_config.php`, including the configured private `data_dir` path and base URL. Treat this file as sensitive.
3. **Protected runtime directory:** the complete configured `data_dir`, including the encrypted Vault store and required runtime PHP files, passkey records, Gallery key envelopes, Gallery object metadata/indexes, Backblaze configuration, and any other application state stored there. Do not selectively omit files based only on their extensions.
4. **Backblaze B2 bucket:** encrypted Gallery objects and the bucket configuration needed to address them. A database/runtime backup without the matching objects is not a complete Gallery backup.
5. **Operational evidence:** record the backup timestamp, release SHA, source host, destination account/folder, archive checksum, encryption/key reference, object inventory, and completion result. Keep audit logs according to the organisation's retention policy, but do not place them in a publicly accessible archive.

## Snapshot consistency and Gallery object coverage

SentryIQ runtime state is file-backed. The protected `data_dir` contains multiple related stores (for example Vault state, passkeys, authentication throttles, document metadata, Gallery key envelopes, Gallery object indexes, albums, duplicate indexes, settings, and the protected Backblaze configuration). Individual stores may be atomically replaced or locked, but there is no single application-wide transaction spanning the complete directory.

For a consistent recovery set:

1. Prefer a provider/filesystem snapshot with documented point-in-time semantics. If that is unavailable, schedule a short maintenance window and stop all application writers before copying the complete runtime directory. Do not assume a recursive live copy is consistent.
2. Capture the exact deployed release and sensitive root configuration alongside that runtime snapshot. Record the source commit/release identifier.
3. Capture the matching B2 Gallery objects and their object-version identifiers as part of the same recovery point. Include all four object roles used per Gallery item (original, thumbnail, preview, and encrypted metadata); a partial role set is not a complete Gallery recovery.
4. Record object keys, version IDs, sizes, and checksums in a private backup inventory. Do not expose filenames, object keys, metadata, or inventory publicly.
5. Resume application writers only after the local snapshot is complete. If B2 object capture cannot be aligned to the same point in time, record the consistency gap and do not claim a fully consistent recovery point.

### B2 backup identity is separate from the application identity

The Gallery application key is intentionally bucket-scoped and limited to the operations required by the application. Do not expand that runtime key merely to support backups.

Use a separate backup identity or provider-side replication mechanism with only the permissions needed to enumerate and read the required bucket objects and versions. Keep its credentials outside the application runtime and web root, and grant no write/delete permission to the backup identity unless the selected backup design demonstrably requires it. Confirm that the chosen B2 API/key type can enumerate historical versions and retrieve them; current-object listing alone may not recover deleted or overwritten objects.

If the bucket's versioning/lifecycle policy can permanently remove historical versions before the approved backup retention period, the backup design must account for that explicitly. A delete marker is not proof that prior object versions have been preserved indefinitely.

## MEGA destination design

MEGA is the selected off-site destination, using a dedicated SentryIQ backup folder in the owner's existing account. Keep the folder private: do not create public links, shared folders, or public exports for backup objects. MEGA's reported 20 GB capacity is owner-provided and must be verified in the account before relying on it. The complete encrypted backup set, retained generations, and available free-account transfer allowance must fit the actual account limits.

- Use the official MEGAcmd command-line client for scripted server-side uploads (`mega-put`) only after validating that the production host's operating system and runtime support the installed MEGAcmd build. Upload only a finalized, immutable encrypted recovery-set file and its manifest; never point a remote sync at a live SentryIQ data directory.
- MEGAcmd also has a native periodic `backup` command with a configurable maximum number of generations, but its current official command documentation labels this functionality **BETA**. It requires the MEGAcmd server process to be running; if it is stopped at a scheduled time, MEGAcmd records an empty backup as `SKIPPED`. It starts a backup immediately when first configured, and when the configured count is exceeded it deletes the oldest backup (with an exception to retain at least one complete backup). Do not enable this mode or its automatic pruning until a test account/folder has demonstrated the exact behaviour and the owner has approved the retention count. The initial implementation should prefer explicit upload of a completed immutable archive rather than depending on this beta scheduler.
- MEGAcmd's documented periodic backup configuration is session/server-bound, not an independent cloud-side schedule. A source-host outage, stopped server, expired/killed session, or unavailable local staging path can prevent a scheduled backup. Treat MEGAcmd's reported backup state/history as evidence to monitor, not as proof that the source snapshot was consistent.
- MEGAcmd requires an authenticated session. Its documentation states that session/cache and sync/backup configuration are stored in the local user's home directory and persist until logout; logging out cancels configured sync/backup tasks and removes their local configuration. Run it under a dedicated unprivileged OS account with a private home directory and restrictive permissions; protect the session state as an account credential. Do not place MEGA passwords, recovery keys, or session files in the web root, repository, logs, or command history.
- An authenticated MEGAcmd session is an account-level capability, not a narrowly scoped bucket token. Treat compromise of the source-host session as compromise of the MEGA account's accessible files. Use a dedicated backup folder, enable account protections such as two-factor authentication where available, and keep account recovery material separate from the source host.
- Generate a unique, non-reusable remote folder/object name for every backup run (for example, UTC timestamp plus a random run identifier). Never overwrite a completed recovery set. Do not create public links or exports. Verify remote file sizes and checksums after upload before marking a run complete.
- Keep the backup encryption key separate from both the MEGA account session and the backup archive. Prefer an independently held recovery key or envelope-encryption design with a documented key-recovery procedure. Do not rely solely on a key stored on the source host being backed up.
- Store a signed or authenticated manifest with each recovery set. It should identify the release SHA, snapshot time, included components, B2 object inventory/version IDs, archive parts, cryptographic algorithms/key reference, and per-part hashes. Do not put credentials or plaintext secrets in the manifest.
- MEGA account storage and transfer limits can constrain scheduled uploads/downloads. Before enabling a schedule, measure the encrypted recovery-set size, confirm actual remaining account storage, and complete a test upload and download within the account's transfer allowance. Alert on quota/transfer failures and never mark an incomplete upload as successful.
- Keep dated recovery sets separate. Do not automatically prune older sets until the owner approves a retention period and a tested cleanup rule. MEGA account access does not provide the same independently administered immutable-retention boundary as an object-lock bucket; an account/session compromise may permit deletion of retained backups. Record this residual risk explicitly.
- Retain an independent backup inventory and alert on missed schedules, failed uploads, checksum mismatches, unexpected object deletion, and storage growth. Do not make the source host the only place where backup success records exist.
- Test a restore by downloading from MEGA to an isolated recovery environment, verifying the manifest and hashes before decryption, then following the restore procedure below.

## Backup requirements

- Backups must be stored outside the SentryIQ web root and outside the same host's sole failure domain.
- Encrypt backups before they leave the source host. Keep the backup encryption key separate from the backup archive and restrict access to named administrators.
- Keep each backup generation under a unique dated remote folder and do not overwrite completed generations. MEGA does not provide the same separately administered immutable-retention control as an object-lock bucket; account/session compromise can still delete backups. Keep account recovery/admin access separate from the source-host session and document this residual risk.
- Back up the application release, root configuration, complete protected runtime directory, and B2 objects as one coordinated recovery set. Record any B2 object-version/lifecycle requirements.
- Use an application-wide quiesce or a provider-supported consistent filesystem snapshot; the separate file stores do not provide a single transaction across the complete runtime directory.
- Use a separate, least-privilege B2 backup identity or provider-side replication. Do not broaden the Gallery application's bucket-scoped runtime key to grant backup enumeration or historical-version access.
- Preserve and inventory B2 object version IDs and checksums where version recovery is required; verify lifecycle rules cannot expire required versions before backup retention.
- Do not email archives, upload them to public file-sharing services, or place them under `public_html`.
- Establish retention and recovery-point objectives with the owner. Do not assume a retention period that has not been approved.
- Run a backup before every application update or data migration, and verify the archive checksum after transfer.

## Restore procedure

1. Select a clean, isolated recovery host. Do not overwrite the live installation during the first restore test.
2. Retrieve the exact application release by its recorded commit/release identifier and verify its GitHub attestation before installation.
3. Retrieve the completed recovery set from the private MEGA backup folder using a separately controlled recovery session. Verify the manifest authenticity and all archive-part hashes before decryption.
4. Restore `sentryiq_config.php` and the complete protected runtime directory to a private absolute path outside `DOCUMENT_ROOT`.
5. Restore the matching encrypted B2 object set and ensure the configured bucket, region, key ID and application key refer to the same storage account. Never put B2 credentials in the web root or in this runbook. Restore the object versions referenced by the backup inventory, not merely the latest object currently present under each key. Keep the backup-only B2 identity separate from the application's runtime key.
6. Apply restrictive ownership and permissions: private directories owner-only where supported; secrets/configuration and key files owner-only (0600); executable application files must not be writable by untrusted web users.
7. Confirm the runtime path passes SentryIQ's canonical outside-web-root validation. Confirm direct HTTP requests cannot retrieve private runtime/configuration files.
8. Run the SentryIQ self-test and focused Vault, passkey, Gallery metadata, and B2 object checks against the isolated restore.
9. Verify that a known Vault record can be decrypted using the authorised recovery method and that a Gallery object can be fetched and decrypted in the browser. Do not print secrets or decrypted content into logs.
10. Record any missing files, key dependencies, permissions, failed checks, restore duration, and data-loss window. Destroy the isolated test copy securely when the exercise is complete.

## Recovery limitations and prerequisites

- A Vault data backup is not useful without the corresponding master-key/recovery material held by the authorised owner.
- A Gallery runtime backup is not sufficient without the matching encrypted B2 objects and usable B2 credentials.
- A source-code repository is not a backup of production data, credentials, or B2 objects.
- The repository does not currently contain an automated backup scheduler, MEGA/MEGAcmd upload integration, backup encryption/key management, or a verified restore test.
- Host-specific commands, MEGA account quota/transfer verification, MEGAcmd session setup, retention, schedule, and key custody must be completed for the actual hosting provider before this procedure can be considered operational.

## Acceptance evidence

Do not mark the backup/restore finding complete until all of the following are recorded:

- [ ] MEGA backup folder created and kept private; no public links/exports.
- [ ] Actual remaining MEGA storage and transfer allowance verified against measured encrypted backup size and retention count.
- [ ] MEGAcmd installed and tested under a dedicated unprivileged OS account; session state protected and recovery/admin access separated.
- [ ] Retention policy and account-level deletion risk explicitly accepted; dated generations and cleanup tested.
- [ ] Backup encryption and key recovery tested independently of the source host.
- [ ] Consistent snapshot procedure tested for runtime data and B2 Gallery objects.
- [ ] Scheduled backup configured for code/configuration/runtime data and B2 objects.
- [ ] Backup integrity verified after transfer and completion monitoring/alerts tested.
- [ ] Isolated restore from MEGA completed successfully.
- [ ] Vault and Gallery recovery checks passed.
- [ ] Recovery time, recovery point, retention, storage cost, and residual limitations documented.
