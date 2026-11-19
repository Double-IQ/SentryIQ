# SentryIQ Backup and Restore Runbook

**Status:** Procedure template only — no backup job or restore has been executed.  
**Selected off-site destination:** Cloudflare R2 (owner decision, 2026-11-19).  
**Scope:** SentryIQ application source/configuration, protected runtime data, and encrypted Backblaze B2 Gallery objects.

This runbook is not evidence that backups exist. R2 has been selected as the destination, but the R2 bucket, credentials, retention policy, encryption/key custody, automation, and restore exercise remain unconfigured.

## Data that must be recoverable

1. **Application release:** the exact deployed SentryIQ release and its verified provenance. Keep the release identifier and commit SHA with the backup record. Do not treat a live web-root copy as the only source of application code.
2. **Root configuration:** `sentryiq_config.php`, including the configured private `data_dir` path and base URL. Treat this file as sensitive.
3. **Protected runtime directory:** the complete configured `data_dir`, including the encrypted Vault store and required runtime PHP files, passkey records, Gallery key envelopes, Gallery object metadata/indexes, Backblaze configuration, and any other application state stored there. Do not selectively omit files based only on their extensions.
4. **Backblaze B2 bucket:** encrypted Gallery objects and the bucket configuration needed to address them. A database/runtime backup without the matching objects is not a complete Gallery backup.
5. **Operational evidence:** record the backup timestamp, release SHA, source host, destination bucket/prefix, archive checksum, encryption/key reference, object inventory, and completion result. Keep audit logs according to the organisation's retention policy, but do not place them in a publicly accessible archive.

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

## Cloudflare R2 destination design

Cloudflare R2 is the selected off-site destination. Use a dedicated **private** bucket for SentryIQ backups, separate from the existing Backblaze B2 Gallery bucket. Do not enable public bucket access, custom domains, or `r2.dev` access for backup objects.

- Use the R2 S3-compatible endpoint over HTTPS and an R2 API token restricted to this one bucket. The application-side backup credential must not have permission to change bucket settings, manage tokens, or remove retention rules.
- Separate the R2 account/bucket administrator from the source-host upload identity. Configure bucket retention/lock policy through the Cloudflare dashboard or a separately held administrative credential, not the SentryIQ runtime.
- Use Cloudflare R2 bucket-lock rules on the backup object prefix to prevent overwrite and deletion for the owner-approved retention period. Cloudflare documents age-based, date-based, and indefinite bucket-lock rules; lock rules take precedence over lifecycle deletion. The retention period must be chosen before activation and must not be guessed by the implementation.
- Generate a unique, non-reusable object key for each backup run (for example, date/time plus a random run identifier). Never overwrite a prior backup object. A retry must use a new run identifier or safely resume the same multipart upload without replacing an existing completed backup.
- Keep the backup encryption key separate from both the R2 object and the R2 upload credential. Prefer an independently held recovery key or envelope-encryption design with a documented key-recovery procedure. Do not rely solely on a key stored on the source host being backed up.
- Store a signed or authenticated manifest with each recovery set. It should identify the release SHA, snapshot time, included components, B2 object inventory/version IDs, archive parts, cryptographic algorithms/key reference, and per-part hashes. Do not put credentials or plaintext secrets in the manifest.
- Upload encrypted archive parts and manifest, verify remote size and checksum, then mark the recovery set complete. An incomplete upload must never be reported as a successful backup.
- Retain an independent backup inventory and alert on missed schedules, failed uploads, checksum mismatches, unexpected object deletion, and storage growth. Do not make the source host the only place where backup success records exist.
- Test a restore by downloading from R2 to an isolated recovery environment, verifying the manifest and hashes before decryption, then following the restore procedure below.

### R2 cost planning

R2 Standard storage is currently published at **US$0.015 per GB-month**, with the first **10 GB-month free**; internet egress is free. Class A and Class B operation charges may also apply, though normal backup workloads may fit within the published monthly request allowances. Infrequent Access has retrieval charges and a 30-day minimum storage duration, so use Standard initially until restore frequency and lifecycle needs are measured.

Approximate storage-only monthly cost for one retained copy, excluding request charges and tax:

| Stored backup data | Approximate monthly storage |
|---:|---:|
| 10 GB | Free within the Standard allowance |
| 50 GB | US$0.60 |
| 100 GB | US$1.35 |
| 250 GB | US$3.60 |
| 500 GB | US$7.35 |
| 1 TB | US$14.85 |

These are estimates, not measured SentryIQ usage. Actual R2 usage depends on Gallery object volume, retained backup count, compression, archive format, and whether unchanged B2 objects are deduplicated or copied into each recovery set. Measure the first completed backup before setting a budget or retention policy.

## Backup requirements

- Backups must be stored outside the SentryIQ web root and outside the same host's sole failure domain.
- Encrypt backups before they leave the source host. Keep the backup encryption key separate from the backup archive and restrict access to named administrators.
- Use R2 bucket-lock retention to prevent backup objects from being overwritten or deleted during the owner-approved retention period. Keep the administrative ability to change that policy separate from the application upload credential.
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
3. Retrieve the completed recovery set from the private R2 bucket using a separately controlled restore credential. Verify the manifest authenticity and all archive-part hashes before decryption.
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
- The repository does not currently contain an automated backup scheduler, R2 destination integration, backup encryption/key management, or a verified restore test.
- Host-specific commands, R2 bucket creation, bucket-lock retention, credentials, schedule, and key custody must be completed for the actual hosting provider before this procedure can be considered operational.

## Acceptance evidence

Do not mark the backup/restore finding complete until all of the following are recorded:

- [ ] Dedicated private R2 bucket created and endpoint recorded.
- [ ] R2 bucket-lock policy and retention period approved and verified.
- [ ] Bucket-scoped upload and restore credentials created with separated permissions and custody.
- [ ] Backup encryption and key recovery tested independently of the source host.
- [ ] Consistent snapshot procedure tested for runtime data and B2 Gallery objects.
- [ ] Scheduled backup configured for code/configuration/runtime data and B2 objects.
- [ ] Backup integrity verified after transfer and completion monitoring/alerts tested.
- [ ] Isolated restore from R2 completed successfully.
- [ ] Vault and Gallery recovery checks passed.
- [ ] Recovery time, recovery point, retention, storage cost, and residual limitations documented.
