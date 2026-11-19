# SentryIQ Backup and Restore Runbook

**Status:** Procedure template only — no backup job or restore has been executed.  
**Scope:** SentryIQ application source/configuration, protected runtime data, and encrypted Backblaze B2 Gallery objects.

This runbook is not evidence that backups exist. Before production acceptance, the owner must select an off-host backup destination, configure encryption and retention, automate or schedule backups, and complete a restore exercise.

## Data that must be recoverable

1. **Application release:** the exact deployed SentryIQ release and its verified provenance. Keep the release identifier and commit SHA with the backup record. Do not treat a live web-root copy as the only source of application code.
2. **Root configuration:** sentryiq_config.php, including the configured private data_dir path and base URL. Treat this file as sensitive.
3. **Protected runtime directory:** the complete configured data_dir, including the encrypted Vault store and required runtime PHP files, passkey records, Gallery key envelopes, Gallery object metadata/indexes, Backblaze configuration, and any other application state stored there. Do not selectively omit files based only on their extensions.
4. **Backblaze B2 bucket:** encrypted Gallery objects and the bucket configuration needed to address them. A database/runtime backup without the matching objects is not a complete Gallery backup.
5. **Operational evidence:** record the backup timestamp, release SHA, source host, backup destination, archive checksum, encryption/key reference, and completion result. Keep audit logs according to the organisation's retention policy, but do not place them in a publicly accessible archive.

## Backup requirements

- Backups must be stored outside the SentryIQ web root and outside the same host's sole failure domain.
- Encrypt backups before they leave the source host. Keep the backup encryption key separate from the backup archive and restrict access to named administrators.
- Use a destination with versioning or immutable retention where available. A compromised origin must not be able to silently overwrite every retained copy.
- Back up the application release, root configuration, complete protected runtime directory, and B2 objects as one coordinated recovery set. Record any B2 object-version/lifecycle requirements.
- Do not email archives, upload them to public file-sharing services, or place them under public_html.
- Establish retention and recovery-point objectives with the owner. Do not assume a retention period that has not been approved.
- Run a backup before every application update or data migration, and verify the archive checksum after transfer.

## Restore procedure

1. Select a clean, isolated recovery host. Do not overwrite the live installation during the first restore test.
2. Retrieve the exact application release by its recorded commit/release identifier and verify its GitHub attestation before installation.
3. Restore sentryiq_config.php and the complete protected runtime directory to a private absolute path outside DOCUMENT_ROOT.
4. Restore the matching encrypted B2 object set and ensure the configured bucket, region, key ID and application key refer to the same storage account. Never put B2 credentials in the web root or in this runbook.
5. Apply restrictive ownership and permissions: private directories owner-only where supported; secrets/configuration and key files owner-only (0600); executable application files must not be writable by untrusted web users.
6. Confirm the runtime path passes SentryIQ's canonical outside-web-root validation. Confirm direct HTTP requests cannot retrieve private runtime/configuration files.
7. Run the SentryIQ self-test and focused Vault, passkey, Gallery metadata, and B2 object checks against the isolated restore.
8. Verify that a known Vault record can be decrypted using the authorised recovery method and that a Gallery object can be fetched and decrypted in the browser. Do not print secrets or decrypted content into logs.
9. Record any missing files, key dependencies, permissions, failed checks, restore duration, and data-loss window. Destroy the isolated test copy securely when the exercise is complete.

## Recovery limitations and prerequisites

- A Vault data backup is not useful without the corresponding master-key/recovery material held by the authorised owner.
- A Gallery runtime backup is not sufficient without the matching encrypted B2 objects and usable B2 credentials.
- A source-code repository is not a backup of production data, credentials, or B2 objects.
- The repository does not currently contain an automated backup scheduler, off-host destination configuration, backup encryption/key management, or a verified restore test.
- Host-specific commands, backup destination, retention, schedule, and credential custody must be completed for the actual hosting provider before this procedure can be considered operational.

## Acceptance evidence

Do not mark the backup/restore finding complete until all of the following are recorded:

- [ ] Off-host destination and administrator access policy approved.
- [ ] Backup encryption and key custody tested.
- [ ] Scheduled backup configured for code/configuration/runtime data and B2 objects.
- [ ] Backup integrity verified after transfer.
- [ ] Isolated restore completed successfully.
- [ ] Vault and Gallery recovery checks passed.
- [ ] Recovery time, recovery point, and residual limitations documented.
