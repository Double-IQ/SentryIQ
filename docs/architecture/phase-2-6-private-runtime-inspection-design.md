# Phase 2.6 — Private server-side runtime inspection boundary

**Status:** Design artifact complete; host/provider qualification and owner/security approval remain open.  
**Application:** https://sentryiq.bichet.co.za  
**Independent verifier:** One specialised HelioHost verifier.  
**Safety:** No host was probed or configured; no credentials, keys, collectors, or deployment were created.

## 1. Objective and limits

Phase 2.5 defines what HelioHost can measure through public HTTPS. That cannot prove the integrity of PHP source files, private runtime templates, private Composer dependencies, or host-side configuration. Phase 2.6 defines the narrowest defensible private-file measurement boundary.

The central rule is that **the verifier must obtain file bytes or metadata through an independently controlled read-only channel, not accept hashes or status claims supplied by the application**. A public PHP endpoint that reports its own file hashes is not independent evidence.

There is also a hard technical limit: a read-only SFTP/SSH account on the application host measures what that host's SSH/file service returns. If the application host's privileged OS/operator is fully compromised, it may falsify the read-only response. Without provider-controlled snapshots, trusted host-level measurement, or hardware-backed remote attestation, the verifier cannot prove the underlying disk state against a fully privileged host attacker. Reports must state that limitation and must not claim stronger assurance.

If no qualified independent mechanism is available, private runtime status is **unavailable**. A policy requiring private runtime evidence must fail closed; it must not silently convert a public-HTTP-only result into a full pass.

## 2. Inventory classes

The format-3 manifest and host deployment profile must distinguish these classes.

| Class | Examples | Inspection rule |
|---|---|---|
| Public static assets | JS, CSS, images, fonts, WASM, web manifest, service worker | Byte measurement through the Phase 2.5 HTTP protocol; private file measurement may be supplementary |
| Publicly deployed server code | PHP entrypoints, application PHP classes, include files, updater code | Exact file bytes through qualified private inspection; never fetch PHP source through public HTTP |
| Private release-managed runtime code | Runtime templates relocated outside webroot, private helper code | Exact file bytes through qualified private inspection |
| Private dependency bundle | Pinned Sigstore/TUF vendor package and reviewed patches | Exact bundle and per-file digest against the authorised dependency inventory |
| Non-secret runtime metadata | Private data root location class, schema version, required configuration file presence, directory/file permission profile | Inspect only approved metadata; never return secret-bearing contents |
| Secret-bearing configuration | API credentials, database passwords, signing secrets, service tokens, private key material | Excluded from content inventory; do not read, hash, log, or return values |
| Mutable application state | Database, user content, ciphertext objects, sessions, logs, caches, temporary files, backups, update workspace | Excluded from release code inventory; separate operational/backup policy |
| Verifier and recovery secrets | HelioHost private key, master private key, recovery material | Must never be present on or accessible from the application host |

The current package builder relocates four private runtime templates into a runtime directory. The target manifest must inventory those files and all other release-managed server code, but must not sweep the entire private data directory or hash mixed secret/config files.

## 3. Logical roots and path mapping

The manifest uses logical root identifiers, never absolute production paths:
- APP_RELEASE_ROOT — release-managed application code under the application deployment root.
- PRIVATE_RUNTIME_ROOT — release-managed PHP/runtime files outside the public document root.
- PRIVATE_DEPENDENCY_ROOT — pinned private dependency bundles outside the public document root.
- PUBLIC_DOCUMENT_ROOT — root used only to map public HTTP asset URLs and to check path separation.
- PRIVATE_CONFIG_ROOT — metadata-only configuration location; secret contents are excluded.

A host-specific deployment profile maps these logical roots to actual paths during qualification. The mapping is stored in protected verifier policy, not accepted from a public request or application-host response.

Path policy:
- Use a fixed allowlist of logical roots and manifest-listed relative paths.
- Reject absolute paths, traversal, backslashes, NUL/control characters, duplicate/case-colliding paths, symlinks, unsupported special files, and path aliases.
- Do not recursively read arbitrary private directories.
- Enumerate only explicitly approved application-code directories to detect unexpected executable files; do not list the entire private data directory.
- Record file type, byte length, digest, and required permission profile for release-managed code.
- For a path that cannot be safely resolved without following a symlink, report failure.
- Never accept a path supplied by the application or challenge requester that is not present in the signed manifest and approved deployment profile.

## 4. Read-only inspection mechanisms

Evaluate the following options in order. No option is assumed available until the host/provider qualification gate is satisfied.

### 4.1 Provider-controlled snapshot or read-only inventory — preferred

A provider-controlled filesystem snapshot/export or host-level inventory is the strongest option if it:
- Is created by a provider-controlled mechanism outside the application process's authority.
- Is immutable/read-only for the measurement window.
- Exposes exact file bytes and safe file metadata for allowlisted roots.
- Has a stable snapshot identifier and capture timestamp.
- Cannot be modified by the application account or its PHP process.
- Can be independently authenticated to the verifier.

This can reduce race conditions and the ability of a compromised application process to forge its own file measurement. The provider's trust boundary and guarantees must be documented; a normal account-level backup/export is not automatically a trusted snapshot.

### 4.2 Restricted read-only SFTP/SSH — conditional, limited assurance

If provider snapshots are unavailable, evaluate a dedicated read-only file-transfer identity:
- HelioHost initiates the connection; the application host does not push hashes or open an inbound connection to the verifier.
- A dedicated account is restricted to the allowlisted code roots or a chroot containing only those roots.
- The account has read/list/stat permissions only; no write, create, truncate, rename, delete, chmod, shell, command execution, port forwarding, agent forwarding, PTY, or privilege escalation.
- Authentication uses a dedicated credential stored only in the verifier's protected private storage; no credential is copied into Git, chat, application configuration, or the public webroot.
- SSH host key is pinned through a separately authenticated host bootstrap and is checked on every connection.
- The verifier enforces strict host/path allowlists, file-size limits, timeouts, and no symlink following.
- Account permissions are tested by attempting forbidden operations and proving they fail.
- The account cannot read user content, sessions, backups, logs, database files, secret config values, private keys, or recovery material.

This provides useful evidence of the bytes returned by the host's file service. It does **not** prove that a privileged application-host operator or compromised OS cannot falsify the response. The report must label this assurance boundary explicitly. Do not describe restricted SFTP as hardware remote attestation or provider-independent proof of the underlying disk.

### 4.3 Host-side collector or signed projection — not sufficient by itself

The legacy private-host collector is a host-side process. Even if it is read-only and signs its own output, an application-host compromise may replace its code, inventory, signing key, or output. An application-host-generated digest is not an independent measurement.

A collector may be considered only as a provider-controlled agent running under an independently administered OS identity with protected policy and signing boundary, and only if the provider can demonstrate that the application account cannot modify the agent, key, policy, or evidence. A normal PHP endpoint or account-level cron job does not meet this condition.

A sanitized projection of secret configuration values is not accepted as proof if the application host can fabricate the projection. Prefer a separate non-secret configuration metadata file or provider-level metadata interface, with its own integrity policy.

### 4.4 No public arbitrary file-read endpoint

Never create a public endpoint that accepts a path, returns file contents, returns arbitrary hashes, exposes private config, or provides a generic filesystem listing. The verifier does not need a web-accessible file browser.

## 5. What is measured

### 5.1 Release-managed application code

Measure every manifest-listed release-managed server-side code file, including PHP entrypoints, included classes, updater code, and private runtime templates.

For each file:
- Resolve the logical root using the qualified host profile.
- Validate path and file type without following symlinks.
- Read exact bytes through the qualified channel.
- Calculate SHA-256 and byte length in the verifier.
- Compare with the signed manifest entry.
- Record only logical path, expected/observed digest, size, permission result, source channel, and status.
- Never include file contents in the report.

The manifest must not omit a PHP file merely because it resides beneath the public document root. PHP source is not a public static HTTP asset; it requires private file measurement if the active policy requires server-code integrity.

### 5.2 Private dependencies

Private dependencies are separate release inputs:
- Verify the downloaded dependency bundle digest against its approved record.
- Verify upstream package names/versions/source commits and patch-set digests.
- Verify installed dependency files against the bundle inventory or a deterministic installed-tree inventory.
- Confirm the autoloader is outside the public webroot and its resolved path is within the approved private dependency root.
- Reject symlinks, changed files, unpinned package versions, missing files, and unexpected executable files.
- Record exact dependency identity and digest, not source code or package contents.

The current CI workflow produces a private verifier dependency ZIP as a temporary Actions artifact. This is not proof of production installation or integrity.

### 5.3 Configuration metadata without secrets

The verifier may check:
- The private data root exists and resolves outside the public document root.
- Required configuration file paths exist as regular files, not symlinks.
- Directory/file owner and permission profile meet the qualified host policy.
- A separately maintained non-secret configuration schema/version marker matches the approved value.
- The private dependency autoloader exists in the expected private location.
- Required configuration keys are present only if a provider-controlled projection can prove presence without exposing values and cannot be forged by the application process.

The verifier must not:
- Read or transfer mixed secret-bearing configuration contents.
- Hash a secret-bearing config file as a whole.
- Hash low-entropy secret values or produce fingerprints that enable offline guessing.
- Return config contents, values, environment dumps, database credentials, API tokens, salts, session secrets, private keys, or service credentials.
- Treat a PHP endpoint that reports configuration status as independent proof.

If current configuration mixes secret and non-secret fields, record only filesystem metadata and mark semantic configuration validation unavailable until a safe split/projection is designed and implemented.

### 5.4 Excluded mutable state

Do not include these files in the release code inventory:
- Databases and user records.
- Vault, Documents, Gallery content, ciphertext objects, wrapped keys, or metadata databases.
- PHP session files and session stores.
- Application logs, security logs, access logs, and audit event stores.
- Cache files, generated thumbnails, icon caches, temporary uploads, and runtime caches.
- Backups, restore staging, update downloads, update staging, and rollback copies.
- Lock files and ephemeral challenge/replay state.
- User-created documents or arbitrary uploads.
- Secret-bearing configuration and all private key/recovery material.

These exclusions are explicit policy entries with reasons and approved logical roots. They are not wildcards that allow an executable file to be hidden anywhere. Unexpected PHP/executable files in code directories remain a failure.

TUF root metadata is public trust metadata rather than a secret. Its version/digest may be recorded as a separate trust-state observation, but it is not application release code and must not be confused with the phone's independent trust store.

## 6. Consistency and race protection

A deployment may change while a verifier reads files. A report must not combine files from two different release states and claim an atomic snapshot.

Preferred:
- Measure a provider-controlled immutable snapshot with a unique snapshot ID and timestamp.

If only restricted SFTP is available:
1. Read the deployed VERSION marker and required release-state metadata before scanning.
2. Read all manifest-listed files and bounded directory inventories.
3. Read the VERSION marker and release-state metadata again.
4. Require the before/after values to match the same authorised release.
5. Where practical, re-read security-critical files or their metadata to detect mutation during the scan.
6. If any file changes, a symlink target changes, a path appears/disappears, or a read fails during measurement, discard the run and report inconsistent/unavailable.
7. Do not treat a successful local application updater lock check as independent proof that no update is in progress.

This is a best-effort consistency check, not an atomic snapshot. The report must label the source channel and consistency guarantee. If policy requires an atomic deployment view and the provider cannot supply one, private runtime status is insufficient for full pass.

## 7. Unexpected files and directory enumeration

A manifest proves only the files it lists. Private measurement must also address unexpected executable files in approved code roots.

The host profile defines bounded directory roots that may be enumerated. For each:
- Enumerate entries using a read-only channel.
- Apply explicit allowlists for expected files and subdirectories.
- Reject unlisted PHP, executable, autoloadable, or security-sensitive files.
- Reject symlinks and special files.
- Do not recursively enumerate excluded data, backup, log, session, upload, cache, or secret directories.
- Report unexpected path names and file metadata only; do not read arbitrary unexpected contents.
- Keep the directory enumeration policy versioned and signed independently.

An unexpected file in a code directory is a failure even if every manifest-listed file matches. If the channel cannot enumerate a required directory safely, report that directory as unmeasured and fail any policy that requires complete enumeration.

## 8. Assurance levels and report language

Use explicit assurance labels; do not collapse them into one generic green check.

| Level | Evidence | Allowed claim |
|---|---|---|
| HTTP-only | Phase 2.5 public HTTPS measurement | Public assets observed at the canonical origin match the authorised manifest at the measurement time; private runtime not measured |
| Remote read-only file service | Restricted SFTP/SSH or equivalent account-level read-only channel | Exact bytes returned by the qualified host file service matched the manifest; privileged host falsification remains possible |
| Provider-controlled snapshot | Authenticated provider snapshot/inventory outside application account control | Measured snapshot bytes matched the manifest within the documented provider trust boundary |
| Hardware/host remote attestation | Provider-supported cryptographic attestation rooted outside the application host | Only the exact claims supported by the attestation technology; never infer broader platform integrity |

The active owner policy decides which level is sufficient. If the target threat model requires resistance to a fully privileged application-host compromise, HTTP-only and account-level SFTP are not enough to claim private runtime integrity. Do not silently label either as provider-controlled or hardware-attested.

Every report must state:
- Which roots/files/directories were measured.
- Which channel and assurance level were used.
- Snapshot ID or scan consistency method.
- Which configuration checks were metadata-only.
- Which paths were excluded and why.
- Which checks were unavailable.
- Whether unexpected executable files were enumerated.
- Whether the active policy considers the resulting evidence sufficient.

## 9. Existing legacy code assessment

The repository contains a former A/B private-host protocol:
- PrivateHostAttestationCollector runs on the application host and reads configured public/private inventories.
- PrivateHostAttestationRequestHandler authenticates A/B bearer tokens and consumes nonces.
- PrivateHostAttestationClient sends a bounded request to the application origin.
- PrivateHostAttestationGate binds a node-specific transport, collector public key, and pinned file/config digests.

This is not the target HelioHost architecture:
- It is A/B-specific, not a single HelioHost verifier contract.
- The collector runs on the application host; it does not independently inspect the host from HelioHost.
- Its signing key and collector policy are in the application-host boundary.
- The former privateConfig inventory hashes config files; that is unsafe for mixed secret-bearing configuration and is not adopted by this design.
- The bearer-token HTTP request handler is an application-host endpoint, not a provider-controlled read-only snapshot or isolated HelioHost worker.
- It cannot prove that a privileged application-host attacker has not modified the collector, key, policy, or response.

Reuse only generic safe patterns after review: bounded request parsing, nonce single-use semantics, safe path validation, file metadata checks, and detached signature envelope parsing. Do not reuse the old A/B identities, tokens, collector signing key, or private-config hashing contract.

The owner confirmed no legacy nodes were ever provisioned. These components remain repository code/regression history only; no service is to be deployed from the old contract.

## 10. Host qualification gate

Before selecting a private inspection channel, obtain evidence for:

### Application host capabilities
- [ ] Provider supports a dedicated read-only account or provider-controlled snapshot/export.
- [ ] The account can be restricted to approved code roots and cannot read user content, sessions, secrets, backups, or logs.
- [ ] Write, rename, delete, chmod, shell, command execution, port forwarding, and privilege escalation are denied.
- [ ] Host key/fingerprint can be authenticated and pinned independently.
- [ ] Directory enumeration, symlink detection, file metadata, and exact file reads are supported.
- [ ] The inspection identity and credential are not accessible to the SentryIQ PHP process.
- [ ] Host file reads can be made sufficiently consistent during an update.
- [ ] Provider-level guarantees about privileged host/operator compromise are documented.

### HelioHost capabilities
- [ ] Outbound connection and host-key validation are available.
- [ ] Private credentials can be stored outside webroot and are readable only by the isolated worker.
- [ ] Worker policy, allowlists, evidence store, and signing key are protected from public intake/report handlers.
- [ ] Connection timeouts, size limits, rate limits, and audit logs are enforceable.
- [ ] The verifier can retain evidence without storing private file contents or secrets.

### Security validation
- [ ] Attempted write/rename/delete/chmod/command operations fail.
- [ ] Symlink, path traversal, hardlink, path race, and concurrent update tests are completed.
- [ ] An application-account compromise cannot read the verifier credential or alter verifier policy.
- [ ] A privileged host compromise limitation is documented; do not overstate the assurance.
- [ ] No test exposes user data, secret config, private keys, recovery material, or session state.

If any required property cannot be proven, the corresponding private measurement class is unavailable. Do not deploy an unsafe collector to fill the gap.

## 11. Acceptance tests

1. Manifest-listed PHP file with exact bytes passes; one-byte modification fails.
2. Missing, duplicate, extra, or wrong-version code file fails.
3. Symlink, hardlink escape, special file, traversal path, case collision, or race during read fails.
4. Private dependency archive and installed tree must match the approved digest inventory.
5. Private autoloader resolving inside webroot fails.
6. Private data root resolving inside webroot or with unsafe permissions fails.
7. Secret-bearing config is never opened, hashed, logged, or returned.
8. Metadata-only config checks disclose no values and cannot be satisfied by an application-generated status response.
9. Unexpected executable files in approved code roots fail.
10. Excluded mutable state is not traversed or copied.
11. Restricted read-only account cannot write, rename, delete, chmod, execute commands, or access excluded directories.
12. Host key mismatch fails before any file read.
13. Update during scan causes inconsistency failure; no mixed release is reported as pass.
14. SFTP result is labelled account-level evidence, not provider snapshot or remote attestation.
15. Unavailable private channel produces an insufficient-evidence report when policy requires private inspection.
16. A report never includes file contents, secrets, credentials, session IDs, or private config values.

## 12. Completion and next step

Phase 2.6 is complete as an inspection-boundary design. It defines file classes, logical roots, read-only channel options, secret/config exclusions, consistency requirements, unexpected-file enumeration, assurance levels, legacy A/B collector limitations, qualification gates, and adversarial tests.

Next: Phase 2.7 defines the exact challenge-bound verifier report schema, signature envelope, freshness/expiry, replay protection, status taxonomy, outage semantics, and report verification requirements. No host provisioning, source implementation, private-file probing, credential creation, or key generation is authorised.
