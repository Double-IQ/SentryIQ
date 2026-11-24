# Phase 1.2 — Protected-data classification and plaintext-location policy

**Status:** Repository-backed design artifact complete; owner/design review remains required.  
**Baseline:** `main` after merge of PR #151.  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Application host:** Existing SentryIQ host; treated as potentially compromised for user-data confidentiality and authority.  
**Independent security node:** One specialised HelioHost verifier; it receives no user plaintext or user-data keys.  
**Scope:** Classify protected information, record current repository storage/processing paths, define permitted plaintext locations, and state target handling requirements. This is a design/audit document, not an implementation or deployment approval.

## 1. Executive findings

1. The Vault uses authenticated encryption at rest, but its current server-side unlock path decrypts records in PHP and places the 32-byte Vault Master Key (VMK) in the PHP session. This is not client-only or zero-knowledge storage against the application host.
2. Documents are encrypted by PHP after multipart upload. Raw document bytes therefore exist in PHP upload temporary storage, PHP memory, and the download response path. The server also stores document names, MIME type, extension, size, and creation time as plaintext metadata.
3. The current Secure Gallery path is materially different: browser code prepares images and metadata, encrypts each object locally, and uploads ciphertext directly to Backblaze B2. PHP stores object identifiers, object keys, sizes, key IDs, and wrapped DEK envelopes, and issues short-lived signed object URLs. This is the intended zero-knowledge direction, but browser execution and the remaining legacy Gallery classes must be treated as part of the security boundary.
4. The separate Vault passkey implementation sends the WebAuthn PRF output to PHP. PHP derives a wrapping key, unwraps the VMK, and establishes a session containing the VMK. The Gallery-specific passkey flow is separate and must not be conflated with this older Vault passkey flow.
5. Private runtime configuration, passkey records, Gallery key envelopes, object indexes, throttling state, audit logs, and encrypted Vault/Document objects are designed to live under a protected data directory outside the public web root. This is a filesystem boundary, not protection against a compromised application process or host administrator.
6. Logs and metadata can reveal account identifiers, IP addresses, user agents, filenames, MIME types, sizes, object counts, access times, and operational behaviour. These are not harmless merely because they are not content plaintext.
7. The backup/restore runbook specifies encryption before off-host transfer and a coordinated recovery set, but the repository explicitly records that no automated backup integration or verified restore exists. No backup, retention, or restore control is claimed as operational here.
8. The current PHP session configuration sets secure cookie attributes and timeouts, but the application does not select or verify the PHP session save handler/path. Because the session contains the VMK, the actual server-side session storage and its backup/log exposure remain a deployment qualification item.

## 2. Classification scheme

| Class | Description | Examples | Minimum handling |
|---|---|---|---|
| **P0 — Public** | Intended for unrestricted publication | Public application assets, public documentation, public release manifests and public keys | Integrity/provenance controls; no secrets or private user data |
| **O1 — Operational metadata** | Data that describes accounts, objects, access, or system operation but is not itself the protected content | Usernames, email address, IP, user agent, timestamps, object IDs, object sizes, MIME type, filenames, key IDs, rate-limit state, audit events | Minimise, validate, restrict access, set retention, avoid unnecessary correlation; keep private where it can identify a user or reveal activity |
| **C2 — Confidential user content** | User-created or user-supplied information whose disclosure is harmful | Vault records, passwords, notes, URLs, documents, photos, captions, album names, private image metadata | Encrypt on the authorised device before transmission/storage; plaintext only in an authorised device's active execution context; no server-side plaintext persistence |
| **S3 — High-value security secrets and key material** | Material that enables decryption, impersonation, recovery, or privileged service access | VMK, DEKs, Gallery root key, Gallery private keys, passkey PRF output, recovery secrets, master-device private key, verifier signing key, release signing key, B2 application key, session credentials | Role separation, least privilege, no logging, no repository/chat storage, narrowly bounded lifetime, protected platform or isolated service custody; never give user-data keys to the application host or verifier in the target architecture |
| **R4 — Recovery and backup material** | Material whose loss or disclosure can compromise or permanently destroy recoverability | Recovery keys, encrypted recovery envelopes, complete backup archives, backup encryption keys, MEGA session state, B2 object-version inventory | Separate custody and failure domain; encrypt before transfer; no public links; verify integrity and restore; retain only under an owner-approved policy |

Classification is based on the highest sensitivity of the data itself, not the filename or storage format. An encrypted backup remains R4 because it may contain the whole application state and may become readable when combined with separately held keys.

## 3. Repository evidence — current implementation

### 3.1 Vault

**Relevant code:** `private_data/vault_engine.php`, `app/Auth/AuthFlow.php`, `app/Vault/*`, `app/Security/SecurityBootstrap.php`, `app/Security/FirstRun.php`.

- The main encrypted store is `passwords.enc` under `SENTRYIQ_DATA_DIR`; the Vault envelope records format/KDF/cipher metadata, salt, nonce, tag, ciphertext, password key-wrap, and optional recovery wrapper.
- The implementation derives a 32-byte key with Argon2id13 (libsodium) and uses AES-256-GCM for VMK wrapping and Vault-record encryption. The VMK is 32 bytes. Record JSON is encrypted as one Vault payload; normalised records include labels, categories, folders, usernames, passwords, URLs, notes, timestamps, icon metadata, and a system-configuration record with username, 2FA email, and IMAP password field.
- Password unlock decrypts the Vault payload in PHP. `vault_unlock()` returns both the VMK and normalised plaintext records. `load_passwords()` decrypts the records in PHP using either the explicit VMK or `$_SESSION['master_key']`.
- The login flow stores the VMK in PHP session state after the password/2FA flow; recovery login also unwraps the VMK in PHP and marks the session authenticated.
- Consequently, the encrypted file protects against disclosure of the file alone without a password/recovery secret, but it does not protect plaintext from the application process, a compromised PHP runtime, or an attacker able to read the active authenticated session.
- The first-run process creates a random recovery key, stores a recovery wrapper in the Vault envelope, verifies it, and places the displayed recovery value in `$_SESSION['first_run_recovery_key']` for the first-run ceremony. The recovery secret is not meant to be persisted server-side as a usable secret. Its display/session lifecycle and any PHP session persistence are sensitive.
- Vault writes use a random temporary file followed by rename and owner-only mode (0600). Temporary files contain the encrypted envelope, not the decrypted records. The code does not establish secure erasure of old filesystem blocks or storage snapshots.

**Classification:** Vault content C2; VMK/password/recovery key S3/R4; envelope metadata O1; encrypted Vault file C2-protected ciphertext.

### 3.2 Vault passkeys and authentication

**Relevant code:** `app/Auth/PasskeyAuth.php`, `app/Auth/WebAuthnChallenge.php`, `app/Auth/WebAuthnCose.php`, `app/Auth/AuthFlow.php`.

- `passkeys.json` stores credential IDs, public keys, username, wrapped VMK envelope (nonce, tag, ciphertext), PRF salt, signature counter, and creation time. The stored VMK wrapper is ciphertext; credential IDs, public keys, username, salt, counter, and timestamps are metadata.
- The Vault passkey browser flow submits the PRF output to PHP. PHP derives a wrapping key with HKDF-SHA-256, unwraps the VMK with AES-256-GCM, and calls the authenticated-session path. This is not a client-only Vault key flow.
- PHP sessions hold the active VMK and temporary authentication values. In the password/2FA flow, the pending VMK, six-digit 2FA code, username, attempt state, and a copy-code token are placed in session state. A temporary token file stores the 2FA code and expiry; its random token appears in the copy-code URL fragment.
- Session cookies are configured Secure, HttpOnly, SameSite=Strict, and the application enforces idle and absolute timeouts. The app does not set or validate `session.save_handler` or `session.save_path`; the actual server-side session storage must therefore be qualified separately.
- Passkey store writes use owner-only file permissions and atomic temporary-file replacement. Security events include username, IP, user agent, and caller-supplied context. The event logger must never receive credential payloads, PRF output, VMK, passwords, or 2FA values.

**Classification:** passkey metadata O1; wrapped VMK C2/S3-protected ciphertext; PRF output and unwrapped VMK S3; active PHP session S3; 2FA code/copy token S3 while valid.

### 3.3 Documents

**Relevant code:** `app/Documents/Upload.php`, `app/Documents/Download.php`, `cloud/Documents/DocumentStore.php`.

- Upload accepts multipart files up to 100 MiB and validates the detected MIME type against an allowlist.
- PHP receives the uploaded file in its upload temporary location, reads it into `$raw`, then encrypts it with the VMK using AES-256-GCM and a document-ID-bound AAD context.
- The persisted file under the private documents directory is the encrypted envelope. The metadata index is plaintext JSON and stores original filename, generated filename, MIME type, extension, byte size, and creation time.
- Upload failures write a private log line containing the original basename and exception class/message.
- Download reads ciphertext, decrypts it in PHP to `$contents`, and emits the plaintext document in an HTTP response. The response uses private/no-store cache control, but the application server necessarily handles plaintext.
- Thus Documents are encrypted at rest but are not end-to-end encrypted in the current PHP upload/download path. A compromise of the application process or active VMK session can expose document content.

**Classification:** document bytes C2; VMK S3; metadata O1/C2-sensitive (filename and MIME can disclose content); encrypted file C2 ciphertext; PHP upload temp, PHP memory, and download response are transient plaintext locations that must be removed from the target design.

### 3.4 Secure Gallery — current browser-encrypted path

**Relevant code:** `assets/js/gallery_crypto.js`, `assets/js/gallery_storage.js`, `app/Gallery/StorageAuthorization.php`, `app/Auth/GalleryPasskeyAuth.php`, `cloud/Gallery/Storage/GalleryObjectStore.php`, `cloud/Gallery/Storage/GalleryKeyStore.php`, `cloud/Gallery/Storage/GalleryKeyring.php`, and the Gallery ADRs.

- The browser generates a Gallery identity using RSA-OAEP-3072/SHA-256, a random 256-bit Gallery root key, and a private-key JWK encrypted under that root key with AES-GCM.
- The root key is wrapped separately for each Gallery passkey using a Gallery-specific PRF output and HKDF-SHA-256. A separate recovery envelope wraps the root key with a user-held recovery secret. Gallery-specific passkey and recovery flows are distinct from the Vault passkey VMK-unwrapping flow.
- Each Gallery object role (original, thumbnail, preview, metadata) gets a fresh random 256-bit AES-GCM DEK and 96-bit nonce. The DEK is wrapped to the Gallery RSA public key using RSA-OAEP-256. AAD binds the ciphertext to the photo ID and role.
- The browser decodes/prepares images, creates derivatives, constructs private metadata (including filename, source MIME, album, dimensions, and timestamps), encrypts all four roles, and uploads ciphertext directly to B2 with credentials omitted from the browser request. The browser code clears several plaintext buffers and canvas dimensions, but JavaScript zeroing is best-effort and cannot guarantee erasure of engine copies, GPU memory, OS swap, crash dumps, or device backups.
- PHP allocates opaque photo IDs and opaque B2 object keys, signs short-lived (300-second) object-scoped PUT/GET/DELETE URLs, validates object sizes/envelope shapes, and stores a private object index. The index contains status, creation/upload timestamps, key ID, object role/key, ciphertext size, and the envelope (algorithm/version, nonce, wrapped DEK, photo ID, role, key ID). It does not need plaintext filename, album, caption, or image dimensions.
- The Gallery metadata object is itself encrypted and stored in B2 as ciphertext. B2 receives ciphertext and generic octet-stream uploads; the B2 application key and signing capability remain in private server configuration.
- Gallery key storage contains public RSA keys, encrypted private-key envelopes, passkey-wrapped root-key envelopes, and an encrypted recovery envelope. The server does not need a plaintext Gallery root key, private key, DEK, PRF output, or recovery secret.
- Object count, opaque identifiers, role, ciphertext size, key IDs, timing, access patterns, and signed-URL issuance remain visible to the application host and/or storage provider. Short URL expiry limits exposure but does not eliminate logs, browser history/telemetry, or URL leakage risk.
- The current object-list endpoint returns object records and envelope metadata to an authenticated browser. Treat the object index and envelopes as private operational metadata, not public data.

**Classification:** photo and private metadata plaintext C2 in authorised browser memory; Gallery root/private keys and DEKs S3; recovery secret R4/S3; public keys and wrapped envelopes C2-protected metadata; object index, key IDs, sizes, timestamps, access patterns O1; B2 credentials S3 service secrets.

**Legacy Gallery code still present:** `cloud/Gallery/Storage/PhotoStorage.php`, `PhotoMetadataStore.php`, and `DuplicateIndex.php` implement an older server-side path that hashes content and stores plaintext names/hash metadata while PHP encrypts image bytes with the VMK. The Gallery zero-knowledge ADR explicitly requires old server-side upload/image-decryption paths to be replaced or disabled before cutover. Their presence means the repository still contains legacy paths; this audit does not assert that all such code has been deleted. Preserve until all consumers/tests are traced and replacement coverage is proven, but do not enable these classes as a fallback in the target design.

### 3.5 Logs, diagnostics, throttling, and errors

**Relevant code:** `private_data/vault_engine.php`, `app/Auth/PasskeyAuth.php`, `app/Auth/ThrottleStore.php`, `app/Security/BoundedLog.php`, `app/Security/FirstRun.php`, `app/Security/SecurityLog.php`, `app/Security/SystemLog.php`.

- Security events record timestamp, event name, username, IP, user agent, and context. Vault log rotation is bounded and applies owner-only permissions; `BoundedLog` also requires a private path when the path-check helper is available.
- Passkey logging has a separate append path and may fall back to PHP `error_log`. Some exception handlers log exception class/message. Gallery storage logs exception class; its JSON response returns an exception message to the caller.
- Document upload logs include original filename and exception message. First-run diagnostic logs include stage, PHP version/SAPI, configured-path indicators, data-file path, record count, and failure details.
- Authentication throttle state is stored privately as JSON keyed by a hash of scope and IP; it records counts and timestamps rather than the raw IP as the index key.
- Logs, diagnostic files, and throttle state are operational metadata. Arbitrary context/message fields can accidentally carry secrets or user content unless the logging contract is allowlisted.
- Server/provider web access logs, PHP-FPM logs, mail logs, object-storage access logs, and hosting backups are outside the inspected application logger implementation. Their exact fields, access controls, retention, and redaction are unknown and must not be assumed safe.

**Classification:** O1, with S3 exposure if secret-bearing context or exception text is written. Logs must never contain C2 content, credentials, key material, signed URLs, session IDs, recovery codes, or request bodies.

### 3.6 Configuration and runtime state

**Relevant code:** `app/Security/SecurityBootstrap.php`, `app/Security/FirstRun.php`, `app/Auth/PasskeyAuth.php`, `app/Gallery/StorageAuthorization.php`.

- The application resolves `SENTRYIQ_DATA_DIR` from private configuration and checks that the real path is outside `DOCUMENT_ROOT`. First-run setup prepares a private directory and writes private runtime files/configuration with restrictive modes.
- The generated private configuration contains account username, 2FA email, canonical base URL, data directory, and private dependency/autoloader path. Runtime configuration also supplies service credentials such as Backblaze B2 signing credentials and other integration secrets.
- Public application source contains code and public assets; it must not contain real private configuration, credentials, production keys, or recovery material. A root pointer/config file may reveal a private filesystem path; it is not itself a user-data key, but should remain non-disclosing and be included in release/inventory policy.
- The protected runtime directory contains a mixture of encrypted user-data files, metadata indexes, key envelopes, logs, temporary files, configuration, dependency bundles, and possibly PHP session files depending on the hosting PHP session configuration. These categories must not be treated as one homogeneous “encrypted data” directory.

**Classification:** account identifiers/config values O1; service credentials S3; protected runtime contents retain their individual classifications; private dependency bundle integrity is security-sensitive operational data.

### 3.7 Backups and recovery sets

**Relevant source:** `docs/operations/backup-restore-runbook.md`.

- The runbook requires encryption before off-host transfer and a recovery set containing application release, root configuration, protected runtime directory, and B2 objects with object-version inventory.
- It calls for a separate backup encryption key, private MEGA destination, unique immutable-by-convention generations, checksums/manifests, and isolated restore validation.
- The same runbook explicitly states that automated backup integration, encryption/key management, and verified restore are not currently implemented; no cPanel backup or cron job has been created. Accordingly, backup controls are target requirements, not current guarantees.
- A full-account cPanel archive can include unrelated files, mail, databases, configuration, private keys, and credentials. Treat it as R4 and encrypt it locally before any off-host transfer. Do not place it under the web root, email it, or create public links.
- A backup that contains only Vault ciphertext but omits the corresponding authorised recovery material is not a complete recovery set. A Gallery recovery set must include the matching encrypted B2 object versions and key-envelope metadata, while keeping usable recovery secrets separate.

**Classification:** complete backup archive R4; backup encryption key S3/R4; encrypted Vault/Documents/Gallery objects C2 ciphertext; B2 and runtime inventories O1/C2-sensitive; recovery secret R4/S3.

## 4. Plaintext-location policy

### 4.1 Target permitted locations

| Data | Permitted plaintext location | Prohibited locations |
|---|---|---|
| Vault records and secrets | Authorised device memory while unlocked and actively used | Application PHP process, PHP session, application-host disk, verifier, logs, server backups |
| Documents | Authorised device memory during selection, encryption, viewing, or editing | PHP upload temp, PHP memory, server filesystem, server download/decryption path, verifier |
| Gallery photos and private metadata | Authorised browser/device memory while preparing, encrypting, viewing, or editing | PHP request body, PHP memory, server temp, application logs, B2, verifier |
| Gallery DEKs/private keys/root key | Authorised device cryptographic execution context; protected device/passkey/recovery wrapping as designed | PHP, application session, server logs, B2, verifier, localStorage, IndexedDB, unencrypted exports |
| Master-device private key | Master phone's platform-protected key store or approved secure hardware | Application host, HelioHost, repository, browser page JavaScript export |
| Recovery secret | Owner-controlled offline recovery medium; briefly in the local recovery ceremony | Either server, PHP session, logs, backup archive, chat, repository |
| Release/verifier signing keys | Their separate protected signing boundaries only | Application data store, user device data, repository plaintext, logs |
| B2 and other service credentials | Private server runtime configuration and the narrowly scoped service process that needs them | Browser, public source, logs, user-data envelope, HelioHost verifier |

### 4.2 Temporary plaintext is still plaintext

The target policy applies to transient copies, not just persisted files. It covers:
- PHP upload temporary files and multipart request bodies;
- PHP variables, output buffers, exception objects, and decrypted response bodies;
- PHP session serialization, session backups, crash dumps, swap, and host snapshots;
- browser `File`, `Blob`, `ImageBitmap`, canvas/GPU surfaces, `ArrayBuffer`, typed arrays, WebCrypto inputs/outputs, decoded image elements, Blob URLs, and browser process memory;
- clipboard, print spool, downloads, OS previews, photo-library caches, device backups, and screenshots created by the user or operating system;
- temporary files created during atomic writes, migration, export, restore, or backup packaging.

The application can reduce lifetime and avoid intentional persistence, but JavaScript buffer overwriting is best-effort. The platform may retain copies outside application control. A compromised browser, operating system, same-origin script, malicious extension, or injected dependency can observe plaintext while it is in use.

### 4.3 Current deviations to close

1. Vault plaintext is decrypted in PHP and the VMK is stored in PHP session state.
2. Vault passkey PRF output is sent to PHP; PHP unwraps the VMK.
3. Documents arrive at PHP as plaintext multipart uploads and are decrypted in PHP for downloads.
4. Legacy Gallery server-side upload/decrypt classes remain in the repository and must be proven unreachable/retired before the zero-knowledge cutover is accepted.
5. PHP session storage location/handler and host-level session backup/log exposure are not specified by application code.
6. Server/provider logs and hosting backup contents/retention have not been inspected; do not claim they exclude sensitive values.
7. Browser memory erasure cannot be guaranteed; the target must minimise plaintext lifetime and explicitly document device/browser compromise limits.

## 5. Metadata that remains visible

Even when content encryption is correctly implemented, the application host and/or storage provider may still observe:
- account identity and authentication events;
- IP address, user agent, request timing, approximate location derived from IP, and session activity;
- number of Vault/Document/Gallery objects and their opaque identifiers;
- object sizes, object roles, key IDs, creation/upload times, and access frequency;
- MIME type or filename where a legacy path or endpoint exposes it;
- presigned URL issuance, object-store host, request method, expiry, and access pattern;
- release version, client version, device public identifiers, and operational error categories.

Target minimisation:
- use opaque random object identifiers and generic content types;
- encrypt filenames, album names, captions, MIME details, dimensions, and document metadata where practical;
- avoid plaintext content hashes and cross-user deduplication unless equality leakage is explicitly accepted;
- avoid exposing key IDs or envelope contents beyond authenticated key-management endpoints;
- keep logs allowlisted, coarse, bounded, access-controlled, and retention-limited;
- do not claim metadata confidentiality where a field is necessarily used for routing, quotas, or storage operations.

## 6. Storage and handling requirements

1. **Encryption boundary:** client-side authenticated encryption must occur before any user content reaches the application host. The server stores ciphertext, public keys, wrapped DEKs, encrypted metadata, and strictly necessary operational metadata only.
2. **Key separation:** VMK/DEK, Gallery root/private keys, master-device identity, per-device keys, recovery keys, release signing, verifier signing, and service credentials are distinct roles. No shared key or “master” secret may silently serve several roles.
3. **Session boundary:** application sessions contain authentication state and short-lived protocol nonces only. They must not contain VMK, plaintext DEKs, Gallery root/private keys, recovery secrets, PRF outputs, or decrypted user records. Server session storage must be private, bounded, and excluded from public paths/logs/backups unless encrypted under an independently held backup key.
4. **Upload/download:** application endpoints accept ciphertext and bounded metadata only. No PHP plaintext upload temporary file or server-side decrypt/stream path is permitted for protected user content.
5. **Logs:** define typed event schemas and field allowlists. Redact request bodies, passwords, filenames where unnecessary, tokens, signed URLs, cookies, session IDs, recovery material, ciphertext payloads, and exception text that can contain user input. Do not log arbitrary arrays from request data.
6. **Temporary data:** use bounded memory, explicit buffer lifetime, best-effort clearing, no persistent browser storage for usable keys, and no server-side plaintext staging. Do not promise secure erasure where the runtime cannot guarantee it.
7. **Metadata:** document each visible field, purpose, access path, retention, and whether it can be encrypted. Prefer opaque IDs and coarse operational metrics.
8. **Configuration:** keep service credentials outside the web root with least-privilege scopes and restrictive permissions. No user-data decryption key is stored in application configuration.
9. **Backups:** produce an application-consistent snapshot; encrypt before leaving the source failure domain; keep the backup key separately; include matching B2 object versions and manifests; never include usable user recovery secrets in a server-controlled archive. Verify restore in isolation.
10. **Verifier isolation:** HelioHost receives no user content, DEKs, VMK, private device keys, recovery material, passkey PRF output, B2 write credentials, or application session credentials. It measures release/deployment evidence only.
11. **Exports and user actions:** explicit user-initiated export/print/copy may create plaintext outside the app boundary. Warn clearly, avoid silent exports, and do not sync unencrypted exports into server backup paths.
12. **Retention/deletion:** define deletion for active objects, temporary uploads, logs, session state, backups, B2 object versions, and stale encrypted envelopes. Deleting a pointer does not prove ciphertext or backups have been erased.

## 7. Required implementation evidence before accepting the target policy

- [ ] Vault decrypts only on authorised devices; PHP never receives VMK or plaintext Vault records.
- [ ] Vault passkey PRF output remains on the client; PHP verifies WebAuthn without unwrapping user-data keys.
- [ ] Documents use client-side encryption and ciphertext-only upload/download; server metadata is minimised/encrypted.
- [ ] Legacy Gallery server-side upload/decrypt paths are unreachable or removed only after dependency/test replacement is complete.
- [ ] Gallery current browser-encryption flow passes adversarial tests for XSS, dependency tampering, ciphertext modification, object substitution, replay, key rotation, recovery, and stale signed URLs.
- [ ] Session payload schema excludes all user-data keys and plaintext; PHP session save handler/path and host retention are verified.
- [ ] Logs, PHP/provider access logs, mail logs, and exception paths have schemas, redaction tests, access controls, and retention.
- [ ] Runtime configuration and service credentials are outside the web root, least-privileged, and excluded from public release artifacts.
- [ ] Browser storage audit confirms no usable keys or plaintext content are written to localStorage, IndexedDB, Cache Storage, service-worker caches, or browser-managed persistent stores by SentryIQ code.
- [ ] Backup generation encrypts before off-host transfer, includes a consistent runtime/B2 recovery set, separates backup keys, and has a successful isolated restore test.
- [ ] HelioHost verifier's inputs and permissions are technically constrained to deployment evidence, with tests proving it cannot access user-data stores or credentials.

## 8. Scope, limitations, and disposition

- This audit is based on tracked repository code and documentation on `main`. It does not inspect a live host, private production configuration, PHP runtime settings, provider logs, actual browser/device storage, Backblaze account configuration, or backup account contents.
- The owner confirmed that no separate legacy nodes were ever provisioned. No external-node or live-host evidence is required for this phase.
- The current repository includes both the newer browser-encrypted Gallery path and older server-side Gallery classes. This document does not assert that production is deployed or that the newer path has been validated on real iOS Safari/WebAuthn/B2 infrastructure.
- No source implementation, production configuration, credentials, keys, backup, deployment, or release baseline was changed or created by this phase.
- Phase 1.2 is complete as a repository-backed classification and policy artifact. Owner/design review is still required before treating the policy as accepted or proceeding to implementation.
