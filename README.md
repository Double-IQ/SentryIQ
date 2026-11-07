# SentryIQ

SentryIQ is a self-hosted secure digital vault for protecting credentials, documents, private images, passkeys, and security-related records in one controlled application.

It is built around a simple goal: **keep sensitive information under the owner's control while making everyday secure storage practical and efficient.**

SentryIQ combines encrypted vault storage, strong authentication, passkey-based unlocking, private document and gallery storage, security auditing, and defensive browser/server controls without requiring the user to hand the contents of their vault to a third-party hosted service.

---

## What SentryIQ Does

SentryIQ brings several security-sensitive tasks together in a single self-hosted application:

- **Credential vault** — securely store usernames, passwords, URLs, notes, categories, and related vault records.
- **Categories and folders** — organize records into logical groups so larger vaults remain easy to manage.
- **Documents** — upload, store, view, download, and delete private documents.
- **Private gallery** — upload and manage private images, albums, selections, and image-related metadata.
- **Passkeys** — register trusted passkey devices and use device authentication such as Face ID, Touch ID, or platform passkeys for vault access.
- **Password recovery authentication** — retain a password-based recovery path with temporary email verification.
- **Security auditing** — record important authentication and vault security events for accountability and troubleshooting.
- **Automatic session protection** — lock inactive vault sessions and require authentication again when appropriate.
- **First-run secure installation** — initialize the protected runtime and encrypted vault storage during installation.
- **Built-in diagnostics** — provide diagnostic tooling to help verify deployment, storage, routing, assets, and runtime health.

---

## Why SentryIQ

### Self-hosted control

SentryIQ is designed for people and organisations that want direct control over where their sensitive information is stored.

The application can be deployed on infrastructure controlled by the owner instead of requiring a third-party account or hosted vault subscription.

### One place for private information

Credentials, documents, private images, and authentication devices can be managed from the same security boundary. This reduces the need to spread sensitive material across unrelated applications and services.

### Practical security

SentryIQ is designed around layered protections rather than relying on a single security mechanism. Encryption protects the vault, authentication protects access, session controls limit exposure, request validation protects state-changing operations, and audit records provide visibility into important security events.

### Efficient deployment

The application is intentionally structured as a focused PHP application with clearly separated application domains, assets, runtime data, diagnostics, and cloud/domain services.

This keeps the deployment footprint understandable and makes it easier to maintain, diagnose, back up, and migrate without introducing an unnecessarily large application stack.

### Efficient daily use

SentryIQ is designed to keep common vault operations direct: unlock the vault, locate a record, manage information, and lock again. Categories, folders, dedicated document handling, gallery management, and passkeys reduce repetitive work while keeping security controls close to the actions they protect.

### Privacy by design

SentryIQ is intended to collect only the information required for features the owner has explicitly enabled.

**SentryIQ never sends telemetry, analytics, or usage data back to the SentryIQ project.**

Security and operational logs are generated for the local installation so the owner can understand what happened inside their own deployment.

---

# Security Features

SentryIQ uses a defence-in-depth security model. The current implementation includes the following protections.

## Vault Encryption

- The master password is **not stored in plaintext**.
- Vault encryption keys are derived with **Argon2id** using a per-vault random salt.
- The vault encryption key is 32 bytes for **AES-256-GCM** encryption.
- AES-GCM provides authenticated encryption so tampering with protected vault data is detected.
- Each vault save uses a fresh random nonce.
- Authentication data (AAD) binds important vault metadata to the encrypted content.
- The encrypted vault envelope is versioned to support controlled future format changes.

## Passkey Security

- Passkeys use the browser's **WebAuthn** platform authentication mechanisms.
- User verification is required during registration and authentication.
- SentryIQ validates the WebAuthn challenge and origin.
- Cross-origin WebAuthn is rejected.
- The relying-party identity is derived from the configured HTTPS application origin.
- Passkey vault keys are protected using the authenticator's **PRF-derived key material** and AES-256-GCM.
- The stored passkey record contains an encrypted copy of the vault key rather than the plaintext vault key.
- Passkey storage is maintained outside the public web root.
- Passkey changes are written using a temporary file and atomic rename.

## Authentication Protection

- Normal password unlock uses a temporary **email 2FA verification code**.
- 2FA codes expire after **5 minutes**.
- Password authentication failures are throttled server-side.
- 2FA verification attempts are limited and throttled.
- Successful authentication regenerates the PHP session ID.
- Pending authentication material is cleared after successful completion, expiry, lockout, or vault locking.

## Session Security

- Secure session cookies are marked **Secure**.
- Session cookies are **HttpOnly**.
- Session cookies use **SameSite=Strict** protection.
- PHP strict session mode is enabled.
- Vault sessions automatically lock after **15 minutes of inactivity**.
- Locking the vault destroys the active session.
- Security-sensitive operations can require **fresh authentication** rather than relying on an old session.

## Request and Application Security

- State-changing POST requests require a session **CSRF token**.
- Security-sensitive settings require fresh authentication.
- GET requests are not used to perform vault state changes.
- HTTPS is required for normal web access.
- Stored resource URLs are restricted to HTTPS where applicable.
- Unsafe resource URLs are rejected instead of being silently followed.

## Browser Security

SentryIQ applies defensive browser headers including:

- Content Security Policy (CSP)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- restrictive `Permissions-Policy`
- no-cache headers for security-sensitive pages

New-tab external links are also protected with `noopener`/`noreferrer` behaviour.

## Secure Runtime Storage

Sensitive runtime data is designed to live **outside the public web root**.

The installation validates the configured data directory and rejects insecure locations such as public web directories and symbolic links. Runtime files use restrictive permissions, and sensitive writes use temporary files with atomic replacement where practical.

Missing or invalid secure storage causes protected operations to fail closed rather than silently falling back to an unsafe location.

## 2FA Copy Tokens

Temporary copy-code tokens are designed so that:

- the token is cryptographically random;
- the token URL does not contain the 2FA code itself;
- token data is stored outside the public web root;
- claiming is performed atomically to reduce replay risk;
- the copy-code response is not cacheable.

## Security Auditing

Important authentication and vault security events are recorded in local audit logs.

The security audit design avoids storing PHP session IDs or plaintext vault passwords in the security event stream.

Audit records make it easier to investigate authentication problems, vault locks, passkey changes, and other security-relevant events without sending telemetry outside the installation.

## Secure First-Run Installation

The first-run process is designed to establish the security boundary before normal vault use:

- secure runtime storage is prepared before protected data is written;
- the vault encryption material is generated during installation;
- runtime support files are copied into protected storage;
- the vault is written and then directly verified;
- the installation configuration records the protected runtime location;
- post-install runtime checks verify that the configured storage is usable.

## Diagnostics and Operational Visibility

SentryIQ includes dedicated diagnostic tooling so deployment problems can be investigated without exposing the vault contents.

The self-test tooling can inspect:

- PHP and HTTPS state;
- configuration and runtime storage;
- required application files;
- public entry points;
- application implementations;
- CSS, JavaScript, and image assets;
- browser-accessible URLs and HTTP responses.

Diagnostic reports are designed to exclude passwords, master keys, encrypted vault contents, and authentication tokens.

---

## Security Boundary

SentryIQ is designed to provide strong protection **within its application threat model**, but no application can protect data from a fully compromised host.

A compromised server, operating system, PHP runtime, administrator account, browser session, or configured 2FA email account can undermine protections that depend on that environment.

Security therefore depends on the complete deployment: the application, the server, the filesystem permissions, the hosting environment, the administrator, and the authentication devices used to access the vault.

---

## Repository structure

```text
SentryIQ/
├── app/          # Internal application code grouped by responsibility
├── assets/       # Shared static browser assets
├── cloud/        # SentryIQ Cloud/domain services
├── diagnostics/  # Diagnostic and troubleshooting tools
├── docs/         # Architecture and project documentation
└── *.php         # Public pages/endpoints and required bootstrap files
```

## Application code

The internal application layer is organized into domain areas:

- `app/Auth/` — authentication, passkeys, and access-flow logic.
- `app/Vault/` — vault records, categories, folders, and vault UI modules.
- `app/Documents/` — document-related application services.
- `app/Gallery/` — gallery-related application services.
- `app/Security/` — security bootstrap, auditing, first-run installation, and shared security services.

Public HTTP URLs remain stable for compatibility while implementations are organized under `app/`. Root-level PHP files may remain where they are still required as public entry points or compatibility/bootstrap files.

## Assets

Browser assets are organized under `assets/css/`, `assets/js/`, and `assets/images/`.

## Cloud layer

The `cloud/` directory remains separate from the local application layer. It contains reusable SentryIQ Cloud/domain services and storage components.

## Private data

Runtime vault data, configuration, encryption material, passkey data, tokens, throttling data, audit logs, and generated private assets are kept outside public application code. Runtime secrets must never be committed to the repository.

## Diagnostics

Operational and troubleshooting tools live under `diagnostics/` and are kept separate from normal application code.

## Documentation

Architecture decisions are recorded under `docs/adr/`. Repository structure and migration decisions are documented in `docs/architecture.md`.

---

## Credits and acknowledgements

SentryIQ is built with help from a wider ecosystem of tools, standards, services and communities. With thanks to:

- [Backblaze](https://www.backblaze.com/cloud-storage) — Backblaze B2 is the planned object-storage home for encrypted Gallery photos.
- [OpenAI](https://openai.com/) — ChatGPT assistance with planning, architecture, implementation and technical review.
- [Git](https://git-scm.com/) — distributed version control.
- [GitHub](https://github.com/) — repository hosting, issue tracking, collaboration and automated checks.
- [Linux](https://www.linux.org/) — the Linux ecosystem and its open-source contributors.
- [PHP](https://www.php.net/) — the server-side language and runtime.
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — browser-native cryptographic primitives.
- [W3C WebAuthn](https://www.w3.org/TR/webauthn-3/) and the [FIDO Alliance](https://fidoalliance.org/passkeys/) — open standards and ecosystem work behind passkey authentication.

These are acknowledgements of tools, services or contributions, not claims of sponsorship, endorsement or official partnership. Names and trademarks belong to their respective owners.

A fuller acknowledgements page is available in the application at [Credits & Acknowledgements](credits.php).

---

## Project philosophy

SentryIQ is being developed with a simple principle:

> **Security should be strong enough to matter, practical enough to use, and transparent enough to understand.**

The goal is not to add security theatre or unnecessary complexity. The goal is to build a focused tool that protects sensitive information, gives the owner control of their data, and makes the security decisions visible and understandable.
