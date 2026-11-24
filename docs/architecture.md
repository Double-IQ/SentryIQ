# SentryIQ Repository Architecture

This document records the repository organization and the boundaries between public endpoints, internal application domains, shared platform services, the cloud layer, private runtime data, assets, diagnostics, and documentation.

## Product architecture

SentryIQ is organized as a private personal information and content platform.

Its user-facing domains are intentionally independent:

- **Vault** — secure structured information such as passwords, credentials, and other protected records.
- **Documents** — private documents and file content.
- **Gallery** — personal media, including photos, videos, audio, and albums.
- **Contacts** — a future personal contacts domain for imported and manually managed address-book data.

The architecture is designed so additional personal-content domains can be introduced without restructuring the existing application.

## Repository boundaries

```text
SentryIQ/
├── app/
│   ├── Auth/
│   ├── Security/
│   ├── Vault/
│   ├── Documents/
│   └── Gallery/
│       └── media capabilities can expand here
├── assets/
│   ├── css/
│   ├── js/
│   └── images/
├── cloud/
├── diagnostics/
├── docs/
├── private_data/
└── public PHP pages, compatibility routes, and required bootstrap files at repository root
```

A future shared `app/Core/` area may hold genuinely cross-domain primitives such as storage abstractions, metadata, search, audit helpers, or common file handling. It should only be introduced when those responsibilities are shared by multiple domains.

A future `app/Contacts/` domain can be added when contact import/storage is implemented. Contacts are deliberately not placed under Gallery because they represent structured personal data rather than media.

## Public HTTP entry points

The deployed application currently serves its public PHP pages and dynamic endpoint URLs from the repository root.

Migrated endpoint implementations live under `app/`, while `.htaccess` preserves established public endpoint URLs through internal rewrites. This keeps browser, form, bookmark, and integration URLs stable while reducing duplicate implementation files at the root.

Only files that are genuine public pages, required shared bootstrap includes, diagnostic entry points, or other actual public resources should remain at the root.

## Internal application code

Application implementation is grouped by domain and platform responsibility.

- `app/Auth/` contains authentication and access-flow implementation.
- `app/Security/` contains security bootstrap, auditing, logging, and security services.
- `app/Vault/` contains vault records, category/folder handling, and vault-specific UI modules.
- `app/Documents/` contains document application services.
- `app/Gallery/` contains gallery and personal-media application services. It is intentionally broader than photos so video and audio can be introduced without creating unrelated top-level media applications.
- `app/Contacts/` is reserved for a future contacts domain.

## Cloud layer

`cloud/` remains intentionally separate from `app/`. It contains reusable SentryIQ Cloud/domain services and storage components.

The local application layer may depend on cloud services where appropriate, but local HTTP/application concerns should not be collapsed into the cloud service tree.

## Runtime and private data

Vault encryption data, runtime configuration, authentication tokens, throttling records, audit logs, media/document storage, and generated private assets are runtime concerns.

They must remain outside tracked application code and outside public static assets.

The tracked `private_data/` directory is source/template material for controlled deployment of private runtime components; the active runtime data directory is determined by the installed SentryIQ configuration.

## Assets

Static CSS, JavaScript, and images live under `assets/`.

Where an existing public asset URL must remain stable, `.htaccess` can preserve that URL while the tracked file lives under the organized assets tree.

## Diagnostics

`diagnostics/` contains diagnostic and troubleshooting scripts and is deliberately kept separate from normal application execution paths.

The public `sentryiq_diagnostic.php` entry point remains available so the deployed installation can run the diagnostic suite.

The diagnostic is part of the operational safety net for structural cleanup: changes should not remove or bypass it, and migrations should keep its filesystem, source-reference, and browser URL checks aligned with the repository structure.

## Security architecture references

The active device-rooted trust model, master-device lifecycle, independent HelioHost verifier, cryptographic release verification, and offline recovery design are documented in:
- [Device-Rooted Security Architecture](architecture/device-rooted-security-architecture.md)
- [Design and Implementation Plan](architecture/design-implementation-plan.md)
- [Legacy Topology Disposition](architecture/legacy-topology-disposition.md)

The former A/B private-host attestation contract is historical only; see [its superseded status](security/private-host-attestation-contract.md).

## Migration principles

- Keep public URLs stable unless a routing migration is explicitly planned.
- Move implementation behind organized application paths while preserving compatibility where practical.
- Map dependencies before moving a file.
- Preserve existing file bytes when a move does not require content changes.
- Make small, reversible changes and verify each migration before continuing.
- Keep the local application layer separate from the cloud service layer.
- Keep secrets and runtime data out of Git.
- Treat diagnostics as protected operational infrastructure.
