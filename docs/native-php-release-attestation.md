# Native PHP release attestation and updater

## Trust path

SentryIQ's updater verifies a release ZIP in PHP without GitHub CLI, shell
execution, exec(), or proc_open(). The native verifier uses:

- k2gl/sigstore-verify 1.6.1 for Sigstore bundle, certificate, and Rekor verification;
- k2gl/tuf 1.2.1 with the pinned SentryIQ root-rotation 404 patch;
- the GitHub Actions OIDC issuer and the exact release workflow identity
  .github/workflows/release.yml;
- the SLSA provenance source repository, tag, source commit, workflow commit,
  repository ID, hosted-runner context, and exact ZIP SHA-256;
- an independent GitHub tag-to-commit resolution and the release trust policy.

The adjacent .sha256 asset is treated only as transport-integrity metadata.
It is not a substitute for the cryptographic attestation.

## Durable Sigstore TUF root

The verified TUF root is stored under SENTRYIQ_DATA_DIR/sigstore-tuf/ by
TufRootStore. The store:

- requires a canonical directory outside the public document root;
- rejects group/world-writable directories, symlinks, malformed roots, and
  unsafe file permissions;
- writes through an exclusive temporary file, flushes/synchronizes it, and
  atomically renames it;
- rejects root-version rollback and same-version replacement with different
  bytes;
- persists only root bytes returned after a complete successful TUF refresh.

The store does not verify TUF signatures itself. Only the native verifier may
supply bytes after the TUF library has successfully verified the refresh.

## Private Composer package

After this workflow is merged to main, the successful main-branch workflow run
publishes a 30-day Actions artifact named sentryiq-sigstore-vendor-php
containing sentryiq-sigstore-vendor.zip and its SHA-256 file.

The ZIP is structured for direct extraction inside the configured private data
directory. The required final path is:

SENTRYIQ_DATA_DIR/sigstore-vendor/vendor/autoload.php

### Current verified artifact (2026-11-21)

The main-branch run [44874394130](https://github.com/Double-IQ/SentryIQ/actions/runs/44874394130) published artifact `sentryiq-sigstore-vendor-php` (artifact ID `14695700420`, 854,394 bytes, outer artifact SHA-256 `971213245f12dfa2f583be23aa943252b73db10864373a82b2cfdfd39f0bf121`). It expires on 2026-12-21 06:12 UTC. PR #110 changed the inner dependency ZIP checksum sidecar to use a portable basename and added a CI `sha256sum --check` validation before publishing.

For the eventual cPanel install, after the hosting acceptance and explicit deployment approval:

1. Download the `sentryiq-sigstore-vendor-php` artifact from the Actions run above and verify the downloaded outer ZIP against the GitHub artifact SHA-256.
2. Extract the outer Actions ZIP locally. It contains `sentryiq-sigstore-vendor.zip` and `sentryiq-sigstore-vendor.zip.sha256`.
3. Verify the inner package using `sha256sum --check sentryiq-sigstore-vendor.zip.sha256` on Linux/macOS, or compare its recorded digest with `Get-FileHash .\\sentryiq-sigstore-vendor.zip -Algorithm SHA256` on Windows.
4. In cPanel File Manager, re-confirm the protected directory (currently expected to be `/home/bicheveb/sentryiq-private`), upload only the inner dependency ZIP there, and extract it there. Do not upload either archive or the vendor directory into the public document root.
5. Confirm the final autoloader path is `/home/bicheveb/sentryiq-private/sigstore-vendor/vendor/autoload.php`. Remove the uploaded inner ZIP after successful extraction.

Do not perform these steps until the private data directory, PHP web-SAPI access, required extensions, and host acceptance have been verified and the owner has approved the installation. This artifact is a dependency package, not a SentryIQ application release.

For the current hosting layout this will resolve to
/home/bicheveb/sentryiq-private/sigstore-vendor/vendor/autoload.php.
Use cPanel File Manager to upload and extract the artifact; no server shell or
Composer installation is required. Keep the parent data directory outside the
document root. The updater validates the canonical path and fails closed if
the package is missing, symlinked, or outside private storage.

## Updater safeguards

Before any live replacement, the updater:

1. downloads only from approved HTTPS GitHub hosts and validates every redirect;
2. enforces a 50 MiB download cap and bounded GitHub API responses;
3. verifies the exact ZIP digest through native Sigstore and the pinned release
   trust policy;
4. validates ZIP entry count, paths, file types, symlinks, and a 250 MiB
   uncompressed-size ceiling before extraction;
5. verifies every extracted file against the attested release manifest;
6. snapshots and verifies all existing targets before changing the first live
   file, then retains backups and restores from them if replacement fails.

The archive boundary tests reject traversal paths, backslash traversal,
drive-prefixed paths, and symlink entries. The rollback tests ensure an
existing file without a completed backup is never mistaken for a new file and
deleted.

## Current status and deployment gate

This change is code and CI only. It does not create a release tag, deploy the
updater, run a production update, or change cPanel configuration. The native
integration job verifies the published v0.1.2 release ZIP against its actual
GitHub attestation and exercises the patched TUF dependency.

Before the updater is enabled on the hosted subdomain, the owner must install
the generated private vendor artifact and confirm the PHP web SAPI can read
the required files and extensions (curl, openssl, sodium, and zip).
A separate explicit approval is still required before any production update or
release activation.
