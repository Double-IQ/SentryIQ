# Phase 3.1 private bootstrap runtime qualification

This runbook is for a **non-production qualification environment** after independently provisioning the runtime values. It is not a key-generation or deployment procedure.

## Private runtime requirements

- The SentryIQ data directory is outside the document root, is a real directory (not a symlink), and has mode `0700`.
- `bootstrap-runtime.php` is a regular file in that directory, not a symlink, with exact mode `0600`.
- Registry-anchor and release-authorisation public pins are independently sourced, have unique key IDs, correct roles/algorithms, and are not copied from the candidate bundle or application host.
- Bundle bytes and registry-anchor payload/signature are the exact reviewed canonical values.
- The initial registry anchor is sequence 1 with no predecessor; a successor names the previous accepted digest and increments exactly one.
- The TUF callback independently validates the pinned root, timestamp, snapshot, targets, and every delegated role required by the candidate. It must not trust a boolean supplied by a request or candidate bundle.
- The target resolver maps only validated relative target paths to files inside a private target store. It must reject symlinks, traversal, and unexpected file types and never fall back to a public web path.
- Owner mapping binds the authenticated application username to an immutable owner ID and rejects unknown accounts.
- No private signing key is stored in the runtime file or application data directory.

## Read-only qualification command

After placing the reviewed runtime file, run this from the repository root using the same PHP runtime and account context intended for the service:

```sh
SENTRYIQ_QUALIFY_USERNAME='known-test-account' php scripts/qualify-bootstrap-runtime.php
```

The CLI performs file/directory boundary checks, callback shape checks, owner mapping, bundle validation, signed registry-anchor validation, and the configured TUF validation. It does not issue a challenge, sign an approval, write a receipt, modify trust state, or deploy.

Expected success output is deliberately non-sensitive:

```
Bootstrap runtime qualification PASSED.
Owner mapping, signed registry anchor, trust bundle, and TUF callback verified.
No challenges or receipts were created; no trust state or deployment changed.
```

Failure is fail-closed and does not print the configuration, bundle, public-key material, or callback exception details. Diagnose failures locally with protected operator logs.

## Still required before Phase 3.1 can close

- Provision and qualify a private test runtime using independently sourced pins.
- Run an authenticated end-to-end test on the deployed non-production endpoint, including challenge issuance, valid approval, receipt persistence, replay rejection, target retrieval, and target-byte verification.
- Integrate the native session bridge into the actual app login/lock/logout lifecycle; the current repository contains native companion libraries and approval UI, not the app shell.
- Qualify native build, unit, and emulator/device tests on the current commit.
- Perform real-device hardware checks for Secure Enclave and Android Keystore authentication/key properties.
- Obtain independent security review of the TUF dependency, callback boundaries, runtime provisioning, and bootstrap protocol.

No production keys, trust roots, data migration, release, or deployment may be created by this qualification runbook.
