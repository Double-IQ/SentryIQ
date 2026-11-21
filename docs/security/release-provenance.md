# Release provenance verification

## What the release workflow produces

For version tags matching `v*.*.*`, the release workflow builds the SentryIQ update ZIP and asks GitHub Actions to create a build-provenance attestation for that exact ZIP using the GitHub Actions OIDC identity. The updater's native verifier also expects a separately attested `release-manifest.json` subject for Integrity Node A/B/C verification.

The attestation provides cryptographic evidence about the repository and workflow identity associated with the build. It is stronger than relying only on a checksum file distributed beside the ZIP.

## Current updater enforcement

The implementation has progressed beyond the earlier prototype-only status:

- `UpdateManager::applyLatest()` verifies the downloaded ZIP **before extraction**. It first resolves the release tag to its immutable commit through the GitHub Git-ref/tag API, then verifies the artifact and checks the embedded manifest against that resolved commit and every extracted file.
- The native path is selected when an administrator supplies the private Composer autoload path (`sigstoreAutoloadPath`). It uses `NativeSigstoreReleaseVerifier`, which fetches the digest-matched GitHub attestation, refreshes Sigstore TUF metadata, verifies the Sigstore bundle and SLSA provenance, binds the authenticated source commit to the independently resolved tag commit, and applies `ReleaseTrustPolicy`.
- An injected `GitHubCliAttestationVerifier` remains an alternate adapter path (principally useful for controlled integration/testing). If neither native dependencies nor an explicit verifier are configured, the updater fails closed and refuses installation.
- The adjacent SHA-256 sidecar is only transport-integrity checking; it is not the trust anchor. The ZIP's verified subject digest binds the embedded canonical inventory, which is then checked against the extracted package.

The code therefore **does enforce attestation verification when correctly configured**; however, this does not mean the production installation is configured or accepted. The cPanel private vendor artifact has been built but not installed, the production `SENTRYIQ_GH_BINARY`/native verifier configuration has not been verified, and no new production release has been published through the current approved workflow. The v0.1.2 artifact remains a workflow fixture, not an acceptable new updater release.

## TUF root refresh and persistence

The native verifier loads the last persisted Sigstore TUF root, or the pinned bootstrap root on first use, then calls the TUF library's `TrustedRoot::fromTuf()` refresh path. It persists the resulting root only after that complete refresh returns successfully. The persistence integration test checks successful root rotation, reuse after process restart, and preservation of the last trusted root after an incomplete refresh. `TufRootStore` enforces monotonic root versions and owner-only files. Its temp-file contents are flushed/fsynced where supported before atomic rename; the containing-directory entry is not explicitly fsynced, so crash-durability remains the boundary recorded in the Node 4 durability review. This is distinct from whether HelioHost can execute the refresh path, which the owner has already investigated.

## Remaining production gates

1. Install and verify the pinned private native Sigstore/TUF dependencies on the intended production host, including actual web-SAPI execution and persistent TUF root refresh/reload.
2. Confirm the host's PHP/cURL/runtime limits, private directory ownership and permissions, and GitHub API access. A configured optional API token must be kept private and have only the required read access.
3. Publish a new release from the approved current source and validate its genuine ZIP and manifest attestations; do not reuse or retag v0.1.2.
4. Confirm the production updater is configured to select the native verifier and that all invalid, unavailable, stale, wrong-identity, wrong-commit, digest-mismatched, and rollback cases fail before extraction or file replacement.
5. Complete the separate release-authority design: independently controlled canonical release authorization and independently pinned trust roots for the Integrity Nodes. The current A/B/C observers share the GitHub/Sigstore trust roots and repository workflow identity; they are not three independent release-authority approvals.

## What an attestation does not prove

A successful attestation establishes provenance under the GitHub Actions/Sigstore trust model. It does not prove the source code is benign, the workflow definition was independently reviewed, or that the artifact is safe to install. GitHub build provenance is one trust layer, not a substitute for separate release authorization and independent observer trust.
