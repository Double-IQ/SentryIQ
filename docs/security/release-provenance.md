# Release provenance verification

## What the release workflow now produces

For each version tag matching `v*.*.*`, the release workflow builds the SentryIQ update ZIP and asks GitHub Actions to create a build-provenance attestation for that exact ZIP using the GitHub Actions OIDC identity.

The attestation is associated with the repository and workflow identity. It gives a verifier cryptographic evidence about where the artifact was built, rather than relying only on a checksum file distributed beside the ZIP.

## Verify a downloaded release

Install a current GitHub CLI with attestation support, download the ZIP from the SentryIQ GitHub release, then run:

```sh
gh attestation verify sentryiq-VERSION.zip --repo Double-IQ/SentryIQ
```

Replace `VERSION` with the actual release version. Verification must succeed before treating the provenance as valid. Review the verified source repository, workflow identity, source ref, and commit against the expected SentryIQ release.

The existing SHA-256 sidecar remains useful for detecting accidental corruption, but it is not an independent trust anchor if an attacker can replace both the ZIP and checksum through the same release channel.

## Important security boundary

This is a first release-assurance step, not completion of signed-release verification:

- GitHub's provenance attestation does not by itself make the current PHP updater verify the attestation.
- `app/Updates/UpdateManager.php` still uses the release checksum flow until a separately reviewed verifier and trust policy are implemented.
- This workflow does not create or store a long-lived release-signing private key.
- It does not replace the planned canonical signed manifest, pinned public trust roots on both Integrity Nodes, expiry policy, or anti-rollback enforcement.
- Do not claim an update is signature-verified until the updater actually validates an approved signature before extraction and installation.

The next implementation step is to define the verifier trust policy and test the GitHub attestation verification path. Production updater enforcement must wait until that policy and the repository identity have been reviewed.
