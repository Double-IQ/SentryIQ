# Release provenance verification

## What the release workflow produces

For version tags matching `v*.*.*`, the release workflow builds the SentryIQ update ZIP and asks GitHub Actions to create a build-provenance attestation for that exact ZIP using the GitHub Actions OIDC identity.

The attestation provides cryptographic evidence about the repository and workflow identity associated with the build. It is stronger than relying only on a checksum file distributed beside the ZIP.

## Verify a downloaded release

Install a current GitHub CLI with attestation support, download the ZIP from the SentryIQ GitHub release, then run:

```sh
gh attestation verify sentryiq-VERSION.zip --repo Double-IQ/SentryIQ
```

Replace `VERSION` with the actual release version. Verification must succeed before treating the provenance as valid. Review the verified source repository, workflow identity, source ref, and commit against the expected SentryIQ release. For the stricter verifier flags and certificate-extension checks used by the PHP prototype, see [GitHub CLI attestation verifier adapter](github-cli-attestation-verifier.md).

The SHA-256 sidecar remains useful for detecting accidental corruption, but it is not an independent trust anchor if an attacker can replace both the ZIP and checksum through the same release channel.

## Current implementation status

The repository now contains:

- `app/Updates/ReleaseTrustPolicy.php`: a normalized-claims policy gate for repository identity, tag/ref, expected source commit, workflow identity, event, artifact digest, and anti-rollback.
- `app/Updates/GitHubCliAttestationVerifier.php`: an experimental adapter that delegates cryptographic verification to the maintained GitHub CLI, then checks the verified certificate extensions, timestamp evidence, provenance statement subject digest, and release policy.
- Contract tests using synthetic CLI JSON output. These test parsing and policy handoff only; they are not cryptographic tests.

**The adapter is not connected to `UpdateManager`. Production updates still use the existing checksum flow.** Do not describe the updater as attestation-verified or signature-enforced.

## Genuine-attestation validation still required

The currently published releases `v0.1.0` and `v0.1.1` were published on 27 September 2026, before the provenance-attestation workflow change. They are not suitable evidence that the new workflow and PHP adapter work together.

Before updater integration:

1. Build a new release through the approved tag-push workflow and obtain its genuine ZIP and GitHub attestation. Do not retag or overwrite an existing release.
2. Verify that artifact with a supported GitHub CLI in a controlled environment and capture the actual `--format json` result.
3. Confirm the adapter accepts the genuine result and rejects mutations to repository ID, source ref/commit, signer/configuration identity, event, runner, timestamp evidence, and artifact digest.
4. Resolve the expected tag commit independently of the attestation output.
5. Confirm the target hosting environment can securely run and update the verifier binary and its trust material. Shared hosting may not support this.
6. Prove that a rejected or unverifiable package cannot be extracted, installed, or modify application/runtime files.

No new tag or release has been created as part of this work.

## Remaining architecture requirements

This prototype does not yet provide the complete SentryIQ release trust design. It does not replace the planned canonical signed manifest, independently pinned public trust roots on both Integrity Nodes, expiry policy, anti-rollback enforcement at the updater boundary, or independent Integrity Node verification.

No production updater enforcement should be enabled until genuine-attestation validation, verifier runtime management, failure/recovery testing, and the independent trust design have been reviewed.
