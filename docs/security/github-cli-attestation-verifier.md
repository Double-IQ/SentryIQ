# GitHub CLI attestation verifier adapter

**Status:** Experimental integration adapter. Not connected to `UpdateManager` and not approved for production use.

## Verifier choice

SentryIQ delegates signature, certificate, trust-root, and transparency/timestamp verification to GitHub CLI:

```sh
gh attestation verify sentryiq-VERSION.zip \
  --repo Double-IQ/SentryIQ \
  --signer-workflow Double-IQ/SentryIQ/.github/workflows/release.yml \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --source-ref refs/tags/vVERSION \
  --predicate-type https://slsa.dev/provenance/v1 \
  --deny-self-hosted-runners \
  --format json
```

The adapter invokes this as an argument array through `proc_open` with shell bypass; it does not concatenate user-controlled values into a shell command. It enforces a 60-second process timeout and a combined 1 MiB output limit.

## Evidence checked after successful CLI verification

The adapter accepts JSON only after the CLI exits with status zero. It then requires:

- Certificate issuer `https://token.actions.githubusercontent.com`.
- Immutable source repository ID `1345956206` and canonical source repository URI.
- Source ref equal to the requested version tag.
- Source commit digest equal to the independently supplied expected full Git commit SHA.
- Exact release workflow identity in the certificate SAN, build signer URI, and build config URI.
- `push` build trigger and GitHub-hosted runner.
- At least one independently verified timestamp.
- SLSA provenance v1 predicate and subject SHA-256 equal to the digest calculated locally from the downloaded ZIP.

The attestation statement is not treated as a substitute for certificate identity. The CLI documentation explicitly warns that predicate contents can be controlled by the workflow; the adapter relies on the certificate extensions for identity and checks the subject digest against the local file.

## Expected commit requirement

The caller must resolve the release tag to a full commit SHA through a separately trusted release metadata path and pass it as `expectedCommit`. Do not copy this value from the attestation JSON itself. The adapter compares that independent value to the certificate's source repository digest.

## Runtime prerequisites and limitations

- A supported, current GitHub CLI with `gh attestation verify` support must be installed on the host.
- The CLI must be able to reach GitHub and Sigstore trust services; any authentication needed for the repository's attestation API must be configured securely.
- Shared hosting may not permit installing or executing GitHub CLI. Do not enable this adapter there without verifying the actual runtime and process permissions.
- The adapter's test runner seam is only for contract tests. Synthetic JSON fixtures do not test cryptography.
- This does not yet provide a separately pinned trust root, a canonical signed manifest, or two independent Integrity Node signatures.
- No production updater enforcement is enabled by this change.

## Tests

```sh
php tests/github_cli_attestation_verifier.test.php
```

These tests validate command constraints, output parsing, policy handoff, non-zero exit handling, immutable repository identity, subject digest matching, and timestamp presence. They use synthetic verifier output and are not cryptographic tests.
