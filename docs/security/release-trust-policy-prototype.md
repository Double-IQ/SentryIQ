# Release trust policy prototype

**Status:** Experimental policy evaluator only. Not wired into the updater and not a cryptographic verifier.

## Purpose

`app/Updates/ReleaseTrustPolicy.php` evaluates a small, normalized claim set after a maintained GitHub/Sigstore verifier has independently validated the attestation bundle. It checks the repository identity, tag/ref, source commit, approved workflow path and workflow ref, triggering event, artifact SHA-256 digest, and monotonic version progression.

The evaluator deliberately does not parse Sigstore bundles, validate certificates, verify DSSE signatures, resolve transparency-log inclusion proofs, or establish trust roots. Those tasks must remain with a maintained verifier such as GitHub CLI's attestation verification implementation until a reviewed integration is selected.

## Normalized adapter contract

A future adapter may call the policy only after cryptographic verification succeeds and must supply:

- `cryptographically_verified`: boolean true only after successful signature, certificate identity, trust-root, and transparency verification.
- `repository_id` and `repository`: immutable repository identity and canonical name.
- `source_ref`: exact version tag ref, for example `refs/tags/v1.2.3`.
- `source_commit`: full 40-character commit SHA resolved for that release tag.
- `workflow_path` and `workflow_ref`: exact approved release workflow identity.
- `source_event`: expected `push` event.
- `subject_sha256`: digest of the exact downloaded ZIP.

The caller must independently resolve the expected release commit from the trusted release/tag metadata and calculate the ZIP digest locally. Do not populate these fields from untrusted release JSON alone.

## Current policy

- Only stable MAJOR.MINOR.PATCH versions are accepted.
- Repository name and immutable repository ID must match `Double-IQ/SentryIQ` / `1345956206`.
- Source tag, commit, workflow path/ref, and event must match the expected release.
- Attested subject digest must match the locally calculated ZIP digest.
- Target version must be strictly newer than the installed version. Rollback requires a separately designed, explicitly authorized recovery path and is not supported here.
- Any missing or mismatched claim fails closed.

## Tests and limitations

Run:

```sh
php tests/release_trust_policy.test.php
```

The tests exercise policy decisions using synthetic normalized claims. They do **not** prove cryptographic attestation verification and must never be described as signature-verification tests.

This prototype is intentionally not referenced by `UpdateManager`. No downloaded package is accepted or installed based on this class. Before production integration, select and pin a maintained verifier, define a strict adapter from its verified output, test genuine and adversarial attestation fixtures, and prove rejected artifacts cannot alter application or runtime files.
