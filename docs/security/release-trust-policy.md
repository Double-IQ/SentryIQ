# Release trust policy and repository controls

**Status:** Proposed; no updater enforcement is enabled by this document.

## Repository identity

The updater currently names `BTM-SA/SentryIQ`, while active development and the release-provenance workflow use `Double-IQ/SentryIQ`. GitHub's API responds to the legacy owner/name route with a permanent redirect to repository ID `1345956206`, which is also the repository ID returned for the active `Double-IQ/SentryIQ` pull request. This indicates the names resolve to the same repository identity, rather than two separate repositories.

For new workflow configuration and documentation, use the canonical repository name `Double-IQ/SentryIQ`. Do not change the updater's repository constant as part of this provenance-only change; make that a separate compatibility-tested change after confirming the intended public release URL and any existing installations.

## What counts as trusted release evidence

The release ZIP's adjacent SHA-256 file is an integrity check, not an independent trust anchor. An attacker who can replace both files through the same release channel can replace the checksum too.

The GitHub Actions build-provenance attestation added to the release workflow is a separate, cryptographically verifiable statement about the artifact's build provenance and workflow identity. A verifier must check at least:

- The attestation is valid and chains to the expected GitHub/Sigstore trust roots.
- The subject digest matches the exact downloaded ZIP.
- The source repository identity is `Double-IQ/SentryIQ` (repository ID `1345956206`).
- The source ref is the expected version tag and the source commit is the commit intended for release.
- The signer workflow identity is this repository's approved release workflow, not an arbitrary workflow in the repository.
- The workflow run completed successfully under the expected event and ref.

A successful attestation check establishes provenance under the GitHub Actions trust model. It does not, by itself, prove that the source code is benign, that the workflow definition was reviewed, or that the artifact is safe to install.

## Required repository controls before production release enforcement

The observed `main` branch metadata reports `protected: false`. Before relying on this repository as a release trust authority, an administrator should configure and verify:

1. Require pull requests before merging to `main`; do not permit direct pushes for routine changes.
2. Require the `PHP Syntax Check / php-lint` and `Gallery Security Checks / gallery-security` checks to pass before merge.
3. Require conversation resolution and dismiss stale approvals when review is enabled. Require at least one independent approval where a second qualified reviewer is available; do not create a self-approval deadlock for a single-maintainer repository.
4. Block force pushes and branch deletion on `main`.
5. Protect version tags matching `v*.*.*` against unauthorized creation, update, and deletion. Restrict release creation to the approved release process and maintainers.
6. Keep the release workflow permissions minimal. Any workflow that receives `id-token: write`, `attestations: write`, or `contents: write` must be reviewed as security-sensitive.
7. Recheck the effective branch protection/ruleset and required check names after configuration; do not treat a documentation checklist as proof that controls are active.

The current repository metadata showed branch protection disabled at the time of this review. The GitHub integration used for this repository could read the branch metadata but could not configure administrative branch-protection settings. An authorized repository administrator must apply and verify these controls in GitHub.

## Updater enforcement prerequisites

Do not make the updater accept an artifact solely because a GitHub attestation exists. Before enforcing verification in `UpdateManager`, implement and test a verifier that binds the artifact digest to the approved repository, tag/ref, commit, and workflow identity. Verification must happen before extraction or installation.

The production policy must also define:

- A monotonic release sequence or equivalent anti-rollback rule, including recovery from an intentionally approved rollback.
- A maximum attestation age or release freshness policy, if applicable.
- Trust-root and verifier updates, including key rotation and emergency revocation.
- Fail-closed behaviour for missing, invalid, expired, wrong-repository, wrong-workflow, wrong-ref, digest-mismatched, or rollback evidence.
- Safe handling of GitHub API/network outages without silently treating an unverifiable package as trusted.
- Tests proving rejected packages cannot modify application or runtime files.

GitHub build provenance is the first provenance layer. The separately approved signed canonical manifest and two independently pinned Integrity Node trust roots remain required by the SentryIQ security roadmap. Do not store a long-lived release-signing private key on the production host or in this repository.
