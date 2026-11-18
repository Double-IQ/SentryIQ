# Required GitHub repository security settings

This document records repository controls that are not enforceable from source files alone.

## Current verified state

- The `main` branch was observed with `protected: false` and `protection.enabled: false` during the Phase 1 audit.
- Workflow action references are now pinned to full commit SHAs in the remediation branch.
- Ordinary CI workflows now declare read-only token permissions and disable persisted checkout credentials.
- A weekly GitHub Actions Dependabot update configuration, `CODEOWNERS`, and `SECURITY.md` have been added in the remediation branch. A pinned CodeQL workflow was evaluated but removed because the current CodeQL release rejects PHP as an unsupported language; do not configure a CodeQL PHP required check.
- GitHub platform settings for secret scanning, Dependabot alerts, private vulnerability reporting, and branch/ruleset enforcement have not been verified or changed.

## Required owner action

Create a ruleset or branch protection rule targeting `main` with:

1. Require a pull request before merging.
2. Require at least one approving review; dismiss stale approvals when new commits are pushed.
3. Require review from Code Owners.
4. Require the current CI checks: PHP Syntax Check, Gallery Security Checks, Release Manifest Tests, and Validate v0.1.2 release attestation.
5. Require branches to be up to date before merging.
6. Block force pushes and branch deletion.
7. Apply the rules to administrators as well, unless a documented emergency bypass process is required.

Create a tag ruleset for `v*` release tags that prevents tag updates and deletion after publication. Release immutability is a critical input to the attestation trust model.

## Additional platform settings

- Enable GitHub secret scanning and push protection where available.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting.
- Review who has repository write/admin access and remove stale collaborators/tokens.
- Review Actions workflow permissions and keep the default GITHUB_TOKEN read-only.

These controls require repository administration privileges. The connected GitHub interface available during this remediation can inspect repository settings but cannot change branch-protection/ruleset or platform security settings. Do not mark them complete until the owner applies and verifies them.
