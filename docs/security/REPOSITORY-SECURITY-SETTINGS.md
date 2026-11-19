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
4. Require these exact GitHub Actions job status checks (the job/check names, not merely the workflow display names):
   - `php-lint`
   - `gallery-security`
   - `release-manifest`
   - `Verify release attestation and dual-node report contract`
5. Require branches to be up to date before merging.
6. Block force pushes and branch deletion.
7. Apply the rules to administrators as well, unless a documented emergency bypass process is required.

The four required check names above were read from successful GitHub Actions jobs on PR remediation head `a0bcabcb838c75b23f941f442214859ba125ad4e` on 2026-11-19. Reconfirm the names in GitHub's branch-protection UI when configuring the ruleset, because renaming a workflow job changes its required status-check name.

Create a tag ruleset for `v*` release tags that prevents tag updates and deletion after publication. Release immutability is a critical input to the attestation trust model.

## Additional platform settings

- Enable GitHub secret scanning and push protection where available.
- Enable Dependabot alerts and security updates.
- Enable private vulnerability reporting.
- Review who has repository write/admin access and remove stale collaborators/tokens.
- Review Actions workflow permissions and keep the default GITHUB_TOKEN read-only.

These controls require repository administration privileges. The connected GitHub interface available during this remediation can inspect repository settings but cannot change branch-protection/ruleset or platform security settings. Do not mark them complete until the owner applies and verifies them.

## Phase 1 live settings re-check (2026-11-19)

- GitHub's branch metadata endpoint currently reports `main.protected: false`.
- The repository rulesets endpoint currently returns an empty list (`[]`); no repository rulesets are present in the returned result.
- The connected integration cannot read the branch-protection detail endpoint (HTTP 403, insufficient integration access), so it cannot inspect any legacy protection configuration beyond the branch metadata flag. The owner must configure and verify protection with repository administration access.
- The repository metadata response did not expose a `security_and_analysis` object, so secret scanning, push protection, and Dependabot alert settings remain unverified. No platform settings were changed.
