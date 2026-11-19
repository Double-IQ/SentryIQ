# Required GitHub repository security settings

This document records repository controls that are not enforceable from source files alone.

## Repository rulesets — independently verified (2026-11-19)

The GitHub repository rulesets API currently reports both rulesets as **active**:

### Protect main

- Ruleset: `SentryIQ - Protect main`
- Ruleset ID: `27621562`
- Target: `refs/heads/main`
- Enforcement: `active`
- Pull request required before merging.
- Required status checks: `php-lint` and `gallery-security`.
- Branch must be up to date with required checks.
- Required review-thread resolution enabled.
- Force-push and branch deletion are blocked.
- No bypass actors are configured; current API response says the connected user cannot bypass.

### Protect release tags

- Ruleset: `SentryIQ - Protect release tags`
- Ruleset ID: `27621577`
- Target: `refs/tags/v*`
- Enforcement: `active`
- Tag updates and deletion are blocked.
- No bypass actors are configured; current API response says the connected user cannot bypass.

GitHub's legacy branch metadata still reports `main.protected: true` with legacy `protection.enabled: false`. This is not a contradiction: the active repository ruleset is the enforcement mechanism. Do not infer that the branch is unprotected from the legacy subobject alone.

The rulesets were read directly from:
- `GET /repos/Double-IQ/SentryIQ/rulesets/27621562`
- `GET /repos/Double-IQ/SentryIQ/rulesets/27621577`

## Platform security settings — owner-confirmed, not API-verified

The repository owner reports that the following controls were reviewed and enabled in GitHub repository settings:

- Secret scanning.
- Push protection.
- Dependabot alerts and security updates.
- Private vulnerability reporting.

The connected GitHub API integration does not expose the repository `security_and_analysis` settings for independent read-back. These remain recorded as **owner-confirmed**, not API-verified.

## Workflow and token controls

- Ordinary CI workflows declare read-only token permissions and disable persisted checkout credentials.
- Workflow action references are pinned to full commit SHAs.
- The active `main` ruleset requires the two job check names `php-lint` and `gallery-security`.
- The release-tag ruleset protects `v*` refs against update and deletion.
- Do not add a required check until its exact job name has been observed on a successful run and the ruleset is updated accordingly.

## Remaining review items

- Reconfirm repository collaborators and administrator access periodically.
- Review Actions workflow permissions and retain read-only defaults except for the narrowly scoped release publisher.
- Keep the release workflow's `contents: write`, `id-token: write`, and `attestations: write` permissions confined to the tag-triggered release workflow.
- Review the release-tag ruleset before the first new release; the API currently confirms update/deletion protection but not a tag-creation allowlist.
- Do not treat GitHub provenance as an independent release-signing key. See `docs/security/release-provenance.md` and `docs/security/canonical-release-manifest.md` for the trust limitations and outstanding updater integration.

## Audit note

The earlier Phase 1 audit text saying that no repository rulesets existed is superseded by the live 2026-11-19 API read-back above. Historical notes may remain in the master checklist as chronology, but the current state is the active rulesets documented here.
