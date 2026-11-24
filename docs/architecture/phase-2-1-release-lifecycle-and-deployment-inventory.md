# Phase 2.1 — Release lifecycle and deployment-path inventory

**Status:** Repository and live GitHub configuration inventory complete. This is a source/configuration audit, not production acceptance.  
**Audit date:** 2026-11-24  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Repository:** `Double-IQ/SentryIQ` (repository ID `1345956206`)  
**Target independent verifier:** one specialised HelioHost verifier; not currently qualified or activated.

## 1. Executive result

The repository has a credible GitHub/Sigstore build-provenance path and a native PHP updater verification path. The updater is designed to verify the downloaded release ZIP before extraction and to validate every packaged file against the ZIP-bound manifest. It also has private dependency checks, protected update workspaces, backup-before-replacement, and rollback handling.

Those controls establish only the build/artifact trust layer. The target design requires two further independent layers that do not exist yet:

1. A separately controlled owner release authorisation bound to the exact version, source commit, manifest digest, and ZIP digest.
2. A HelioHost verifier report, signed with its own dedicated key, measuring the actual deployed public assets and qualified private runtime surface, then independently accepted by the owner's master phone.

There is no verified production activation of the native updater, no verified production dependency installation, no deployment workflow to HelioHost, no independent verifier service, and no phone-side release gate. The current repository release process must not be described as the completed target trust architecture.

## 2. Release lifecycle traced

| Stage | Current repository behaviour | Target-design disposition |
|---|---|---|
| Source/tag | `v*.*.*` tag push triggers release workflow; version in `VERSION` must match tag | Retain immutable source/tag binding; strengthen approval and repository governance |
| Checkout/build | Checkout action pinned to commit SHA; release script archives the tag, relocates four private runtime templates into `runtime/`, removes `.git`, `.github`, and source `private_data/` from package | Good baseline; document deterministic build and full build inputs |
| Inventory | Python builder creates format-2 canonical inventory with repository ID, version, commit, workflow path, path/size/SHA-256 for each packaged file, plus public/runtime lists | Package inventory is useful; it is not a live deployed-webroot inventory |
| Provenance | GitHub Actions attests ZIP and external `release-manifest.json` as subjects | Build provenance only; no separate owner approval |
| Release publication | Workflow publishes ZIP, ZIP checksum, external manifest, and manifest checksum as GitHub Release assets | Current release asset channel is mutable; tag protection alone does not make a release immutable |
| Discovery/delivery | Updater reads latest stable GitHub Release metadata, finds ZIP/checksum, downloads from GitHub HTTPS hosts, validates redirects and checksum | Checksum is transport integrity only; artifact attestation is the trust control |
| Updater verification | Resolves the version tag through Git refs (including annotated tags), verifies ZIP attestation using native Sigstore/TUF when private autoload is configured, then checks exact repository/ref/commit/workflow/event/digest policy | Strong source-level capability; production selection/configuration remains unverified |
| Extraction/inventory | ZIP safety checks and extraction precede validation of embedded manifest; every listed file size/digest and exact path set are checked, including runtime allowlist | Covers archive contents, not unknown files already on the production host |
| Installation | Creates private backup, completes backups before replacing live files, updates public and private runtime files, verifies installed `VERSION`, attempts rollback on failure | Good updater safety controls; does not independently attest resulting deployment |
| Production deployment | No deployment workflow is present in the current `.github/workflows` inventory. The updater endpoint `update_apply.php` is the repository's self-update path and requires fresh auth, CSRF, private data directory and private native verifier autoload path | No evidence of a configured or successfully exercised production update path |
| Independent measurement | No HelioHost report service, report protocol integration, or private-file read-only collector activation found in this audit | Required Phase 2.4–2.7 work |
| Owner acceptance | No master-phone release/verifier trust-root bootstrap or phone-side enforcement path found | Required Phase 2.3 and 2.8 work |

## 3. Implemented controls and evidence

### 3.1 Build and package

Files inspected:
- `.github/workflows/release.yml`
- `scripts/build-release-package.sh`
- `scripts/build-release-manifest.py`
- `.github/workflows/release-manifest-tests.yml`

Observed controls:
- Release workflow triggers on pushed version tags matching `v*.*.*`.
- It checks tag/version equality and stable `MAJOR.MINOR.PATCH` format.
- Checkout action is pinned to a full commit SHA and uses `persist-credentials: false`.
- Build script archives the supplied source ref and checks the package's required private runtime templates.
- It moves `vault_engine.php`, `email_template.php`, `vault_icon_cache.php`, and `VaultKdfPolicy.php` to the package's `runtime/` area, then removes source `private_data/`, `.git/`, and `.github/`.
- Manifest format 2 inventories all packaged files except the manifest itself, including relative path, byte length, and SHA-256; it also emits `public_files` and `runtime_files`.
- Symlinks are rejected; output JSON is deterministic (sorted keys and compact encoding).
- Release-manifest tests run on pull requests and main pushes; package validation builds the package from the exact commit under test.

Limits:
- The inventory describes the Git archive package, not every file that exists in a deployed webroot or private host data directory.
- The package has no PWA manifest/service-worker shell at the current audited baseline; the manifest cannot cover absent assets.
- The workflow removes `.github/` from the delivered package, so workflow identity is metadata in the inventory/provenance rather than a deployed file.
- The manifest does not itself authenticate anything; its trust comes from the ZIP attestation that binds the embedded copy.

### 3.2 GitHub/Sigstore provenance

Files inspected:
- `.github/workflows/release.yml`
- `app/Updates/NativeSigstoreReleaseVerifier.php`
- `app/Updates/SigstoreProvenance.php`
- `app/Updates/FulcioCertificateClaims.php`
- `app/Updates/ReleaseTrustPolicy.php`
- `app/Updates/TufRootStore.php`

Observed controls:
- Release workflow requests GitHub build-provenance attestations for the ZIP and external manifest.
- Native verifier retrieves attestations by the downloaded artifact SHA-256, verifies Sigstore bundle against refreshed Sigstore TUF trust metadata, and validates SLSA provenance.
- Policy binds repository name and immutable repository ID, version tag ref, source commit, workflow definition commit, workflow path/ref, push event, and exact artifact subject digest.
- The native verifier resolves the tag independently through GitHub and requires the attested source commit to match.
- TUF root store persists verified root bytes outside the webroot, rejects symlinks and unsafe permissions, uses locking and atomic replacement, and enforces monotonically increasing root versions. Signature/threshold verification is performed by the TUF library before the store receives bytes.
- Private verifier dependencies are version-pinned in code and must resolve canonically inside the private SentryIQ data directory, outside the public webroot.

Limits:
- GitHub/Sigstore provenance proves a build identity and artifact digest under that trust model; it does not establish benign source, independent owner approval, production deployment, or browser runtime integrity.
- TUF trust is not the same as an owner-pinned release-authorisation root or HelioHost report key.
- TUF state under the application host's private data directory is not independent of a fully compromised application host.
- No production host filesystem, process identity, dependency bundle, or durable TUF state was inspected.

### 3.3 Updater and rollback

Files inspected:
- `app/Updates/UpdateManager.php`
- `app/Updates/ReleaseDownloadPolicy.php`
- `update_apply.php`
- `tests/release_trust_policy.test.php`
- `tests/update_rollback.test.php`
- `.github/workflows/native-release-attestation.yml`

Observed controls:
- Updater requires a private data directory outside the document root.
- `update_apply.php` requires fresh authentication and CSRF, validates private configuration, and refuses to proceed if the native Sigstore autoload path is missing or outside the private data directory.
- Downloads are restricted to HTTPS GitHub hosts and redirects are checked against an allowlist.
- ZIP checksum is checked as transfer-integrity metadata, then the ZIP attestation is cryptographically verified before extraction.
- Tag resolution supports lightweight and annotated tags and is independent of the Releases API's `target_commitish`.
- Embedded inventory validation rejects malformed/duplicate/traversal paths, symlinks, missing files, size/digest mismatch, unlisted extra files, and runtime-file allowlist mismatch.
- Updater creates verified backups before replacing any live file, uses a lock to prevent overlapping updates, verifies installed version after replacement, and attempts rollback on failure.
- Regression workflow tests native verification and updater safety across PHP 8.1–8.5; it also builds a private dependency ZIP for cPanel installation as a CI artifact.

Limits:
- The private dependency ZIP is a CI artifact (30-day retention in the inspected workflow), not proof that the production host has installed or pinned it.
- The application-side updater is not an independent deployment verifier. A compromised app host can alter files and its own local evidence.
- Version comparison against the installed `VERSION` is useful updater anti-rollback, but is not the target phone-held monotonic release-acceptance state or a separately approved rollback ceremony.
- The legacy `NativeSigstoreIntegrityAttestationVerifier` adapter still documents the A/B/C callable contract; it is regression/legacy integration, not the target HelioHost verifier or master-phone gate.

## 4. Live GitHub governance and release observations

Live GitHub API inspection on 2026-11-24 found:

### Main branch ruleset
- Active ruleset: **SentryIQ - Protect main**.
- Prevents branch deletion and non-fast-forward updates.
- Requires PRs and resolved review threads.
- Configured required approving review count is **0**; code-owner review is disabled.
- Extra approval for unattributed changes is enabled.
- Strict required status checks are configured for only **`php-lint`** and **`gallery-security`**.
- No bypass actors are configured; current user cannot bypass.

**Finding — high priority:** The ruleset does not require an approving review. The broader CI suite may run, but most of its checks are not required by this ruleset for merging. The owner/security governance decision should require at least one independent approval and require all security-critical checks (including release manifest and native updater/provenance tests) before release-trust code can merge.

### Version tag ruleset
- Active ruleset: **SentryIQ - Protect release tags**.
- Applies to `refs/tags/v*`.
- Prevents tag update and deletion.
- No bypass actors are configured.

This materially improves tag immutability. It does not, by itself, make the GitHub Release object or its uploaded assets immutable.

### Published releases
- Latest observed stable GitHub Release: `v0.1.2`.
- Its ZIP and checksum assets are published; release API reports `immutable: false`.
- The release workflow publishes an external inventory manifest and its checksum for new releases, but the observed v0.1.2 release did not list those two assets.
- No new release was published as part of this audit.

**Finding — high priority:** Protected tags and mutable GitHub Release assets are distinct controls. Require immutable release publication (where supported) or an independently signed release-asset digest record and strict edit permissions; verify the actual release asset set before treating a release as accepted.

### Workflow inventory

The current `.github/workflows` directory contains release packaging, release-manifest tests, PHP lint, Gallery security, TUF validation/store tests, native release-attestation regression, legacy verifier regression, and historical v0.1.2 attestation validation workflows. There is no dedicated production deployment workflow in the inspected directory. The legacy verifier workflows are read-only regression coverage following Phase 0.6; they do not provision remote nodes.

The release workflow declares `contents: write`, `id-token: write`, and `attestations: write` at workflow scope. These are needed by distinct publication/attestation steps, but are broader than necessary for a future multi-job pipeline. Split build/test, attest, and publish jobs and grant each job only the permissions it needs. No production environment approval gate is configured in this workflow.

## 5. Findings and priority

| ID | Priority | Finding | Required disposition |
|---|---|---|---|
| RLS-01 | High | No owner-controlled release authorisation over exact release version/commit/manifest/ZIP digests | Design a separate signed approval object and independent key custody; bind exact subjects |
| RLS-02 | High | No HelioHost independent verifier report or master-phone acceptance integration | Complete verifier, report schema, trust-root bootstrap, freshness and phone-side gate |
| RLS-03 | High | Main ruleset permits zero approving reviews and requires only PHP lint/Gallery checks | Owner/security governance change: require independent approval and full critical CI set |
| RLS-04 | High | Latest observed GitHub Release reports `immutable: false`; tag protection does not freeze release assets | Enable immutable releases where available or introduce a separately authenticated immutable release record and asset verification |
| RLS-05 | High | No verified production deployment path or production updater activation evidence | Qualify and test actual host updater/deployment procedure after explicit authorisation |
| RLS-06 | Medium | Release workflow grants write/attestation/OIDC permissions at workflow scope and has no production environment gate | Split jobs and minimise permissions; require approval for any production-facing publication step as appropriate |
| RLS-07 | Medium | Package manifest covers package files, not deployed webroot unexpected files, runtime config, private dependencies, headers, redirects or cache variants | Extend the canonical inventory/measurement contract in Phase 2.2–2.6 |
| RLS-08 | Medium | Native updater anti-rollback is local version comparison; no phone-held monotonic accepted release state or approved rollback protocol | Define phone-held monotonic state and separately authenticated rollback |
| RLS-09 | Medium | External release manifest is published/attested but current updater consumes ZIP and embedded manifest; no independent verifier consumes the external manifest yet | Define one canonical subject-binding contract for updater, verifier and phone |
| RLS-10 | Medium | Private verifier dependencies are produced as a temporary CI artifact; production installation and patch integrity are unverified | Define reproducible dependency bundle, provenance/hash verification and host qualification |
| RLS-11 | Low | Existing legacy adapter naming/docstrings still refer to A/B/C | Keep as regression compatibility only; rename/retire only after replacement tests are complete |

## 6. Target release lifecycle required by Phase 1 trust model

The accepted target flow should be:

1. A reviewed source commit and protected version tag identify the exact release input.
2. CI builds a deterministic package and canonical manifest, including all public browser assets and the agreed private runtime inventory.
3. GitHub/Sigstore attestation proves repository/workflow/ref/commit and exact package/manifest digests.
4. A separately controlled release-authorisation key approves the exact release identity and digests; this approval cannot be minted by the application host or by GitHub build provenance alone.
5. GitHub Release delivery supplies the immutable package and evidence. Checksums remain transport diagnostics, not trust anchors.
6. The application updater verifies provenance, release authorisation, package inventory and anti-rollback before installation; production activation must be demonstrated on the qualified host.
7. HelioHost independently obtains the approved release record from a source not controlled solely by the application host, measures live public assets and qualified private runtime files read-only, and signs a bounded report.
8. The master's phone verifies release authorisation and HelioHost report signatures against independently bootstrapped/pinned trust roots, checks release/digests/policy/freshness/challenge/epoch, and fails closed when any evidence is absent or invalid.
9. Any rollback is a separately authenticated owner decision bound to the exact previous release; it does not disable general anti-rollback.

## 7. Evidence boundary and explicit non-actions

**Verified from repository source/configuration:** workflow definitions, package builder, manifest builder, native verifier, provenance parser/policy, TUF root store, updater, release download policy, updater endpoint, and associated regression workflows.

**Verified from live GitHub metadata:** active main/tag rulesets and their exact rules; published release metadata and assets; the latest release's `immutable: false` state; 19 successful check runs on the Phase 0.6 merge commit.

**Not established:** actual production host state, deployed VERSION or asset bytes, production private dependency installation, production updater selection, private runtime permissions, HelioHost account/isolation/capabilities, any verifier key/report, master-phone trust roots, PWA runtime, release authorisation, or production acceptance.

No source runtime, production configuration, credentials, secrets, cryptographic keys, trust baselines, release assets, or deployments were changed by this audit. No keys were generated and no release was published.

## 8. Phase 2.1 closure

Phase 2.1 is complete as a repository/live-GitHub inventory. Its output is this artifact. It does not close Phase 2 as a whole and does not authorise implementation or production changes.

**Next planned item: Phase 2.2 — define the canonical signed release manifest and inventory coverage for HTML, JavaScript, CSS, PWA manifest, icons, service worker, and the qualified server-side runtime.** This design must explicitly distinguish package inventory from live deployment measurement and must not assume a PWA shell already exists.
