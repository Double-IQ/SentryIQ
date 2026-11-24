# Release trust policy — current architecture

**Status:** Repository release-provenance controls and native updater verification exist in code/CI. Production-host activation is not verified. The independent release-authorization and HelioHost verifier trust layers remain design work; this policy does not claim they are deployed.

**Application target:** `https://sentryiq.bichet.co.za`  
**Canonical repository:** `Double-IQ/SentryIQ`  
**Independent verifier target:** one specialised HelioHost verifier. It is not a release signer and is not a second application host.

## 1. Separate trust roles

These roles must remain cryptographically and operationally separate:

1. **GitHub build provenance:** attests which repository, source ref/commit, workflow identity, and artifact digest produced a release artifact.
2. **Release authorisation:** a separately controlled approval over the exact release identity/digest. This layer is not yet implemented as the final owner-controlled trust mechanism.
3. **HelioHost verifier report:** independently measures the agreed deployed release/runtime surface and signs its own report with a dedicated verifier key. It must not inherit the old A/B/C identities or share the release-authority key.
4. **Master-phone trust:** the owner's master device independently verifies/pins approved release and verifier trust roots. It is not a GitHub workflow identity.
5. **Device and content keys:** master/device signing, key agreement, data roots, object DEKs, recovery materials, and session credentials are separate roles and never serve as release-signing keys.

The Phase 1 cryptographic profile, key-role separation, trust boundaries, and threat model are authoritative for the target roles. See [cryptographic profile](../architecture/phase-1-cryptographic-profile.md), [key-role separation](../architecture/phase-1-key-role-separation.md), [trust boundaries](../architecture/phase-1-data-flow-and-trust-boundaries.md), and [runtime/supply-chain threat model](../architecture/phase-1-runtime-and-supply-chain-threat-model.md).

## 2. GitHub provenance verification requirements

A verifier consuming a GitHub/Sigstore attestation must check all of the following against explicit policy, not values copied from the artifact itself:

- Signature and certificate chain validate against the expected Sigstore/GitHub trust roots.
- The attestation subject digest equals the exact downloaded artifact bytes.
- Source repository identity is the canonical repository `Double-IQ/SentryIQ` (and immutable repository ID where supported).
- Source ref is the approved immutable version tag and source commit is the commit intended for release.
- Signer workflow identity is the reviewed release workflow path and approved repository identity.
- Workflow event, run conclusion, and source ref satisfy the release policy.
- ZIP and manifest subjects, where both are published, are individually digest-bound and mutually consistent.

A SHA-256 sidecar is transport-integrity metadata, not an independent trust anchor. An attacker able to replace both an artifact and its adjacent checksum can replace both.

A valid build attestation proves provenance under the GitHub Actions/Sigstore trust model. It does not prove source code is benign, workflow policy was independently reviewed, a release was owner-authorised, or the deployed browser/runtime is uncompromised.

## 3. Repository workflow disposition

- `.github/workflows/release.yml` remains the generic tag-triggered package and provenance workflow. Its `contents: write`, `id-token: write`, and `attestations: write` permissions are security-sensitive and must remain minimal.
- `.github/workflows/release-manifest-tests.yml` remains generic PR/main validation for deterministic package inventory.
- `.github/workflows/native-release-attestation.yml` remains native updater/Sigstore regression coverage. Its generic release-verification tests remain relevant; any legacy adapter fixture is compatibility regression coverage only, not a production multi-node topology.
- `.github/workflows/native-sigstore-integrity-node.yml` remains temporarily as regression coverage for legacy verifier classes and native trust components while the replacement single-verifier contract is designed. It is not a deployment workflow and grants only read access. Its A/B/C, private-host, and Node 4 test cases must not be interpreted as live services or active deployment requirements.
- `.github/workflows/integrity-node-tests.yml` remains legacy code regression coverage pending the reviewed replacement verifier/test suite. It does not provision or execute any remote node.
- The obsolete `.github/workflows/node-a-commit-generated-lockfile.yml` workflow, which granted `contents: write` to push a generated lockfile to a retired Cloudflare branch, is removed from the active workflow set. Its historical contents are retained under `docs/security/archive/`.

No Cloudflare Worker, R2, Durable Object, Val Town service, A/B/C node, or Node 4 deployment is part of the current target. The owner confirmed none of those legacy nodes was provisioned.

## 4. Required repository controls

Before treating GitHub as a production release trust authority, an authorised repository administrator must configure and verify:

1. Pull-request review and required CI checks on `main`.
2. No routine direct pushes, force pushes, or branch deletion on `main`.
3. Protected version tags matching the release naming convention.
4. Restricted release creation and workflow modification permissions.
5. Least privilege for every workflow receiving `contents: write`, `id-token: write`, or `attestations: write`.
6. Independent review of release-workflow changes and CODEOWNERS/ruleset coverage for trust-critical paths.

Repository configuration must be inspected live; a document or passing CI run is not proof that branch rules are enabled. The prior repository inspection found branch protection disabled at that time; this must be rechecked rather than assumed unchanged.

## 5. Native updater enforcement boundary

The repository contains a native Sigstore release-verifier path used by the updater when its private verifier dependencies/configuration are supplied. The code path is designed to verify the downloaded ZIP before extraction, bind it to repository/workflow/ref/commit provenance, and validate the embedded inventory against the extracted package. This is source-level capability, not evidence that the production host has the dependencies installed or that production is selecting the native path.

Production activation remains unverified. Do not infer deployment, release publication, or successful production enforcement from CI, a built dependency artifact, or repository code.

## 6. Fail-closed requirements

The updater and future phone-side release gate must reject:
- Missing, invalid, expired, wrong-repository, wrong-workflow, wrong-ref, or wrong-commit attestations.
- Subject digest mismatch or inconsistent ZIP/manifest inventory.
- Unsupported manifest/profile versions, downgrade attempts, or rollback below accepted monotonic state.
- Missing or untrusted release-authorisation evidence.
- Invalid, stale, replayed, incorrectly scoped, or incorrectly signed verifier reports.
- Verifier outages or unavailable trust metadata when the operation requires fresh verification.

A deliberately approved rollback must be a separately authenticated, auditable action with explicit version/digest binding; it must not disable general anti-rollback checks.

## 7. Remaining gates

1. Complete Phase 0.6 repository contract/workflow/document reconciliation.
2. Complete Phase 2 release manifest, trust-root distribution, independent release-authorisation, HelioHost verifier, report freshness, and phone-side verification design.
3. Qualify HelioHost isolation and key custody before any verifier key generation or deployment.
4. Obtain owner decisions recorded in the [Phase 1 consolidated owner-review baseline](../architecture/phase-1-consolidated-owner-review-baseline.md).
5. Separately authorise production key initialisation, release publication, migration, and deployment.

**Safety boundary:** No production key, verifier identity, baseline, deployment, release, or trust-root change is authorised by this document.
