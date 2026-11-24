# Release provenance — current repository evidence and limits

**Canonical repository:** `Double-IQ/SentryIQ`  
**Canonical application target:** `https://sentryiq.bichet.co.za`  
**Status:** Generic GitHub build-provenance and native updater verification code exist in the repository. Production activation is unverified. The independent release-authorisation and single-HelioHost-verifier layers remain design work.

## 1. What the release workflow produces

The tag-triggered release workflow builds the update ZIP and canonical release inventory. It requests GitHub Actions build-provenance attestations for the ZIP and external inventory manifest. The inventory binds the release identity, source repository/commit/workflow, and packaged file inventory.

The adjacent SHA-256 sidecar is useful for transfer diagnostics but is not a trust anchor. Trust comes from successful verification of an attestation against expected GitHub/Sigstore roots and a narrowly defined workflow/repository/ref policy.

## 2. Native updater verification

The repository contains a native PHP Sigstore verifier path. When correctly configured with its private Composer dependencies, the updater is designed to:
- Resolve a release tag to its immutable commit.
- Verify the downloaded ZIP's GitHub/Sigstore attestation before extraction.
- Bind the attestation to the expected repository, source ref/commit, approved workflow identity, and exact artifact digest.
- Validate the embedded canonical inventory against the resolved commit and extracted file inventory.
- Fail closed when the native verifier is required but unavailable or invalid.

These are source/CI capabilities. They do **not** establish that the production installation has the private dependencies installed, selects the native verifier, or has passed a live production acceptance test. No production release, verifier activation, or deployment is claimed here.

## 3. TUF metadata and persistence

The native verifier includes TUF root refresh and persistence support, including monotonic root-version handling and protected local state. Repository tests exercise refresh, restart reuse, and preservation of the last trusted root after incomplete refresh.

CI tests do not establish the durability or isolation of a particular production host. Filesystem permissions, process ownership, web-SAPI configuration, private storage, and crash behaviour require host qualification and acceptance testing.

## 4. Independent release and verifier trust are separate

GitHub provenance is evidence about the build process; it is not owner release authorisation and is not independent deployed-code measurement.

The target architecture has one independent HelioHost verifier with its own dedicated report-signing key. It is not a legacy Node C, does not require Nodes A/B, does not report through the old Node 4 event plane, and must not share the GitHub release workflow's signing identity or master-device keys.

The owner’s master phone must independently trust the release-authorisation and verifier trust roots. The verifier must not receive application write credentials, user content keys, recovery material, or master-device private keys.

See the [release trust policy](release-trust-policy.md), [Phase 1 trust boundaries](../architecture/phase-1-data-flow-and-trust-boundaries.md), [key-role separation](../architecture/phase-1-key-role-separation.md), and [Phase 1.9 threat model](../architecture/phase-1-runtime-and-supply-chain-threat-model.md).

## 5. Remaining production and design gates

1. Confirm repository rulesets, protected tags, workflow permissions, and independent review controls.
2. Complete Phase 2 design for canonical manifest coverage, trust-root distribution/rotation, release authorisation, and rollback policy.
3. Define a versioned verifier report with nonce/challenge, target origin, manifest/artifact digests, freshness, expiry, replay prevention, and phone-side signature verification.
4. Qualify HelioHost private storage, read-only measurement, scheduler/runtime, process isolation, and verifier-key custody.
5. Install and verify pinned private native dependencies on the intended production host only after explicit approval.
6. Conduct adversarial tests for forged, stale, replayed, wrong-identity, wrong-digest, rollback, and verifier-outage cases.
7. Obtain explicit owner approval before production key generation, trust baseline initialisation, release publication, migration, or deployment.

## 6. What provenance does not prove

A successful GitHub/Sigstore attestation does not prove the source code is benign, that the workflow was independently reviewed, that the release was separately owner-authorised, that the production host is uncompromised, or that browser-delivered code is safe at runtime. Those claims require separate controls and evidence.

**Safety boundary:** This document records repository capability and outstanding gates. It does not authorise production changes.
