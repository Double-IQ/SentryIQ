# Canonical release inventory manifest

**Status:** The release workflow builds and publishes a deterministic inventory and requests GitHub build-provenance attestations for the ZIP and external manifest. The native updater contains a path that verifies the downloaded ZIP attestation and validates the embedded inventory before extraction. Production activation remains unverified.

## 1. Inventory contents

The release workflow generates:
- `update-manifest.json` inside the update ZIP;
- `release-manifest.json` as a separate GitHub Release asset;
- SHA-256 sidecars for transfer diagnostics.

The inventory binds the release version, canonical source repository and immutable repository ID, source commit, workflow path, and packaged file inventory including relative paths, byte lengths, and SHA-256 digests. Runtime files are inventoried separately from public files. The manifest builder rejects symbolic links and incomplete packages.

The workflow requests GitHub build-provenance attestations for the ZIP and external manifest. Each attestation must be verified against the exact subject digest and approved repository/workflow/ref policy.

## 2. Verification boundary

The adjacent SHA-256 sidecar is not a trust anchor. It can detect accidental transfer corruption but cannot authenticate an artifact if the same channel can replace both the artifact and checksum.

The native updater path, when configured with its private verifier dependencies, verifies the ZIP's GitHub/Sigstore provenance before extraction and validates the ZIP-bound embedded inventory against the resolved release commit and extracted file inventory. This is repository code capability, not evidence that the production host is configured to select or successfully execute the verifier.

The separate external `release-manifest.json` attestation is independently useful for release inspection and future verifier workflows. Do not claim that an independent HelioHost verifier or master-phone gate currently consumes it; those integrations are Phase 2 design work.

## 3. What the manifest does not prove

The JSON inventory is not self-authenticating. A matching hash does not prove that source code is benign, the release was separately owner-authorised, the production host is uncompromised, or browser-delivered code is safe at runtime.

GitHub build provenance is one trust layer. The target architecture additionally requires separately controlled release authorisation, an independent HelioHost verifier report, and master-phone verification of pinned trust roots. These are separate identities and keys; none may be substituted for the other.

## 4. Validation

Run:

```sh
python3 tests/build_release_manifest.test.py
```

The tests cover deterministic output, file hashes and sizes, repository/build identity fields, and rejection of malformed or incomplete input. Native updater provenance and archive-boundary tests are maintained in the native release-attestation workflow.

## 5. Remaining gates

- Complete Phase 2 design for manifest coverage of browser-delivered assets, server-side runtime inventory, trust-root distribution, release authorisation, verifier reports, freshness, and rollback.
- Verify GitHub branch/tag rules and release workflow permissions.
- Qualify HelioHost isolation and key custody before any verifier key generation.
- Verify production updater configuration and actual host behaviour only after explicit owner authorisation.

See [release trust policy](release-trust-policy.md), [release provenance](release-provenance.md), and the [design and implementation plan](../architecture/design-implementation-plan.md).

**Safety:** No production key, release, trust baseline, or deployment is authorised by this document.
