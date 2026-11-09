# Canonical release inventory manifest

**Status:** Implemented in the release-build workflow; not yet enforced by the updater.

The release workflow now generates a deterministic JSON inventory in two places:

- `update-manifest.json` inside the update ZIP;
- `release-manifest.json` as a separate GitHub Release asset.

The inventory binds the release version, source repository and immutable repository ID, source commit, workflow path, and every packaged file's relative path, byte length, and SHA-256 digest. Runtime files are inventoried separately from public files. The manifest builder rejects symbolic links and incomplete packages.

The workflow requests GitHub build-provenance attestations for both the ZIP and the external inventory manifest. The manifest is also published with a SHA-256 sidecar for transport diagnostics.

## Trust limitations — intentionally not hidden

This is **not a release-signing system**. The JSON manifest is not self-authenticating, and its adjacent checksum is not an independent trust anchor. Trust in the external manifest currently depends on successful independent verification of its GitHub provenance attestation against the expected repository, workflow, issuer, and source tag.

The updater does not yet fetch or verify this manifest or its attestation. Do not treat this change as production update enforcement, and do not enable automatic installation based on this manifest alone.

A separate offline or hardware-backed release-signing key, key custody and rotation policy, monotonic anti-rollback state, and updater integration remain outstanding decisions/work. The two Integrity Nodes must independently pin the approved trust material; the production origin must not control it.

## Validation

Run:

```sh
python3 tests/build_release_manifest.test.py
```

The tests cover deterministic output, file hashes and sizes, repository/build identity fields, and rejection of malformed or incomplete input.
