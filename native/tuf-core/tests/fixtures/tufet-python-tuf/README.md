# Signed TUF interoperability fixtures

These four metadata files are copied byte-for-byte from the Tuffet 0.1.0
upstream test repository:

- Upstream: https://github.com/rf-signing-experiment/tuffet
- Tag: `tuffet-v0.1.0`
- Source directory: `crates/tuffet/tests/data/python-tuf/metadata/`
- Upstream fixture documentation: `crates/tuffet/tests/data/README.md`

The set contains a signed root, timestamp, snapshot, and top-level targets
metadata. It is public test data; no SentryIQ production trust root or private
signing key is included. The root fixture contains an RSA-PSS root signature,
and the delegated metadata keys/role definitions are public fixture material.

The Rust tests consume these exact bytes with `include_bytes!` and verify the
complete top-level metadata refresh using Tuffet. Do not use these fixtures as
a production trust anchor or for deployment.
