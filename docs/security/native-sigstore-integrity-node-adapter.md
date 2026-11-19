# Native Sigstore adapter for Integrity Nodes A, B and C

## Purpose

`NativeSigstoreIntegrityAttestationVerifier` implements the callable contract
used by the public-origin Integrity Node verifiers. It connects Nodes A, B and
C to the same native PHP Sigstore/TUF trust path used by the updater. It does
not invoke GitHub CLI, a shell, Composer, or a local executable.

For each candidate deployed release, the node verifies two separate subjects:

1. `release-manifest.json`
2. `sentryiq-<version>.zip`

The current release workflow attests both assets. Each artifact is independently
hashed, looked up through GitHub's attestation API, and verified against the
Sigstore trusted root. The authenticated Fulcio leaf certificate and SLSA
provenance are checked for the pinned issuer, release workflow identity,
repository ID, tag, source commit, workflow commit, hosted-runner context and
exact subject digest/name. The source tag is independently resolved through
GitHub and must point to the attested source commit.

The manifest is not trusted merely because it was downloaded beside the ZIP.
Its own attestation must pass before the node uses its file inventory. The ZIP
is then independently attested and verified against the same release identity.

## Anti-rollback policy

The updater's default release policy remains strictly newer-than-installed.
Integrity Nodes need to verify the release already deployed at the origin, so
the adapter explicitly enables equality for that one policy call. Older
versions remain rejected even in integrity-node mode. This exception is not
controlled by request data and is not used by the updater.

## Private runtime requirements

Each node requires:

- PHP with cURL, OpenSSL and Sodium.
- The pinned private Composer vendor tree containing
  `k2gl/sigstore-verify 1.6.1` and the patched `k2gl/tuf 1.2.1`.
- The vendor autoloader under that node's own private data directory, outside
  its public webroot.
- A private writable data directory for the persistent Sigstore TUF root.
- Its own Ed25519 report-signing key, protected runtime configuration and
  direct owner-alert transport.

The adapter constructor fails closed if the private autoloader is missing,
symlinked, outside private storage, or contains the wrong dependency versions.
The verifier also requires the patched TUF runtime classes. Do not copy a
node's signing key, tokens, mutable state or private configuration to another
node.

## Wiring

Construct one adapter in each node's protected bootstrap:

```php
$verifyAttestation = NativeSigstoreIntegrityAttestationVerifier::fromPrivatePaths(
    '/absolute/private/path/sigstore-vendor/vendor/autoload.php',
    '/absolute/private/path/to/private-data'
);
```

Pass that callable to exactly one node verifier on the corresponding host.
Nodes A and B additionally require their own independently pinned private-host
attestation gate and Node 4 event exchange. Node C remains independent of Node
4 and must retain its own direct owner-alert path.

The release artifact fetcher is responsible for staging the manifest and ZIP
in a private per-release directory. It must not place either artifact in the
public webroot. The adapter accepts only the canonical manifest filename and
the version-matched ZIP filename.

## Validation and deployment boundary

CI exercises the adapter contract and release policy across PHP 8.1–8.5. The
actual published v0.1.2 release ZIP is verified end to end against its genuine
GitHub attestation. That historical release predates a separately published
manifest asset, so the real-release integration currently covers the ZIP;
manifest subject binding is covered by policy tests and the current release
workflow emits an attestation for the manifest on subsequent releases.

This code does not provision a node, install dependencies on a host, create
keys or tokens, configure schedules, choose alert providers, or deploy a
monitor. HelioHost/cPanel compatibility, actual private paths, outbound HTTPS,
resource limits, live release selection, baseline initialization, direct
alerts and end-to-end scheduled operation must be verified on each node before
it is treated as operational.
