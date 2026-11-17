# Native Sigstore adapter for Integrity Nodes A, B and C

## Purpose

`NativeSigstoreIntegrityAttestationVerifier` implements the callable contract accepted by `IntegrityNodeA`, `IntegrityNodeB` and `IntegrityNodeC`. It connects those public-origin verifiers to SentryIQ's native PHP Sigstore/TUF verification path without invoking a shell or GitHub CLI.

The node classes invoke the callback twice for each release:

1. `release-manifest.json`
2. `sentryiq-<version>.zip`

Each artifact is independently looked up by its SHA-256 digest in GitHub's attestation API. Its Sigstore bundle is verified against refreshed TUF trust metadata, then its SLSA subject name, digest, repository, tag, workflow and source commit are checked. The release trust policy is applied separately to each subject. Integrity-node mode permits the currently deployed version to be verified (version equality) while still rejecting any older release; the updater's default policy remains strictly newer-than-installed.

## Private runtime requirements

Each node needs:

- PHP with cURL, OpenSSL and sodium support.
- A private Composer vendor tree containing the pinned `k2gl/sigstore-verify 1.6.1` and patched `k2gl/tuf 1.2.1` dependencies.
- The vendor `autoload.php` outside the public webroot.
- A private writable data directory for the persistent Sigstore TUF root.
- The node's own signing key and identity, separate from the verifier dependencies.

The verifier uses HTTPS with peer and hostname validation, refuses redirects, bounds response sizes and timeouts, and does not require `exec`, `proc_open`, GitHub CLI or an installed Git binary.

## Wiring

Construct the callback once in the node's protected runtime bootstrap. Each node's direct owner-alert callback is mandatory and must use a separately configured transport that does not depend on Node 4:

Example for **Node A's host only**:

```php
$verifyAttestation = NativeSigstoreIntegrityAttestationVerifier::fromPrivatePaths(
    '/absolute/private/path/vendor/autoload.php',
    '/absolute/private/path/data'
);

$nodeA = new IntegrityNodeA($integrityASigner, $verifyAttestation, null, $nodeAOwnerAlert);
```

Node B and Node C each construct the same adapter independently from their own private vendor/data paths and instantiate only their own signer and verifier class. Never place multiple nodes' signing keys or runtime credentials on one host.

Instantiate only the node that belongs to that host. Never share signing keys or signer objects across nodes. Node A, B and C each retain their own identity and runtime configuration.

The node's local manifest file must be named exactly `release-manifest.json`; the package file must be named exactly `sentryiq-<version>.zip`. These names are compared with the authenticated SLSA subjects, not inferred from an untrusted checksum file.

## Host placement

- Nodes A and B: install the pinned vendor tree in each node's private filesystem, outside its webroot.
- Node C on HelioHost: use a private vendor autoload path in the HelioHost account; the implementation does not depend on shell functions disabled by that host.
- Node 4 / BTM-SA: this is the event receiver on the same host as SentryIQ. It is not an independent physical failure domain and does not replace A/B/C verification.

The private data directory and vendor path are deployment-specific. Do not copy the example paths literally or expose either directory through HTTP.

## What this does not do

This adapter does not provision hosts, generate or distribute node keys, configure per-node tokens, schedule checks, configure alert destinations, or deploy any code. Those remain separate, independently authorized operations. The adapter is not a reason to put node signing keys on the SentryIQ application host.
