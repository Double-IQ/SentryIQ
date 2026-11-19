# Integrity Node C — HelioHost deployment boundary

## Purpose

Node C is an additional independently identified public-origin verifier on a
separate HelioHost account. Its identity is `integrity-c`. It is not Node 4
and is not a substitute for either mandatory Integrity Node A or B.

Node 4 is BTM-SA on the same physical host as SentryIQ. It receives and
correlates A/B reports but is not an independent host failure domain. Node C
must retain its own schedule, signing key, private state and direct owner-alert
path.

## HelioHost execution constraints

The HelioHost shared-hosting environment disables process execution functions
such as `proc_open`, `exec` and `popen`. Node C must not invoke a shell,
GitHub CLI, Composer process or local executable. Its origin and attestation
network operations use PHP cURL with HTTPS certificate and hostname
verification, no redirects, bounded response sizes and request timeouts.

## Native Sigstore adapter

`NativeSigstoreIntegrityAttestationVerifier` implements the callable
contract accepted by Nodes A/B/C. It verifies `release-manifest.json` and
`sentryiq-<version>.zip` as separate GitHub attestation subjects using the
native PHP verifier, pinned Sigstore TUF trust root and SentryIQ release
policy. It checks the authenticated Fulcio certificate and SLSA provenance,
including repository ID, workflow identity, issuer, tag, source/workflow
commit, hosted-runner context and exact subject digest.

The adapter is code in the repository, but Node C is not operational until it
is merged, installed and wired into a protected HelioHost runtime. Do not use
`GitHubCliAttestationVerifier` on HelioHost or downgrade to checksums or
unsigned API metadata. A missing verifier, private vendor package or TUF root
must fail closed.

See `docs/security/native-sigstore-integrity-node-adapter.md` for the shared
A/B/C contract.

## Runtime requirements — not performed

- Install the pinned private Composer vendor tree outside the webroot. The
  absolute path must be verified on the actual HelioHost account.
- Provide a private writable data directory for the persistent Sigstore TUF
  root and node-local evidence.
- Generate a unique Ed25519 key for `integrity-c`; never reuse A/B keys or
  commit the private key.
- Store the key and any node-specific credentials outside the webroot in
  protected configuration.
- Configure an explicit public-path allowlist. Never infer that private PHP
  or configuration files are externally fetchable.
- Configure a direct owner-alert path independent of Node 4.
- Use an administrator-controlled schedule independent of SentryIQ and Nodes
  A/B, within HelioHost resource limits.
- Verify PHP extensions, outbound HTTPS, filesystem permissions, clock
  freshness, execution time and memory on the actual account.
- Initialize the monotonic baseline once with `bin/integrity-node-baseline.php`
  after independently confirming the known-good deployed version, source
  commit, manifest digest and ZIP digest. The CLI pre-provisions the state lock
  and refuses to overwrite an existing baseline. Never initialize from the
  live origin's claim alone; delete the one-time baseline config after use.

## Local evidence retention

Node C stores each signed result under its private data directory with exact
0600 file permissions. Evidence older than 30 days is pruned on the next
successful append; recent records are never silently discarded. The hard cap
is 10,000 records. At a fifteen-minute schedule, 30 days produces about 2,880
records. Schedule Node C no more frequently than every fifteen minutes unless
the run-lock and evidence capacity are deliberately revalidated.

## Regression coverage

Synthetic node tests verify that manifest-attestation failure and
artifact-attestation failure abort before origin approval, and that origin
network failure produces a signed rejection rather than approval. Native
adapter tests cover canonical manifest/ZIP subject selection, same-version
monitoring and anti-rollback. The real v0.1.2 ZIP attestation is verified in CI;
that historical release predates a separately published manifest asset.

These tests do not replace HelioHost runtime validation, independent key
provisioning, schedule setup or live end-to-end monitoring.

## Status

Native PHP Sigstore adapter: merged to `main`; native verification and PHP 8.1–8.5 CI acceptance passed.

HelioHost runtime integration, absolute private paths, Node C key provisioning,
protected configuration, public-path inventory, independent schedule, direct
alert delivery and live end-to-end validation: not performed.

No HelioHost files or production configuration have been changed.
