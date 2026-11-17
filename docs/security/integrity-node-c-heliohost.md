# Integrity Node C — HelioHost deployment boundary

## Purpose

Node C is an additional independently identified public-origin verifier intended for the separate HelioHost account. Its report identity is `integrity-c`. It is not Node 4.

Node 4 is BTM-SA on the same host as the SentryIQ application. It receives and correlates the two mandatory independent Node A/B reports. Node C remains an additional security node and must not be treated as a substitute for either A or B.

## HelioHost execution constraints

The HelioHost shared-hosting environment disables process execution functions such as `proc_open`, `exec`, and `popen`. Node C must not invoke a shell, GitHub CLI, Composer process, or local executable. Its network operations use PHP cURL with HTTPS certificate and hostname validation, no redirects, bounded response sizes, and request timeouts.

## Native Sigstore adapter

The native PHP adapter is now implemented on the SentryIQ branch in PR #46:

- `NativeSigstoreIntegrityAttestationVerifier` implements the callable contract accepted by Nodes A/B/C.
- It verifies `release-manifest.json` and `sentryiq-<version>.zip` as separate GitHub attestation subjects.
- It uses the pinned `k2gl/sigstore-verify 1.6.1` and patched `k2gl/tuf 1.2.1` packages, verifies the Sigstore bundle and SLSA provenance, and applies the release trust/anti-rollback policy.
- It uses PHP HTTPS/cURL and does not require shell execution.

The adapter is code-complete and its PHP 8.1–8.5 CI matrix has passed. **It is not yet merged, installed, configured, or wired into a live Node C runtime.** Until those steps are completed and live-tested, Node C remains non-operational and must fail closed. Do not use `GitHubCliAttestationVerifier` on HelioHost or downgrade to checksums/unsigned API metadata.

The adapter wiring contract is documented in `docs/security/native-sigstore-integrity-node-adapter.md`. Node C must instantiate only its own signer identity and use administrator-controlled private paths for the vendor autoloader and writable TUF data directory.

## Runtime requirements — not performed

- Install the pinned private Composer vendor tree outside the web root. The existing HelioHost private vendor installation is a candidate dependency source, but its absolute path and compatibility with the final merged branch must be checked during deployment.
- Provide a private writable data directory for the persistent Sigstore TUF root.
- Generate a unique Ed25519 key for `integrity-c`; never reuse A/B keys or commit the private key.
- Store the key and any node-specific credentials outside the web root in protected configuration.
- Supply a fresh 32-byte nonce from the event plane only if the Node C runtime is explicitly configured to use that protocol; Node 4 currently accepts only the mandatory A/B identities.
- Configure an explicit public-path allowlist. Never infer that private PHP/config files are externally fetchable.
- Configure a direct owner alert path independent of Node 4.
- Use an administrator-controlled schedule independent of SentryIQ and Nodes A/B.
- Restrict any HTTP trigger endpoint with authentication, replay protection, rate limiting, and no secrets in URLs or logs.

## Status

Native PHP attestation adapter: implemented in PR #46; PHP 8.1–8.5 CI passed.

HelioHost runtime integration, absolute private paths, Node C key provisioning, protected configuration, public-path inventory, independent schedule, direct alert delivery, and live end-to-end validation: not yet performed.

No HelioHost files or production configuration have been changed by this documentation update.
