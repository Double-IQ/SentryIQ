# Integrity Node C — HelioHost compatibility boundary

## Purpose

Node C is a third independently identified public-origin verifier intended for a separate HelioHost account. It uses the shared verifier contract but must have its own runtime, administrator-controlled schedule, signing key, and direct alert destination. Its report identity is `integrity-c`.

## HelioHost execution constraints

The HelioHost shared-hosting environment documents that process execution functions such as `proc_open`, `exec`, and `popen` are disabled. Node C therefore does not invoke a shell, GitHub CLI, Composer process, or local executable. Its origin fetch uses PHP cURL with HTTPS-only transport, certificate and hostname verification, no redirects, bounded response size, and request timeouts.

## Critical attestation adapter requirement

The Node C class deliberately receives its attestation verifier as an injected callable. PR #48 now adds `NativeSigstoreIntegrityAttestationVerifier`, a native PHP/HTTPS adapter that independently verifies the canonical manifest and ZIP using GitHub artifact attestations, Sigstore TUF, and the SentryIQ provenance policy. It does not invoke GitHub CLI or process execution. The adapter is still an unmerged dependency and must be installed and wired from the private Composer autoloader on Node C before production use.

The existing `GitHubCliAttestationVerifier` invokes GitHub CLI through `proc_open` and is not suitable for HelioHost. Do not wire that class into Node C or treat the injected test callback as real verification. Node C must fail closed rather than downgrade to checksum-only or trust unsigned API metadata.

## Runtime requirements (not performed by this PR)

- Generate a unique Ed25519 key for `integrity-c`; never reuse A/B keys or commit the private key.
- Store the key and GitHub/API credentials outside the web root in protected HelioHost configuration.
- Use a dedicated HelioHost account and independent Plesk scheduled task; keep frequency within HelioHost resource limits.
- Generate a fresh 32-byte nonce locally for each run; Node C does not use Node 4's challenge API, which is deliberately limited to Nodes A/B. Persist C's signed report in its own private evidence store and prevent local replay/overwrite.
- Configure an explicit public-path allowlist. Never infer that private PHP/config files are externally fetchable.
- Configure and test the direct owner-alert callback added to `IntegrityNodeC`; it must deliver from HelioHost to an owner destination without routing through Node 4. The callback is an injection point, not a configured mail/webhook transport.
- Restrict any HTTP trigger endpoint with authentication, replay protection, rate limiting, and no secrets in URLs or logs.

## Status

PR #50 adds the native PHP Sigstore runtime wiring and a signature-verified append-only private evidence store for Node C. These are repository implementations and CI-tested contracts only; they are not installed or wired on HelioHost. No HelioHost account provisioning, key generation, schedule, private evidence directory, direct alert transport, or production deployment has been performed.
