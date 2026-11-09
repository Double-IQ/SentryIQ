# Integrity Node C — HelioHost compatibility boundary

## Purpose

Node C is a third independently identified public-origin verifier intended for a separate HelioHost account. It uses the shared verifier contract but must have its own runtime, administrator-controlled schedule, signing key, and direct alert destination. Its report identity is `integrity-c`.

## HelioHost execution constraints

The HelioHost shared-hosting environment documents that process execution functions such as `proc_open`, `exec`, and `popen` are disabled. Node C therefore does not invoke a shell, GitHub CLI, Composer process, or local executable. Its origin fetch uses PHP cURL with HTTPS-only transport, certificate and hostname verification, no redirects, bounded response size, and request timeouts.

## Critical attestation adapter requirement

The Node C class deliberately receives its attestation verifier as an injected callable. **This PR does not provide a HelioHost-ready cryptographic Sigstore/GitHub attestation adapter.** The existing `GitHubCliAttestationVerifier` invokes GitHub CLI through `proc_open` and is not suitable for HelioHost. Do not wire that class into Node C or treat the injected test callback as real verification.

Before Node C can approve anything in production, implement and independently test a native PHP / HTTPS-based adapter that cryptographically validates GitHub artifact attestations and enforces the same SentryIQ policy (repository ID, workflow identity, issuer, source ref/commit, subject digest, predicate, trusted timestamp, and hosted-runner requirements). If a trustworthy native verifier cannot be delivered, Node C must fail closed and remain non-operational rather than downgrade to checksum-only or trust unsigned API metadata.

## Runtime requirements (not performed by this PR)

- Generate a unique Ed25519 key for `integrity-c`; never reuse A/B keys or commit the private key.
- Store the key and GitHub/API credentials outside the web root in protected HelioHost configuration.
- Use a dedicated HelioHost account and independent Plesk scheduled task; keep frequency within HelioHost resource limits.
- Supply a fresh 32-byte nonce from the event plane and implement replay protection there.
- Configure an explicit public-path allowlist. Never infer that private PHP/config files are externally fetchable.
- Configure a direct owner alert path independent of Node 4.
- Restrict any HTTP trigger endpoint with authentication, replay protection, rate limiting, and no secrets in URLs or logs.

## Status

Prototype implementation and synthetic contract tests only. No HelioHost account provisioning, key generation, schedule, endpoint, native attestation adapter, or production deployment is included.
