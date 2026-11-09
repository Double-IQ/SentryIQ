# Native PHP Sigstore verifier evaluation

## Decision

SentryIQ will not implement Fulcio, DSSE, Rekor, Merkle proofs, signed checkpoints,
RFC 3161 timestamps, or TUF itself. The current candidate for evaluation is
`k2gl/sigstore-verify` **1.6.1**, an external PHP library that claims to implement
these checks and pass Sigstore's conformance suite.

This is an evaluation, not production approval. The package has a small public
adoption footprint and no independent security audit was identified during the
initial review. Its own conformance workflow is useful evidence, but is not a
substitute for independent review or a successful SentryIQ-specific cross-check.

## What this PR tests

The workflow downloads the exact published v0.1.2 ZIP and its genuine Sigstore
bundle from GitHub, then verifies it with the PHP library. The v0.1.2 release
predates the separately published manifest asset, so the manifest is not part
of this initial real-release test. It checks the authenticated SLSA provenance for:

- exact workflow SAN identity and GitHub Actions OIDC issuer;
- SLSA provenance v1 predicate;
- exact subject SHA-256;
- repository URI and immutable repository ID `1345956206`;
- tag-push event and exact SLSA builder workflow identity;
- exact release tag, workflow path, and source commit.

It also runs negative controls for a wrong subject digest, unrelated signer,
tampered DSSE signature, wrong repository, wrong source commit, wrong release
tag, wrong runner, wrong certificate repository/commit, and malformed DER
UTF8String encodings. The native PHP result and all negative controls passed in
CI, and the same ZIP independently passed GitHub's maintained
`gh attestation verify`.

The package is installed in a temporary CI-only directory. No dependency is
added to the SentryIQ application, release ZIP, or production runtime by this PR.

## Important limitations before production

1. This harness uses GitHub CLI only to **download** the genuine bundle and to
   provide an independent CI cross-check. The native PHP verification itself
   does not invoke a shell or executable.
2. The current test does not yet implement Node C's production GitHub API
   bundle-fetch client, bounded HTTP transport, token handling, or rate-limit
   policy.
3. The production dependency needs a committed Composer lockfile and a
   reproducible deployment bundle containing the exact dependency tree. The
   temporary CI install is not an acceptable production dependency process.
4. The Sigstore public-good TUF root is refreshed at verification time by the
   candidate library. Production must test this on HelioHost and define cache,
   expiry, rotation, and failure behaviour.
5. The candidate API exposes the verified DSSE payload and leaf certificate,
   but the adapter must still demonstrate that every legacy certificate claim
   currently required by SentryIQ (including source/signer/config digests and
   runner environment) is either checked through authenticated provenance or
   verified from the authenticated certificate. No field may be silently
   dropped.
6. HelioHost PHP version, OpenSSL, Sodium, cURL, allow_url_fopen, outbound
   HTTPS, memory, and execution-time limits must be tested on the actual account.

## Activation rule

Node C remains fail-closed and non-operational until all of the following are
complete: successful real-artifact CI cross-check; a separately attested manifest in a
subsequent release; reviewed dependency lock and deployment packaging; full
parity with the existing SentryIQ certificate/provenance policy; independent
security review of the candidate dependency; HelioHost runtime test; and
adversarial tests for malformed bundles/DER, wrong identities, wrong repositories,
wrong commits, invalid Rekor evidence, stale trust roots, and modified artifacts.
