# Legacy GitHub CLI attestation adapter

**Status:** Superseded for production updater use by the native PHP Sigstore
verifier documented in docs/native-php-release-attestation.md.

The current UpdateManager no longer creates a GitHub CLI verifier by default and
does not read SENTRYIQ_GH_BINARY. Production update application requires the
private Composer autoloader configured in the private sentryiq_config.php and
fails closed when it is missing or unsafe.

GitHubCliAttestationVerifier remains in the repository only as an explicitly
injected test adapter for legacy updater contract tests. It is not selected by
the production update endpoint. No shell, exec(), proc_open(), or external CLI
is required by the native production verification path.

The test adapter's synthetic verifier output does not test cryptography. The
native verifier's cryptographic and actual-release integration coverage is
documented in docs/native-php-release-attestation.md.
