# Temporary HelioHost native Sigstore attestation test

This is an isolated, one-shot runtime check for the native PHP Sigstore verifier on the actual HelioHost PHP web-SAPI. It verifies the published SentryIQ v0.1.2 release ZIP against its genuine GitHub Sigstore/SLSA attestation using the pinned `k2gl/sigstore-verify:1.6.1` dependency.

It is a compatibility probe only. v0.1.2 is an old test fixture and is **not** approved for the new SentryIQ updater or production release.

## Bundle contents

- `httpdocs/verify-release.php`: one-shot public entry point; deletes itself at shutdown.
- `private/validate-native-php-sigstore.php`: verifier harness.
- `private/sentryiq-0.1.2.zip`: exact published release ZIP.
- `private/attestation-bundle.jsonl`: genuine GitHub SLSA provenance bundle.
- `private/vendor/`: Composer dependency pinned to `k2gl/sigstore-verify:1.6.1`.
- `BUILD-INFO.txt` and `SHA256SUMS`: build identity and file hashes.

## Run on HelioHost without SSH

1. Download the `sentryiq-heliohost-v0.1.2-attestation` artifact from the successful GitHub Actions run linked in PR #34.
2. Verify the downloaded artifact archive SHA-256 against the GitHub Actions artifact metadata, then extract it locally.
3. Verify the extracted files with `sha256sum -c SHA256SUMS` (or compare the recorded hashes with your local SHA-256 utility on Windows).
4. In HelioHost's file manager, confirm the account's `httpdocs` document root and its parent directory. Do not place dependencies in `httpdocs`.
5. Upload `httpdocs/verify-release.php` into `httpdocs`, renaming it to a fresh unpredictable filename before the upload.
6. Upload the extracted `private` directory beside `httpdocs` and rename it to `sentryiq-probe-private`. The required autoloader path is `../sentryiq-probe-private/vendor/autoload.php` relative to `httpdocs`.
7. Request the one-shot endpoint exactly once. Save the complete text response and the matching `BUILD-INFO.txt`. The endpoint removes itself after execution.
8. Confirm that the result explicitly reports successful native Sigstore verification. A timeout or HTTP error is inconclusive, not a pass.
9. Remove the `sentryiq-probe-private` directory after recording the result. Confirm the one-shot endpoint is absent from `httpdocs`.

If the file manager cannot access a sibling directory outside `httpdocs`, stop. Do not place Composer dependencies, the release ZIP, or the attestation bundle in the public web root as a workaround.

## Safety and interpretation

- No production SentryIQ files, runtime configuration, credentials, users, or vault data are read or modified.
- The endpoint emits only verifier result information; it does not print environment variables or secrets.
- The endpoint deletes itself after the response. If a timeout prevents normal shutdown, manually remove the uploaded script immediately.
- This test proves that the candidate verifier can validate this known published artifact on the tested HelioHost runtime. It does not prove a TUF root rotation occurred, establish Node C's independent host identity, or deploy/activate Node C.
- Node C remains fail-closed until separate root-rotation, expiry, rollback, offline, persistence, alert, and scheduled-runtime tests are accepted.
