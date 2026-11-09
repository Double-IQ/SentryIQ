# Temporary HelioHost Sigstore/TUF runtime probe

This folder is an isolated test harness for the candidate dependency used by
PR #33. It is **not** part of SentryIQ's production dependency tree and must
not be copied into the public web root permanently.

## What it checks

- PHP 8.1 or newer and required JSON/OpenSSL extensions;
- Sodium and cURL availability, plus the PHP stream fallback setting;
- PHP memory/time limits and whether common shell functions are disabled;
- outbound HTTPS to Sigstore's public TUF repository;
- a complete TUF refresh from the package's bundled bootstrap root, including
  any root versions available for rotation, current timestamp/snapshot/targets
  metadata, and the authenticated `trusted_root.json` target.

The probe does not print environment variables, application configuration,
private keys, or user data. It does not write or persist a trust root and does
not modify SentryIQ. It intentionally uses the package's default HTTPS fetcher.

## Run on the actual HelioHost account

1. Upload this folder to a temporary directory outside the public web root if
   possible.
2. In that directory, run `composer install --no-interaction --no-dev --prefer-dist`
   if Composer is available. For this isolated probe only, resolve the exact
   dependency pinned in `composer.json`; do not add it to SentryIQ's main
   `composer.json`.
3. Run `php probe.php` using the same PHP version and account that would run
   Node C.
4. Save the JSON output and share it for review. Do not share hosting passwords,
   API tokens, private keys, or the contents of the hosting account.
5. Delete the temporary probe directory and its vendor folder after testing.

If the account does not provide Composer/SSH, do not enable shell access or
change hosting settings just for this test. We can prepare a separate upload
bundle after confirming the account's supported PHP version and file limits.

## Interpreting the result

- `status: passed` proves that this PHP runtime completed a live Sigstore TUF
  refresh and parsed the authenticated trust root at the time of the test.
- It does **not**, by itself, prove a root key was rotated during that run.
  A separate controlled rotation test and offline/expired-metadata negative
  tests are still required.
- `status: failed` means Node C must remain fail-closed. The exception class
  and message are included to help diagnose transport, TLS, expiry, or metadata
  failures.
- This probe does not validate Node C's future production bundle-fetcher,
  request authentication, caching, replay protection, or alert integration.

## Trust-root expiry and outage policy

The candidate's bundled bootstrap TUF root currently declares expiry
`2026-11-20T13:58:18Z`. That bootstrap root is a starting trust anchor, not a
reason to skip TUF refresh: the TUF client must walk forward through valid
root rotations and verify fresh timestamp, snapshot, and targets metadata.
Do not fall back to an expired cached trust root or accept stale metadata when
refresh fails. Production must define and test secure persistence of a
successfully rotated root before Node C can be enabled.
