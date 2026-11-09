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

## Build the upload bundle

The GitHub Actions workflow
`.github/workflows/heliohost-tuf-probe-bundle.yml` installs the pinned
Composer dependency on a clean GitHub-hosted runner and publishes a ZIP artifact
named `sentryiq-heliohost-tuf-probe` for seven days. The ZIP contains:

- `httpdocs/probe.php`: the one-shot web endpoint;
- `private/vendor/`: Composer dependencies, intended to remain outside the
  public document root;
- `BUILD-INFO.txt` and `SHA256SUMS`: build details and file hashes.

The bundle is temporary test material, not a production release.

## Run on the actual HelioHost account without SSH

undefined

**Important:** do not put the `vendor` directory under `httpdocs`, do not
leave the endpoint online, and do not upload this bundle into the SentryIQ
production application directory. If Plesk File Manager cannot access the
parent directory of `httpdocs`, stop and report that; do not place dependencies
in the public directory as a workaround.

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

## Runtime limits and expiry policy

The candidate's bundled bootstrap TUF root currently declares expiry
`2026-11-20T13:58:18Z`. That bootstrap root is a starting trust anchor, not a
reason to skip TUF refresh: the TUF client must walk forward through valid
root rotations and verify fresh timestamp, snapshot, and targets metadata.
Do not fall back to an expired cached trust root or accept stale metadata when
refresh fails. Production must define and test secure persistence of a
successfully rotated root before Node C can be enabled.

The current HelioHost account reports a 30-second PHP execution limit. The
probe does not attempt to bypass hosting limits. A timeout is an inconclusive
runtime result and must not be treated as a successful refresh.
