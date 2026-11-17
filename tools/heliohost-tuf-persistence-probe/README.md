# HelioHost TUF persistent-root two-request probe

This is a temporary, non-production probe for the existing patched TUF vendor
bundle in `sentryiq-tuf-patched-private/vendor`. It does not change SentryIQ
production files or enable Node C.

## What it proves

- Request 1 starts from the package's bundled Sigstore bootstrap root, performs
  a complete live TUF refresh, verifies/downloads the Sigstore
  `trusted_root.json` target, and only then persists the updater's latest
  trusted root to `tuf-root.json`.
- Request 2 is a separate HTTP request and PHP process. It loads that persisted
  root as its trust anchor, refreshes again, and reports the SHA-256 of the
  exact bytes it loaded and the verified/persisted root.
- A corrupt stored root, failed TUF refresh, or target verification failure
  returns failure; there is no fallback to the bundled root when a persisted
  root exists but is invalid.

The endpoint files delete themselves after each request. The private PHP files
and root store stay outside the web root.

## Upload and run

1. Keep the existing `sentryiq-tuf-patched-private/vendor/` directory intact.
2. Extract this ZIP locally.
3. Upload `private/TufRootStore.php` and `private/probe-common.php` into the
   existing `sentryiq-tuf-patched-private` directory beside `httpdocs`.
   Do not upload any of these private files into `httpdocs`.
4. Upload `httpdocs/refresh-root.php` and `httpdocs/reload-root.php` into
   `httpdocs`. Rename each to a fresh unpredictable filename before requesting
   it (for example, `r-<random>.php` and `l-<random>.php`).
5. Request the renamed refresh endpoint once and save its complete JSON.
   It should report `status: passed`. The endpoint deletes itself.
6. Only after step 5 passes, request the renamed reload endpoint and save its
   complete JSON. It should report `status: passed`, mode `reload`, and
   `loaded_persisted_root: true`. The endpoint deletes itself.
7. Send both JSON responses back here. Compare the first response's
   `persisted_root_sha256` with the second response's
   `starting_root_sha256`; they must match exactly.
8. After reviewing the result, remove `probe-common.php`,
   `TufRootStore.php`, `tuf-root.json`, and `tuf-root.lock` from the private
   directory. Keep or remove the vendor directory only as separately decided.

If the private directory cannot be accessed beside `httpdocs`, stop. Never
put Composer dependencies or the root store in the public web root.

## Scope

This proves persistence across two real HelioHost HTTP/PHP requests using the
actual patched updater and live Sigstore TUF repository. It does not by itself
prove an upstream root rotation happened during those two requests; the root
versions and hashes in the responses show what was loaded and verified.
