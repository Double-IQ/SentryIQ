# k2gl/tuf 1.2.1 root-rotation hardening

This directory contains a narrowly scoped patch for the exact upstream source
revision below. It is a tracked review artifact; it does **not** vendor, install,
or activate a modified TUF library in SentryIQ.

- Package: `k2gl/tuf` 1.2.1
- Upstream repository: https://github.com/k2gl/tuf
- Exact upstream commit: `0c324cd765e04c9d47d01fe0e9887d6ab8153bfd`
- Patch: [`patches/k2gl-tuf-1.2.1-root-404.patch`](../../patches/k2gl-tuf-1.2.1-root-404.patch)

## Security behaviour

The upstream updater previously treated every `DownloadException` while
fetching the next sequential root metadata version as the normal end of the
rotation chain. That could hide server errors, transport failures, or oversized
responses.

The patch introduces `NotFoundException` as a specific `DownloadException`
subtype. Only a genuine HTTP 404 ends root rotation normally. Other failures
remain fatal. It also disables redirects in the stream transport and checks
the response-size limit before classifying the HTTP status.

Custom `Fetcher` implementations must use `NotFoundException` only for a
genuine missing object.

## Apply and validate upstream

Apply only to a clean checkout of the exact commit:

```sh
git checkout 0c324cd765e04c9d47d01fe0e9887d6ab8153bfd
git apply --check patches/k2gl-tuf-1.2.1-root-404.patch
git apply patches/k2gl-tuf-1.2.1-root-404.patch
composer validate --strict
composer install --prefer-dist --no-progress
composer test
composer phpstan
composer cs
```

The companion GitHub Actions workflow checks the patch against the pinned
upstream revision across PHP 8.1–8.5. The latest pull-request run
[44551369561](https://github.com/Double-IQ/SentryIQ/actions/runs/44551369561)
passed all five PHP matrix jobs, including Composer validation/install,
PHPUnit, PHPStan, and coding standards.

The HTTP transport tests exercise both the cURL path and the PHP stream
fallback. They verify that HTTP 404 maps to `NotFoundException`, while HTTP
500, redirects, and oversized 404 responses remain fatal download failures.
A successful 200 response is also checked.

For PHP 8.1 only, the workflow temporarily removes the development-only
`roave/security-advisories` constraint because its current metadata no longer
resolves against the hosted runner's PHP 8.1 patch level. This is a CI-only
change; it does not alter the patch or any runtime dependency.

The patch remains a review candidate rather than a production-approved
dependency: it has not been applied to SentryIQ's production runtime or
validated on the HelioHost deployment.

## Scope boundary

No SentryIQ runtime dependency, production code, release artifact, HelioHost
file, DNS setting, or deployment configuration is changed by this patch PR.


## CI compatibility note

The current `roave/security-advisories` development-only meta-package no longer resolves on the PHP 8.1 patch level supplied by the hosted runner. The validation workflow temporarily omits that development-only constraint for the PHP 8.1 test job; it does not change the package patch or any runtime dependency.

## Additional rotation and expiry regression tests

The candidate patch also adds offline regression tests for three fail-closed
conditions: a candidate root not signed by the previously trusted root, a
candidate root not signed by its own new root threshold, and an expired trusted
bootstrap root. The upstream suite already covers a successful root rotation
and verifies that the updater exposes the latest verified root bytes after
refresh. The HelioHost live probe confirms a successful refresh, but does not
claim that a root rotation occurred during that run.

The updater exposes verified root bytes to its caller; durable storage,
atomic replacement, permissions, corruption recovery, and reload across
separate PHP requests remain application-integration responsibilities and
must be tested before Node C relies on persisted rotation state.

## Durable root persistence boundary

The separate `TufRootStore` candidate persists only the exact root bytes returned
after a complete successful TUF refresh. It enforces an atomic replacement,
owner-only root-file permissions, a private-directory boundary outside the
document root, a monotonic root-version guard, and rejection of corrupt or
symlinked root/lock files. It does not verify signatures itself; callers must
never pass unverified metadata to `storeVerifiedRoot()`.

CI exercises the real pinned TUF updater against a synthetic root rotation,
reloads the stored root in a fresh PHP process, and verifies that an incomplete
refresh cannot replace the last trusted root. This is still a storage component
and test boundary, not production activation: the updater runtime has not yet
been wired to this store or tested on the HelioHost PHP web SAPI.


### Crash-durability qualification

`TufRootStore::storeVerifiedRoot()` flushes and synchronizes the temporary root file before atomic rename, but does not synchronize the containing directory after publication. As with the Node 4 event store, atomic visibility is not a guarantee that the renamed directory entry survives sudden power loss or filesystem failure. A restart could therefore expose an older trusted-root snapshot even though a refresh had completed before the crash. The monotonic version guard prevents rollback during normal operation, but cannot by itself prevent filesystem rollback after a crash. Before production activation, verify the HelioHost filesystem's rename-durability guarantees or use persistence with documented durable commits. Existing process-reload tests do not simulate power loss.
