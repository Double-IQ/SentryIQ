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
[43580059384](https://github.com/Double-IQ/SentryIQ/actions/runs/43580059384)
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