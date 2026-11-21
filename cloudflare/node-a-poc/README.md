# Node A Cloudflare Workers proof of concept

**Status: isolated runtime/storage PoC only. Not deployable as the production Node A.**

This directory is deliberately separate from the PHP production application. It tests a narrow but important question in the actual Workers runtime:

1. Can the pinned Sigstore JavaScript verifier and TUF client modules load under `workerd`?
2. Do Ed25519 key generation/sign/verify and SHA-256 work in that runtime?
3. Does a SQLite-backed Durable Object preserve a monotonic release pin and run lock across separate stubs/requests, and reject downgrade or same-version replacement?

## Run

From this directory:

```sh
npm install
npm test
```

Direct dependencies are exact-version pinned in `package.json`. A reviewed npm lockfile is still required before any deployment or use in a production build.

## Important non-claims

- The runtime check imports `@sigstore/verify@4.1.3` and `@sigstore/tuf@5.0.1`, but does **not** verify a real Sigstore bundle.
- It intentionally does not call `initTUF()`: the upstream TUF client uses filesystem-backed metadata and target caches. Workers' virtual filesystem is ephemeral and request-scoped; this PoC does not make it durable.
- The SQLite Durable Object currently stores the monotonic release pin, a run lease and a bounded run audit. It does not yet store or validate TUF metadata.
- The release-pin method is a storage primitive. It must only be called after the full release attestation, manifest/ZIP, origin, private-host and Node 4 acceptance gates have passed. No production caller is wired.
- The Worker exposes only health/runtime diagnostics. It does not fetch releases, call Node 4, access private-host attestation, send alerts, or expose state mutation routes.
- No secrets, Cloudflare account identifiers, production bindings, routes, Cron Triggers or deployments are configured.

## Acceptance sequence after this PoC

1. Pass this workerd suite.
2. Add genuine SentryIQ manifest and ZIP attestation fixtures; verify both using `@sigstore/verify` with an authenticated TUF trusted root.
3. Implement and independently review a Durable Object-backed TUF adapter that preserves root rotation, metadata expiry/version checks, target hashes and atomic refresh. Do not bridge the current filesystem cache with ephemeral `/tmp`.
4. Test TUF restart/eviction, failed refresh preserving last-known-good metadata, rollback, expiry, threshold/signature failures and malicious metadata.
5. Port the existing `SigstoreProvenance` and `ReleaseTrustPolicy` constraints without weakening them.
6. Add the Node 4 challenge/report exchange, private-host collector and independent owner-alert path.
7. Complete production deployment only after account access, secrets, schedules, independent failure-domain and owner acceptance gates are met.

The Worker runtime tests are local Miniflare/workerd tests. They are not a substitute for a Cloudflare account-backed staging deployment.
