# Node A Cloudflare Workers proof of concept

**Status: isolated runtime/storage PoC only. Not deployable as the production Node A.**

This directory is deliberately separate from the PHP production application. It tests a narrow but important question in the actual Workers runtime:

1. Can the pinned Sigstore JavaScript verifier and TUF client modules load under `workerd`, and can the verifier validate a real upstream Rekor v2 fixture?
2. Do Ed25519 key generation/sign/verify and SHA-256 work in that runtime?
3. Can the stock Sigstore TUF client bootstrap its cache on Workers' writable `/tmp`, and does it reject a non-`/tmp` persistent path?
4. Does a separate SQLite-backed Durable Object prototype preserve staged files, a monotonic release pin and run lock across separate stubs/requests, and reject downgrade or same-version replacement?

## Run

From this directory:

```sh
npm install
npm test
```

Direct dependencies are exact-version pinned in `package.json`. A reviewed npm lockfile is still required before any deployment or use in a production build.

## Important non-claims

- The runtime suite verifies an upstream Sigstore Rekor v2 certificate bundle using `@sigstore/verify@4.1.3` and its upstream trusted-root fixture. It is not yet a genuine SentryIQ release bundle and does not exercise the repository-specific release policy.
- The suite calls the stock `@sigstore/tuf@5.0.1` client with a fixture root. It confirms cache bootstrap works under `/tmp`, but a cache path outside `/tmp` fails with the Workers filesystem permission restriction. The test intentionally stops at a loopback network failure; it does not complete a live Sigstore TUF refresh.
- The separate Durable Object filesystem prototype stages file writes, discards uncommitted changes, and commits successful changes to SQLite in a storage transaction. It is **not wired into** the upstream TUF client; the upstream package still uses the native filesystem APIs.
- The generated CI dependency resolution is `@sigstore/tuf@5.0.1`, `tuf-js@6.0.3`, and `@tufjs/models@5.0.3`. The Sigstore wrapper exposes no storage adapter; the TUF `Fetcher` interface changes transport only, and the updater still uses filesystem metadata/target directories. `TrustedMetadataStore` is internal to `tuf-js`, not exported from its public API. A custom fetcher alone therefore cannot solve persistence.
- The SQLite Durable Object stores the monotonic release pin, a run lease, bounded run audit and the isolated TUF-file prototype. It does not yet store or validate real TUF metadata through the stock client.
- The release-pin method is a storage primitive. It must only be called after the full release attestation, manifest/ZIP, origin, private-host and Node 4 acceptance gates have passed. No production caller is wired.
- The Worker exposes only health/runtime diagnostics. It does not fetch releases, call Node 4, access private-host attestation, send alerts, or expose state mutation routes.
- No secrets, Cloudflare account identifiers, production bindings, routes, Cron Triggers or deployments are configured.

## Acceptance sequence after this PoC

1. Pass this workerd suite.
2. Add genuine SentryIQ manifest and ZIP attestation fixtures; verify both using `@sigstore/verify` with an authenticated TUF trusted root.
3. Implement and independently review a Durable Object-backed TUF adapter that the verifier can actually use, preserving sequential root rotation, metadata expiry/version checks, target hashes and crash-safe atomic refresh. Do not treat ephemeral `/tmp` as persistent.
4. Test TUF restart/eviction, failed refresh preserving last-known-good metadata, rollback, expiry, threshold/signature failures and malicious metadata.
5. Port the existing `SigstoreProvenance` and `ReleaseTrustPolicy` constraints without weakening them.
6. Add the Node 4 challenge/report exchange, private-host collector and independent owner-alert path.
7. Complete production deployment only after account access, secrets, schedules, independent failure-domain and owner acceptance gates are met.

The Worker runtime tests are local Miniflare/workerd tests. They are not a substitute for a Cloudflare account-backed staging deployment.
