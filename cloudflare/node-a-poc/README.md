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

Direct dependencies are exact-version pinned in `package.json`. `npm test` first runs the version-guarded `apply-sigstore-core-compat` script. The published `@sigstore/core@4.0.1` artifact forwards an undefined digest to `crypto.verify`, which workerd rejects for EC/RSA signatures; the local patch supplies SHA-256 only for EC/RSA keys and leaves EdDSA and RSA-PSS defaults unchanged. The patch refuses unknown package versions or compiled code shapes. The GitHub Actions workflow applies it explicitly after `npm ci --ignore-scripts`. A committed, reviewed npm lockfile is still required before any deployment or production build.

## Important non-claims

- The runtime suite verifies the genuine SentryIQ v0.1.2 GitHub attestation bundle and the upstream Sigstore Rekor v2 certificate bundle using `@sigstore/verify@4.1.3` and the current Sigstore trusted root. It rejects a one-byte-tampered DSSE signature after trusted-key validation and includes an Ed25519 regression check. This is a positive/negative cryptographic PoC, not yet the complete repository-specific release policy or production caller.
- The suite calls the stock `@sigstore/tuf@5.0.1` client with a fixture root. It confirms cache bootstrap works under `/tmp`, but a cache path outside `/tmp` fails with the Workers filesystem permission restriction. The test intentionally stops at a loopback network failure; it does not complete a live Sigstore TUF refresh.
- The separate Durable Object filesystem prototype stages file writes, discards uncommitted changes, and commits successful changes to SQLite in a storage transaction. It is **not wired into** the upstream TUF client; the upstream package still uses the native filesystem APIs. `src/tuf-storage-contract.ts` now defines the explicit metadata/target persistence boundary intended for the future adapter, but it is contract-only and has no production implementation yet. Target bytes are intended for R2; Durable Objects own metadata and committed-pointer publication under the run fence.
- The latest workerd CI run passes 17/17 tests, including genuine SentryIQ v0.1.2 attestation verification, tampered-DSSE rejection, Ed25519 regression, fenced metadata CAS and updater-poisoning lifecycle tests. The CI-generated `package-lock.json` is uploaded as an artifact for review but is not yet committed to this branch; a committed lockfile remains a release gate. The generated CI dependency resolution is `@sigstore/tuf@5.0.1`, `tuf-js@6.0.3`, and `@tufjs/models@5.0.3`. The Sigstore wrapper exposes no storage adapter; the TUF `Fetcher` interface changes transport only, and the updater still uses filesystem metadata/target directories. `TrustedMetadataStore` is internal to `tuf-js`, not exported from its public API. A custom fetcher alone therefore cannot solve persistence.
- The SQLite Durable Object stores the monotonic release pin, a run lease, bounded run audit and the isolated TUF-file prototype. It does not yet store or validate real TUF metadata through the stock client.
- The release-pin method is a storage primitive. It must only be called after the full release attestation, manifest/ZIP, origin, private-host and Node 4 acceptance gates have passed. No production caller is wired.
- The Worker exposes only health/runtime diagnostics. It does not fetch releases, call Node 4, access private-host attestation, send alerts, or expose state mutation routes.
- No secrets, Cloudflare account identifiers, production bindings, routes, Cron Triggers or deployments are configured.

## Acceptance sequence after this PoC

1. Preserve the 17-test workerd suite and replace the temporary dependency patch with an upstream release or a separately reviewed/pinned maintained patch plus committed lockfile.
2. Verify the genuine SentryIQ manifest and ZIP attestations independently against the authenticated TUF trusted root, with digest, subject, identity, workflow and source-commit negative cases.
3. Implement and independently review a Durable Object-backed TUF adapter that the verifier can actually use, preserving sequential root rotation, metadata expiry/version checks, target hashes and crash-safe atomic refresh. Do not treat ephemeral `/tmp` as persistent.
4. Test TUF restart/eviction, failed refresh preserving last-known-good metadata, rollback, expiry, threshold/signature failures and malicious metadata.
5. Port the existing `SigstoreProvenance` and `ReleaseTrustPolicy` constraints without weakening them.
6. Add the Node 4 challenge/report exchange, private-host collector and independent owner-alert path.
7. Complete production deployment only after account access, secrets, schedules, independent failure-domain and owner acceptance gates are met.

The Worker runtime tests are local Miniflare/workerd tests. They are not a substitute for a Cloudflare account-backed staging deployment.

### Adapter integration constraint confirmed from pinned upstream source

The pinned `tuf-js@6.0.3` updater performs synchronous filesystem reads and writes in its constructor, metadata refresh path and target-cache path. The pinned `@sigstore/tuf@5.0.1` wrapper also synchronously creates directories and seeds the initial root/targets before constructing the updater. Therefore the asynchronous `TufStorageAdapter` contract is **not a drop-in implementation**: the maintained fork must refactor those call sites to asynchronous adapter operations (including async initialization), preserve upstream verification ordering, and make updater instances unusable after a persistence failure that may follow an in-memory trust-state mutation. Merely swapping `fs`, passing a custom fetcher, or wrapping the existing synchronous methods would be unsafe and is explicitly not the integration plan.
