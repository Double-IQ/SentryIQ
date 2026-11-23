# Node A Cloudflare Workers proof of concept

**Status: isolated Workerd implementation and policy-integration PoC; not deployable or accepted as production Node A.**

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

- The runtime suite verifies the genuine SentryIQ v0.1.2 GitHub attestation bundle and the upstream Sigstore Rekor v2 certificate bundle using `@sigstore/verify@4.1.3` and the current Sigstore trusted root. It rejects a one-byte-tampered DSSE signature after trusted-key validation and includes an Ed25519 regression check. The branch now also contains a repository-specific SLSA/GitHub release policy, strict release-manifest parser, bounded Snappy GitHub-bundle retrieval, dual-subject manifest/ZIP evidence gate, and canonical-origin static-asset/header verifier. These modules are tested, but are not yet wired into the scheduled Worker control plane.
- The suite calls the stock `@sigstore/tuf@5.0.1` client with a fixture root. It confirms cache bootstrap works under `/tmp`, but a cache path outside `/tmp` fails with the Workers filesystem permission restriction. The test intentionally stops at a loopback network failure; it does not complete a live Sigstore TUF refresh.
- The Worker-native async TUF path now uses pinned `tuf-js@6.0.3` trusted metadata with fenced Durable Object metadata persistence and private R2 target staging. The stock filesystem-backed `@sigstore/tuf` wrapper is removed from the Worker path. This is isolated Workerd/R2-test-double evidence; account-backed Cloudflare deployment, real R2 fault injection, and operational acceptance remain outstanding.
- The latest confirmed workerd CI run passes 17/17 tests, including genuine SentryIQ v0.1.2 attestation verification, tampered-DSSE rejection, Ed25519 regression, fenced metadata CAS and updater-poisoning lifecycle tests. The CI-generated `package-lock.json` is uploaded as an artifact for review but is not yet committed to this branch; a committed lockfile remains a release gate. The generated CI dependency resolution is `@sigstore/tuf@5.0.1`, `tuf-js@6.0.3`, and `@tufjs/models@5.0.3`. The Sigstore wrapper exposes no storage adapter; the TUF `Fetcher` interface changes transport only, and the updater still uses filesystem metadata/target directories. `TrustedMetadataStore` is internal to `tuf-js`, not exported from its public API. A custom fetcher alone therefore cannot solve persistence.
- The SQLite Durable Object stores the monotonic release pin, run lease, bounded run audit, fenced TUF metadata, immutable target pointers, staging records and delayed target-GC queue. It does not provision or validate a live Cloudflare account or production binding.
- The release-pin method is a storage primitive. It must only be called after the full release attestation, manifest/ZIP, origin, private-host and Node 4 acceptance gates have passed. No production caller is wired.
- The Worker exposes health/runtime diagnostics and authenticated TUF refresh/target routes. The release-evidence and origin-policy modules are not yet called by a scheduled release-monitor workflow; Node 4 exchange, private-host attestation, direct owner alerts and Cron scheduling remain outstanding.
- No secrets, Cloudflare account identifiers, production bindings, routes, Cron Triggers or deployments are configured.

## Acceptance sequence after this PoC

1. Preserve the 17-test workerd suite and replace the temporary dependency patch with an upstream release or a separately reviewed/pinned maintained patch plus committed lockfile.
2. Wire the tested dual-subject manifest/ZIP evidence gate and canonical-origin verifier into the Worker scheduled control plane, then add golden and adversarial end-to-end tests against a genuine current release.
3. Continue independent review and account-backed fault-injection acceptance of the implemented Durable Object-backed async TUF adapter, preserving sequential root rotation, metadata expiry/version checks, target hashes and crash-safe atomic refresh. Do not treat ephemeral `/tmp` as persistent.
4. Test TUF restart/eviction, failed refresh preserving last-known-good metadata, rollback, expiry, threshold/signature failures and malicious metadata.
5. Port the existing `SigstoreProvenance` and `ReleaseTrustPolicy` constraints without weakening them.
6. Add the Node 4 challenge/report exchange, private-host collector and independent owner-alert path.
7. Complete production deployment only after account access, secrets, schedules, independent failure-domain and owner acceptance gates are met.

The Worker runtime tests are local Miniflare/workerd tests. They are not a substitute for a Cloudflare account-backed staging deployment.

### Adapter integration constraint confirmed from pinned upstream source

The pinned `tuf-js@6.0.3` updater performs synchronous filesystem reads and writes in its constructor, metadata refresh path and target-cache path. The pinned `@sigstore/tuf@5.0.1` wrapper also synchronously creates directories and seeds the initial root/targets before constructing the updater. Therefore the asynchronous `TufStorageAdapter` contract is **not a drop-in implementation**: the maintained fork must refactor those call sites to asynchronous adapter operations (including async initialization), preserve upstream verification ordering, and make updater instances unusable after a persistence failure that may follow an in-memory trust-state mutation. Merely swapping `fs`, passing a custom fetcher, or wrapping the existing synchronous methods would be unsafe and is explicitly not the integration plan.

The pinned upstream `tuf-js@6.0.3` source also contains post-mutation validation hazards: timestamp and snapshot trusted-set entries are assigned before final expiry/linkage checks. The maintained fork must validate candidates before publishing them or roll back atomically; otherwise its adapter must poison the updater after any post-mutation failure. This is covered in the implementation plan and a new regression test.

The expanded suite now adds a dedicated regression for an upstream timestamp/snapshot-style partial trusted-state mutation and explicitly asserts that a poisoned updater blocks refresh, target lookup, target-info, cached-target lookup, and target download. The expanded exact-head CI run is pending.

The updater guard also serializes calls against the shared mutable TUF trusted set. Work queued behind a call that poisons the updater is rejected before it reaches the upstream client; this prevents concurrent target/refresh work from racing partially mutated trust state. The expanded suite passes 19/19 tests on PR #143 head `21299d1b024d12e932af2e7dfaf3a666afdb9a17`; CI run [45078053162](https://github.com/Double-IQ/SentryIQ/actions/runs/45078053162).

The pinned upstream trusted-state atomicity patch is now applied and tested against `tuf-js@6.0.3` commit `ce8ba9cd3f074531976ff4eef82af1f3adae3728`. CI verifies the upstream source commit and source-file hashes, applies the patch, builds the upstream workspaces, and passes 8 CLIENT suites / 43 tests. The same workflow passes all 20 workerd tests. Combined exact-head evidence: [CI run 45080395120](https://github.com/Double-IQ/SentryIQ/actions/runs/45080395120). This closes the identified timestamp/snapshot partial-mutation defect in the pinned source slice only; the asynchronous Durable Object/R2 adapter and its full TUF acceptance matrix remain outstanding.

The same upstream patch now also makes cached-target lookup fail closed: only a verified target hash/length mismatch or an actual `ENOENT` is treated as a cache miss; permission and infrastructure errors propagate. An upstream EACCES regression covers this behavior. The latest run passed 8 CLIENT suites / 43 tests and 20/20 workerd tests.

The latest exact-head run also compiles the full target-stage contract, including the immutable descriptor carried from stage allocation through commit, and passes 20/20 workerd tests plus 8 upstream CLIENT suites / 43 tests.

A concrete `DurableObjectTufMetadataStore` now implements the metadata side of the storage contract. It adapts the existing Durable Object read/CAS methods, checks the caller's run/fence/token identity against the active lock, and leaves rollback/root-version enforcement inside the DO transaction. Its workerd regression verifies commit/read round-trip and rejects a mismatched fence. Latest exact-head CI: 21/21 workerd tests and 8 upstream CLIENT suites / 43 tests passed.

The Durable Object metadata adapter now classifies persistence failures explicitly: `TufMetadataReadError` carries stable code `TUF_METADATA_READ_FAILED` so the upstream async updater can distinguish a durable-store outage from an absent/corrupt cached role; failed fenced commits become `TufPersistenceCommitError` (`TUF_METADATA_COMMIT_FAILED`) so the guarded updater is poisoned and must be recreated. Regression coverage includes lease release/takeover, stale-owner commit rejection, typed read outage, and typed commit failure. Latest exact-head CI: 21/21 workerd tests and 8 upstream CLIENT suites / 43 tests passed ([CI run 45105712826](https://github.com/Double-IQ/SentryIQ/actions/runs/45105712826)).

The pinned upstream `tuf-js` patch now exports a stable storage-error classifier and rethrows `TUF_METADATA_READ_FAILED` / `TUF_METADATA_COMMIT_FAILED` through the updater's cache-recovery and persistence catch paths. This prevents a durable-store outage from being silently converted into a remote cache miss. A dedicated upstream regression covers both error codes. Latest exact-head CI: 9 upstream CLIENT suites / 44 tests and 21/21 workerd tests passed ([CI run 45106120596](https://github.com/Double-IQ/SentryIQ/actions/runs/45106120596)).
