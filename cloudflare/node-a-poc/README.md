# Node A Cloudflare Workers proof of concept

**Status: Worker-native implementation and authenticated manual monitor routes are in draft PR #145; not production-deployed or operationally accepted.**

This directory is deliberately separate from the PHP production application. Node A's owner-confirmed platform is Cloudflare Workers. The implementation uses a Worker-native TypeScript TUF runtime, Durable Object fencing/metadata persistence, private R2 target staging, and a release-integrity monitor composition.

## Run

From this directory:

```sh
npm install
npm test
```

Direct dependencies are exact-version pinned in `package.json`. The CI workflow generates an exact `package-lock.json` for each run, installs from it, and uploads it for review. That lockfile is **not yet committed to this branch**, so committing a reviewed lockfile remains a reproducibility/deployment gate.

## Implemented on the draft branch

- **Async TUF and target storage:** pinned `tuf-js@6.0.3` trusted metadata is persisted through fenced Durable Object operations; sequential root rotation, timestamp rollback/equivocation checks, online timestamp/snapshot refresh, consistent-snapshot naming, bounded metadata transport, delegated-role verification, private R2 staging, atomic pointer publication, and fenced cleanup are covered by Workerd tests.
- **Release evidence:** strict duplicate-key-safe manifest parsing, exact repository/release/tag/commit identity, complete public/runtime inventory, exact `VERSION` byte binding, bounded GitHub release asset retrieval with a redirect allowlist, streaming ZIP SHA-256, Snappy bundle decoding, and authenticated GitHub/SLSA attestation policy.
- **Canonical origin:** byte length and SHA-256 checks for signed public assets, fixed canonical HTTPS origin, redirect rejection, and required security-header checks.
- **Private host:** A-only collector request, pinned Ed25519 response verification, nonce/freshness/release binding, and exact pinned deployed-file/private-config inventory checks.
- **Node 4 exchange:** challenge request, A-only Ed25519 report signing, bounded report submission, and acknowledgement validation.
- **Independent owner alert:** generic HTTPS webhook transport pinned to an exact external hostname, with redirects rejected and a strict non-sensitive event context.
- **Monitor composition:** TUF refresh and trusted-root loading, deployed VERSION and release assets, GitHub release evidence, canonical-origin checks, private-host attestation, Node 4 report, direct owner alerts, and release-pin advancement under a Durable Object run lease.
- **Worker routes:** `POST /internal/monitor/run` performs a manual monitor run after baseline initialization. `POST /internal/baseline/initialize` performs the same verification and can initialize the immutable baseline only with both the normal API bearer token and a separate one-time baseline approval token. Both routes fail closed when configuration is absent.

The Worker suite passes **128/128 tests across 21 files** on exact head `f94faef1ac6aecc88b4f0d3521d9af97d08b1303`; the pinned upstream TUF trusted-state atomicity job and Worker bundle scan also pass ([CI run 45182533408](https://github.com/Double-IQ/SentryIQ/actions/runs/45182533408)). The CI test job also retrieves the genuine published v0.1.2 release asset and GitHub attestation bundle and injects the current Sigstore trusted root into the workerd integration tests.

## Operational boundary and non-claims

- The published v0.1.2 release predates the required embedded canonical manifest and has no `release-manifest.json`; the new monitor intentionally cannot accept it. A new manifest-bearing release is required before a live monitor run can pass.
- The stock `@sigstore/tuf@5.0.1` filesystem-backed wrapper remains in isolated compatibility tests only. It is removed from the Worker production dependency path. The Worker uses the async `tuf-js` adapter and the pinned upstream atomicity patch.
- The new monitor routes are **manual only**. No Cron trigger, production schedule, or background monitoring is configured.
- The baseline has not been initialized. No one-time baseline approval token has been provisioned.
- No Cloudflare production account/bucket, TUF bootstrap secret/mirror, GitHub API token, Node 4 token, report signing key, private-host token/collector key, expected inventory maps, independent alert endpoint, or production Worker deployment has been provisioned or verified.
- The generic direct-alert transport is implemented, but its external endpoint and credential must be selected and provisioned by the owner. It must be independently controlled and not hosted on the SentryIQ application origin.
- The Durable Object release pin is advanced only after the signed Node 4 report is acknowledged. A rejected or unacknowledged event does not advance the pin.
- `GET /runtime-check` deliberately reports `productionReady: false` until account-backed acceptance is completed.
- PRs #143 and #145 remain draft/unmerged. No production changes have been made.

## Acceptance sequence still required

1. Commit and review the CI-generated dependency lockfile; retain the pinned upstream TUF patch or replace it only with a separately reviewed upstream release.
2. Provision the intended Cloudflare account, R2 bucket, Durable Object, TUF bootstrap/mirror configuration, GitHub/Node 4/private-host credentials, pinned inventories, and independent owner-alert webhook.
3. Independently review the current manifest-bearing release and initialize the immutable baseline through the one-time approval route. Do not use v0.1.2 for this path.
4. Exercise the manual monitor against the live non-production Worker and verify the actual Node 4, private-host collector, and owner-alert provider acknowledgements.
5. Select and approve the monitoring cadence, then configure and test the Cron trigger. No schedule is assumed by this PoC.
6. Complete account-backed R2 fault injection, lease takeover, stale-owner rejection, target digest comparison, restart/eviction, rollback rehearsal, and deployment evidence.
7. Only then consider production readiness and merge/deploy approval.

The Workerd suite and Wrangler bundle scan are not substitutes for a Cloudflare account-backed staging deployment.

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
