# Node A: asynchronous TUF adapter implementation plan

Status: design/implementation checklist only. This document does not claim an upstream TUF adapter exists.

## Pinned upstream inputs

- `tuf-js@6.0.3`, source commit `ce8ba9cd3f074531976ff4eef82af1f3adae3728`.
- `@sigstore/tuf@5.0.1`, source commit `3154029799fe44e6a037fc634e175abe091521b3`.
- The published Sigstore wrapper constructs `Updater` with filesystem paths and has no storage-adapter option.
- `tuf-js` imports `fs` directly. Its updater constructor synchronously loads root metadata; refresh paths synchronously read/write timestamp, snapshot and delegated metadata; target methods use filesystem streams, existence checks and copies.
- Sigstore's wrapper synchronously creates cache directories and seeds root/seed targets before the updater is constructed.

## Required refactor boundary

Replace the path-based API with an explicit asynchronous storage API. Do not shim or monkey-patch Node's global `fs`.

1. **Bootstrap**
   - Add an asynchronous updater factory (for example, `Updater.create(options, storage)`) rather than doing I/O in the constructor.
   - Read the trusted root role through the adapter. If no root exists, seed only the explicitly configured trust-anchor bytes, then persist them using a fenced create-if-absent operation.
   - Validate the seed's expected role/version envelope before use. The trust anchor itself remains an operator-provisioned trust input, not a remotely trusted update.

2. **Metadata reads**
   - Convert `loadLocalMetadata` to async `storage.readRole(roleName)`.
   - Update constructor/bootstrap, `loadTimestamp`, `loadSnapshot`, `loadTargets`, `getTargetInfo`, `refresh`, and delegation traversal to await storage reads.
   - Preserve existing upstream parsing, signature thresholds, expiry, rollback/equivocation, snapshot linkage and delegation validation. Storage must not become a second TUF verifier.

3. **Metadata writes**
   - Replace `persistMetadata` with `commitVerifiedRole(role, expectedIdentity, nextBytes, fence)`.
   - Call only after the upstream `TrustedMetadataStore` has accepted the role.
   - Root rotation remains one version per iteration: verify root N+1, commit root N+1, then request N+2. Never batch root rotations.
   - Timestamp, snapshot and delegated role writes occur only after their corresponding upstream checks.
   - If the upstream trusted set mutates and the durable commit then fails, mark that updater instance poisoned and reject every further operation on it. Recreate a fresh updater from last-known-good durable bytes before retrying. Do not reuse the mutated in-memory trust set.

4. **Targets**
   - Replace `downloadFile`'s temporary-file callback with a stream-to-stage API.
   - Enforce the TUF target length while streaming and compute the required digest(s) incrementally. Do not buffer an unbounded target in Worker memory.
   - Complete the R2 staging object, verify its final length and digest, then publish its immutable object key in a short Durable Object transaction that rechecks the run fence.
   - A stale worker may leave an unreachable staging object, but it must never publish a pointer. Readers resolve committed pointers only.
   - Rework `findCachedTarget` to resolve a committed pointer and verify the retrieved stream before returning a readable target abstraction. Do not return a local filesystem path.

5. **Sigstore wrapper**
   - Replace `TUFClient`'s synchronous directory creation and `seedCache` path-copy logic with an async factory that accepts the storage adapter and an explicit trusted root seed.
   - Return a target stream/reader (or a bounded caller-owned artifact sink), not a path string. Update Sigstore's target consumer to consume that abstraction without writing a local file.
   - Ensure wrapper-level seed targets, if any, use the same verified immutable target-store protocol; do not silently write seed files into ephemeral `/tmp`.

## Acceptance tests required before production status

- No native filesystem operation is reached in adapter mode; fail closed if any path-based fallback is invoked.
- Bootstrap from an explicit trust anchor and restart from Durable Object state.
- Multiple sequential root rotations, including failure immediately after upstream root acceptance but before durable commit; verify updater poisoning and recreation.
- Valid timestamp/snapshot/targets refresh; expiry, rollback, same-version equivocation, bad signatures, insufficient threshold, snapshot mismatch and delegated-role attacks.
- Failed refresh preserves last-known-good durable metadata.
- Target download verifies declared length and digest, survives restart, and never publishes incomplete bytes.
- Inject crashes before and after R2 completion and before/after pointer publication; verify orphan cleanup and pointer atomicity.
- Lease takeover during metadata and target operations; stale owner cannot commit metadata or publish target pointers.
- Reproducible dependency install with a committed lockfile and source/tarball integrity checks for any maintained upstream fork or patch.

## Explicit non-claims

The current `tuf-storage-contract.ts`, SQLite metadata primitive and R2 target design do not implement this refactor. The existing filesystem simulation is not connected to `tuf-js`. Production readiness requires the adapter to be wired into the real upstream verifier and the complete acceptance matrix above to pass.

## Updater poisoning primitive added to the PoC

`src/guarded-tuf-updater.ts` now supplies a fail-closed lifecycle wrapper. The future async adapter must translate a failure to durably commit metadata after upstream acceptance into `TufPersistenceCommitError`. The wrapper then permanently rejects refresh, target-info, cached-target and target-download calls on that updater instance. Ordinary network/validation failures that occur before a persistence-commit failure do not poison the instance. Unit tests cover both paths.

This primitive is not yet connected to `tuf-js`; production integration must ensure the adapter emits the typed error at the exact persistence boundary and that every public updater operation is routed through the guard.

## Additional upstream mutation hazard confirmed

The pinned `tuf-js@6.0.3` `TrustedMetadataStore` has post-assignment checks in two update methods:

- `updateTimestamp` assigns `trustedSet.timestamp` and then calls `checkFinalTimestamp()`.
- `updateSnapshot` assigns `trustedSet.snapshot` and then calls `checkFinalSnapsnot()`.

Those checks can throw (for example, expiry or timestamp/snapshot version linkage), leaving the in-memory trusted set partially advanced even though the update method reports failure. Therefore the fork must either validate against a candidate state before publishing it (preferred) or explicitly roll back the mutation. The updater lifecycle guard now also recognizes `TufStateMutationError` and covers the public refresh, target-info, cached-target and target-download operations; the patched upstream boundary must translate any failure after an unrolled-back trusted-set mutation into that type. A generic validation/network error must not be treated as proof that state is unchanged unless the callsite can establish that ordering.

## Concurrency guard

The lifecycle wrapper serializes every public updater operation through a promise queue. This is necessary because a second refresh/target operation must not race a first operation that may partially mutate the trusted set; operations already queued behind a mutation failure must re-check poison and fail before touching upstream state. The regression suite exercises this queued-call case. The upstream integration must preserve this single-updater serialization or provide an equivalent mutex around the shared mutable `TrustedMetadataStore`.

## Pinned source callsite map for the fork

| Upstream source | Current filesystem dependency | Required adapter replacement |
|---|---|---|
| `tuf-js/packages/client/src/updater.ts` constructor and `loadLocalMetadata` | Synchronous `readFileSync` of root and role metadata | Async factory/bootstrap plus `readRole` |
| Same `updater.ts`, `persistMetadata` | Synchronous `writeFileSync` after role validation | Fenced `commitVerifiedRole` with expected-current identity |
| Same `updater.ts`, `findCachedTarget` | `existsSync` and `createReadStream`; broad catch currently treats any error as cache miss | Resolve committed target pointer; distinguish not-found from storage failure; verify the stream |
| Same `updater.ts`, `downloadTarget` | Fetcher temp file, `createReadStream` verification, then `copyFileSync` | Stream directly to private R2 stage, incrementally enforce length/hash, then fenced pointer commit |
| `tuf-js/packages/client/src/fetcher.ts` | Temp-file creation, `createWriteStream`, and `createReadStream` for byte downloads | Keep metadata byte fetch bounded in memory; use stream-to-stage only for target objects; remove filesystem temp-file callback contract |
| `@sigstore/tuf/packages/tuf/src/client.ts` | Synchronous cache/targets directory creation and root/seed-target copy/write | Async TUF client factory with explicit trust-anchor bytes and storage adapter |
| `@sigstore/tuf/packages/tuf/src/target.ts` | Reads target path back with `fs.readFile` and returns string | Consume a verified target byte stream/reader; avoid path-based readback and unbounded string conversion |

The current `findCachedTarget` implementation catches every error and returns a cache miss. The adapter fork must not preserve that blanket behavior for Durable Object/R2 failures: only an explicit not-found result or a failed cached-target integrity check should trigger a re-download. Permission, connectivity, unavailable-object-store and consistency errors must propagate so the caller fails closed rather than silently treating an infrastructure fault as an absent cache entry.

## Trusted-state atomicity patch: implemented and verified

The narrow `tuf-js@6.0.3` patch is stored at `patches/tuf-js-6.0.3-trusted-state-atomicity.patch`. It moves final timestamp expiry validation and final snapshot expiry/timestamp-linkage validation before the candidate metadata is assigned into `TrustedMetadataStore`. The patch also adds two upstream regression tests that force each final check to fail and assert the corresponding trusted-set getter remains unset. The workflow pins the upstream commit plus the exact Git blob hashes for both patched source files, applies with `git apply --unidiff-zero`, builds the upstream workspaces, and runs the upstream CLIENT Jest project.

Verified on PR #143 head `93e873f8bbdba3c4bb8e61c6c49893892c11bf87`: upstream TUF CLIENT **8 suites / 42 tests passed**, and the workerd suite **20/20 passed** in [CI run 45080395120](https://github.com/Double-IQ/SentryIQ/actions/runs/45080395120). This is a targeted source-level fix, not the async storage adapter. It does not yet make `tuf-js` usable with Durable Objects/R2 or establish production readiness.

## Target digest preservation

The target-store contract carries the complete hash map from the TUF `TargetFile`, not a hard-coded SHA-256 field. The adapter must incrementally compute and verify every algorithm declared by upstream target metadata and enforce the declared length before the immutable R2 pointer can be published. The workerd suite includes a compile-time/runtime contract assertion retaining both SHA-256 and SHA-512 fields. Metadata-record identity remains SHA-256 over the exact metadata bytes; this distinction does not narrow target verification.

The same maintained patch also narrows cached-target recovery: only `LengthOrHashMismatchError` and `ENOENT` become cache misses; all other filesystem/storage errors propagate. The upstream CLIENT suite includes an EACCES regression for this behavior.

Each private target stage carries the full immutable `TufTargetDescriptor` (path, length and every declared hash). `commitTarget` must compare the completed R2 object against that descriptor before publishing the pointer; it must not reconstruct or narrow the expected digest set from a SHA-256-only shortcut.

The complete target-stage contract now retains its immutable descriptor through commit, including the full TUF hash map; the workerd compile-time assertion and the upstream TUF patch suite both pass on the latest exact head.

## Durable Object metadata adapter slice implemented

`src/durable-tuf-metadata-store.ts` now implements `TufMetadataStore` over the existing Node A Durable Object RPC surface. It delegates metadata reads and compare-and-set commits to the authoritative DO methods, validates the supplied run ID/fence/token against the active run lock, and does not duplicate rollback or root-rotation policy outside the DO transaction. A workerd test verifies read-after-commit and rejects a mismatched fence. On latest exact-head CI, workerd passed **21/21** and upstream TUF CLIENT passed **8 suites / 43 tests** ([run 45080395120](https://github.com/Double-IQ/SentryIQ/actions/runs/45080395120)).

This is a concrete metadata-store implementation slice only. It is not yet passed into `tuf-js`; the async updater factory/refactor, R2 target-store implementation, and full refresh/rotation/restart acceptance matrix remain open.

## Newly identified fail-closed integration requirement

The pinned upstream `updater.ts` has broad recovery catches in `loadTimestamp`, `loadSnapshot`, and `loadTargets`. Those catches intentionally permit a corrupt or expired *cached metadata record* to be replaced from the remote repository. They must not also swallow a Durable Object/R2 read failure, because silently converting an unavailable or unauthorized durable store into a remote cache miss weakens the persistence boundary and can conceal a storage outage.

The async adapter must therefore distinguish:
- a missing role (`readRole` returns `null`);
- cached metadata bytes that fail upstream TUF parsing/verification (the updater may follow the TUF-defined remote-refresh path);
- a durable-store operation failure (typed storage error, propagated immediately).

Do not identify storage failures by message text or by treating every thrown error as recoverable. The adapter must wrap RPC failures in a stable typed error, and the patched updater's catch blocks must explicitly rethrow it. This is a prerequisite to wiring `DurableObjectTufMetadataStore` into the updater.

The same rule applies to persistence: after the upstream trusted set accepts a candidate, a failed fenced commit must emit the dedicated persistence-commit error and poison that updater instance. The next attempt must instantiate a new updater from the last durable metadata snapshot; it must never retry against the already-advanced in-memory trusted set.

## Typed durable-store failure contract implemented

`TufMetadataReadError` now exposes stable code `TUF_METADATA_READ_FAILED`. `DurableObjectTufMetadataStore.readRole` wraps Durable Object RPC failures in this type, allowing the upstream updater patch to rethrow storage outages rather than swallowing them in cached-metadata recovery catches. `TufPersistenceCommitError` now exposes `TUF_METADATA_COMMIT_FAILED`; failed fenced compare-and-set commits are wrapped in this error so `GuardedTufUpdater` poisons the mutable updater and requires reconstruction from durable state.

The workerd regression verifies the metadata adapter's read/write round trip, rejects a mismatched supplied fence, rejects an old owner after release and a higher fencing epoch takeover, checks the stable read-error code, and checks the stable commit-error code. Latest exact-head CI passed **21/21 workerd tests** and **8 upstream CLIENT suites / 43 tests** ([CI run 45105712826](https://github.com/Double-IQ/SentryIQ/actions/runs/45105712826)).

## Upstream fail-closed storage-error propagation patch

The pinned `tuf-js@6.0.3` patch now includes `isTufStorageError`, which recognizes the stable read and commit error codes emitted by the Node A adapter. Updater recovery catches in force-cache bootstrap, timestamp cache loading, snapshot cache loading, delegated-target cache loading, remote snapshot/targets error wrapping, and metadata persistence now rethrow these errors rather than converting them into ordinary cache misses or generic runtime/persistence wrappers. This preserves the distinction between a missing/corrupt cached record and a failed durable storage operation.

The new upstream `storage-error.test.ts` regression verifies both codes are classified as non-recoverable and ordinary parse errors remain recoverable. Exact-head CI passed **9 upstream CLIENT suites / 44 tests** and **21/21 workerd tests** ([CI run 45106120596](https://github.com/Double-IQ/SentryIQ/actions/runs/45106120596)). This is still the fail-closed error-propagation slice; the full asynchronous updater factory, metadata read/commit integration, R2 target streaming and end-to-end TUF refresh matrix remain outstanding.


## Stream-native fetcher and Sigstore consumer contract (source-audited)

The pinned fetcher and wrapper were inspected at their exact commits. The adapter boundary must change the public target result, not merely replace the backing filesystem:

- `BaseFetcher.downloadFile(url, maxLength, handler)` currently writes every target to `tempFile()` and passes a filename to the handler. Replace this path-based callback with a stream consumer or a target-stage sink. The fetcher must count bytes before forwarding each chunk, cancel the reader immediately on overflow, propagate fetch/stream failures, and require exact final length before the stage can be committed.
- Metadata `downloadBytes` remains bounded by the metadata role limit and can collect chunks into a `Uint8Array`/`Buffer`; it must not route through a temporary file. Enforce the byte limit while collecting, not after concatenation.
- Target integrity verification must cover every algorithm in `TargetFile.hashes`. Since the upstream model owns the trusted descriptor, the adapter must feed the same bytes to upstream verification and the R2 stage (or perform equivalent incremental digest checks using the complete descriptor). Do not publish a target pointer until both upstream verification and the storage completion checks succeed.
- `Updater.downloadTarget` must return a target handle/descriptor, not a string path. `findCachedTarget` must return the same abstraction or `undefined`; it must treat only explicit not-found and integrity mismatch as cache misses. The adapter's stream/open errors remain fatal.
- The current `@sigstore/tuf` `readTarget()` calls `fs.readFile(path, 'utf-8')` after `getTargetPath()`. Replace both with a target-reader API. The Sigstore package currently consumes trust metadata and target payload as text; decode UTF-8 only at this final consumer boundary, with a documented maximum target size for string consumers. For larger targets, expose a stream API rather than silently buffering.
- The current `TUFClient` constructor performs cache directory creation and seed copying synchronously. Replace it with `static async create(options, storage)` (or equivalent), with an explicit trust-anchor byte input and no implicit `seeds.json` filesystem writes. Any bundled seed target must enter through the same immutable target-store verification/publish protocol or be removed from the Worker adapter mode.
- The adapter-mode build must fail if `node:fs`, `node:path`, `tempFile`, `createReadStream`, `createWriteStream`, `readFileSync`, `writeFileSync`, `copyFileSync`, `existsSync`, `mkdirSync`, or path-returning target APIs remain reachable from runtime entry points. Test this with a runtime trap as well as a source-level forbidden-import scan; a scan alone is insufficient because transitive dependencies may reintroduce filesystem access.

### Proposed narrow API shape

```ts
export interface TufTargetHandle {
  readonly path: string;
  readonly length: number;
  readonly hashes: Readonly<Record<string, string>>;
  open(): Promise<ReadableStream<Uint8Array>>;
}

export interface AsyncTufFetcher {
  fetch(url: string): Promise<ReadableStream<Uint8Array>>;
  fetchMetadata(url: string, maxBytes: number): Promise<Uint8Array>;
  stageTarget(
    url: string,
    descriptor: TufTargetDescriptor,
    store: TufTargetStore,
    fence: TufRunFence
  ): Promise<CommittedTufTarget>;
}
```

The interfaces above are a design proposal, not code already wired into `tuf-js`. The first implementation slice should land in a maintained fork/patch with compile-time types and upstream tests, then the Sigstore wrapper should be migrated against that new API. The existing filesystem-based `Updater` API must remain available to non-Worker consumers unless upstream chooses a major-version breaking change; the Worker adapter should use a separate explicit async factory/entry point rather than silently changing the package-wide contract.


## Persistence ordering audit: awaits and mutation boundaries

A line-by-line review of pinned `updater.ts` identified a critical conversion hazard: all current `persistMetadata(...)` callsites are synchronous and none is awaited. Once persistence becomes asynchronous, simply changing its return type to `Promise<void>` would let `loadRoot`, `loadTimestamp`, `loadSnapshot`, and delegated `loadTargets` report success before the durable write completes. Every callsite must become `await persistVerifiedMetadata(...)`, and the enclosing method must not expose the newly accepted role as durable until that await resolves.

| Workflow | Upstream acceptance point | Required durable boundary |
|---|---|---|
| Root rotation | `trustedSet.updateRoot(bytesData)` | Immediately await commit of exactly that root version before the loop requests the next version |
| Timestamp remote update | `trustedSet.updateTimestamp(bytesData)` | Await timestamp commit before `loadTimestamp` returns |
| Snapshot remote update | `trustedSet.updateSnapshot(bytesData)` | Await snapshot commit before `loadSnapshot` returns; storage errors must escape the current `RuntimeError` wrapper unchanged |
| Delegated targets role | `trustedSet.updateDelegatedTargets(bytesData, role, parentRole)` | Await role commit before returning the trusted role; storage errors must escape the current `RuntimeError` wrapper unchanged |

Two separate atomicity concerns must not be conflated:

1. Candidate validation inside `TrustedMetadataStore` must complete before the candidate is assigned into the in-memory trusted set. The existing atomicity patch addresses the final timestamp and snapshot checks.
2. A valid candidate is then accepted in memory, after which the fenced durable commit can still fail. That failure must poison the updater instance; it is not safe to retry on the same trusted set. The next updater must bootstrap from the last committed durable bytes.

The `forceCache` path has an additional ordering requirement: the local timestamp read and validation must be awaited, but a typed durable read failure must not enter the broad catch that falls back to a remote refresh. A genuinely absent/corrupt/expired cached role may follow the existing TUF recovery path; an unavailable Durable Object is an infrastructure failure and must propagate. The same distinction is required in snapshot and delegated-role cache recovery.

This ordering review is source-derived and does not change runtime code. It is now an explicit acceptance checklist for the async fork so a mechanical Promise conversion cannot accidentally introduce fire-and-forget persistence or swallow durable commit failures.
