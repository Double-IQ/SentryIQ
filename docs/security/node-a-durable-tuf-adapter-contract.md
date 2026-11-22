# Node A Durable Object-backed TUF adapter contract

**Status: design contract for implementation and review. This document does not claim that the current filesystem shim is integrated with TUF.**

## 1. Current verified boundary

The Node A PoC currently has two separate pieces:

- @sigstore/tuf 5.0.1 delegates update work to tuf-js 6.0.3. The updater receives metadata and target directory paths and performs filesystem operations itself.
- cloudflare/node-a-poc/src/tuf-fs.ts is a test-only filesystem-shaped adapter over a Durable Object SQLite table. It is not injected into the upstream updater's imported filesystem module or any supported storage interface.

Consequently, a passing test of tuf-fs.ts does not demonstrate that a TUF refresh, root rotation, target download, or restart recovery uses Durable Object persistence. Do not route production verification through this shim or patch global node:fs.

The production direction is a narrowly scoped, pinned tuf-js storage seam (or an upstream-supported equivalent), consumed by the existing @sigstore/tuf integration. Keep upstream TUF cryptographic verification, role/delegation traversal, expiry checks, rollback protection, and target hash verification authoritative.

## 2. Adapter boundary

Introduce an explicit storage contract at the updater boundary. The exact TypeScript names can follow the pinned upstream fork, but the semantic operations must remain separate:

    interface TufStorage {
      readMetadata(name: MetadataName): Promise<Uint8Array | null>;
      commitVerifiedMetadata(
        name: MetadataName,
        expectedCurrent: { version: number; sha256: string } | null,
        next: { version: number; sha256: string; bytes: Uint8Array },
        fence: RunFence
      ): Promise<void>;

      createTargetStage(name: TargetName, fence: RunFence): Promise<TargetStage>;
      commitVerifiedTarget(
        stage: TargetStage,
        expected: { length: number; sha256: string },
        fence: RunFence
      ): Promise<void>;
      discardTargetStage(stage: TargetStage, fence: RunFence): Promise<void>;
    }

This is a contract sketch, not code to copy blindly: align the names and call sites with the exact tuf-js 6.0.3 updater flow and its stream semantics before implementing. Names are logical, normalized TUF-relative paths; the adapter must not accept arbitrary absolute paths.

### Metadata rules

- Keep root, timestamp, snapshot, targets and delegated-role metadata as distinct objects. Do not collapse them into one opaque cache blob.
- Preserve the exact signed metadata bytes. Hashes stored by the adapter are integrity/index fields, not a replacement for upstream signature verification.
- A write is accepted only when the current run fence is active and the compare-current condition still holds in the same SQLite transaction as the write.
- For versioned roles, reject lower versions. Reject same-version different bytes/digests. An identical same-version write may be treated as idempotent.
- The updater must verify candidate metadata before calling the durable commit operation. The adapter must not mark unverified bytes as trusted.
- Keep last-known-good bytes intact when parsing, signature, threshold, expiry, rollback, or fetch validation fails.

### Sequential root rotation

Root rotation is intentionally not one all-or-nothing refresh batch:

1. Read the currently trusted root.
2. Fetch the next candidate root version.
3. Let the upstream TUF verifier validate it against the currently trusted root and the required root version/threshold rules.
4. Atomically persist that one accepted root transition under the current run fence.
5. Only then continue to the next root version.
6. If a later root, timestamp, snapshot, targets or delegated role fails, retain every already accepted root transition and all last-known-good metadata.

Do not wrap the entire refresh in a transaction that discards valid root transitions because a later role fails. Each accepted root transition is its own short durable commit.

### Target rules

- Stream target bytes into a bounded, request-scoped staging object; never buffer an unbounded artifact in Worker memory or hold a SQLite transaction open during download.
- The upstream updater must finish its expected length and cryptographic target-hash checks before the adapter promotes the staged target.
- Promotion must be atomic and fenced. An incomplete or failed target remains uncommitted and is discarded.
- Release manifest and ZIP attestation verification remains a separate SentryIQ policy layer; a TUF target hash does not establish GitHub workflow identity or release provenance.

## 3. Durable Object transaction and fencing contract

Every durable mutation must check ownership in the same transaction as the mutation. The existing PoC run_lock stores a random token and expiry, but it does not yet implement a monotonic fencing epoch. A token alone is not sufficient for a production multi-run protocol.

Required lease record:

- run_id: unique identifier for the scheduled run.
- fence: monotonically increasing integer allocated on every successful lease acquisition/takeover.
- token_hash: hash of a high-entropy bearer token; do not persist or log the raw token.
- expires_at: lease expiry.

Required behavior:

- Acquire in a short transaction; reject an unexpired lease; increment and persist the fence on takeover.
- Renew only when run ID, fence and token match and the lease is still active.
- Before each metadata/target commit, check run ID, fence, token and unexpired lease inside that same transaction.
- Release only the exact active lease. A stale owner cannot release or mutate the new owner's lease.
- No SQLite transaction spans network fetch, TUF cryptographic verification, artifact download, attestation verification, or Node 4 calls.
- A stale worker must not submit a new Node 4 report or advance the release pin after lease expiry/takeover.

The fence must be passed as explicit context to the TUF storage adapter. It must not be inferred from AsyncLocalStorage alone; asynchronous context carries the request context, while the durable transaction independently verifies ownership.

## 4. Crash and recovery semantics

- Crash before metadata commit: staged candidate is discarded; last-known-good metadata remains.
- Crash after one verified root transition commits: that root remains durable and is the trusted starting point on restart.
- Crash during a later role update: incomplete role write is absent; prior valid role bytes remain.
- Crash during target download: stage is disposable and never visible as a committed target.
- Crash after target hash verification but before promotion: retry or discard the stage; never assume promotion happened.
- Restart/eviction: a new Durable Object instance must reconstruct the full TUF state from SQLite without relying on Worker /tmp, in-memory maps, module globals, or container disk.

For each operation, define idempotency and expected-current semantics. Avoid a generic "commit all staged files" operation that can accidentally publish metadata from a failed refresh.

## 5. Required implementation strategy

1. Pin the exact upstream tuf-js 6.0.3 source and @sigstore/tuf 5.0.1 wrapper source, including package integrity hashes.
2. Make the smallest maintainable fork/patch that injects TufStorage into the updater. Replace only the direct metadata/target filesystem operations. Do not monkey-patch global fs, and do not replace TUF verification logic.
3. Add a patch-drift test that enumerates every upstream filesystem call site used by the updater and fails if an upgrade introduces an unreviewed call site.
4. Keep the patch and lockfile reviewable. Pin the upstream tarball integrity and patch digest; document how to rebase and audit the patch on every upstream update.
5. Retain the current filesystem shim only as a unit-test utility if useful. Do not use it as evidence of integration.

If a maintained upstream release adds a first-class storage adapter, prefer that over a long-lived fork after equivalent tests pass.

## 6. Acceptance matrix

| Area | Required evidence |
|---|---|
| Real integration | The actual @sigstore/tuf verifier path performs refresh using the DO adapter; no native filesystem fallback is used for durable metadata/targets. |
| Bootstrap | Fresh DO storage bootstraps the pinned trusted root and required metadata through the adapter. |
| Root rotation | Multiple sequential root versions verify and each accepted root survives a later-stage failure and restart. |
| Metadata validity | Timestamp/snapshot/targets/delegated metadata signatures, thresholds, expiry and version checks remain upstream-enforced. |
| Rollback/equivocation | Older versions and same-version different bytes are rejected; last-known-good metadata survives failed refresh. |
| Targets | Real target download is streamed, length/hash checked, atomically promoted and recovered after restart. |
| Fencing | Concurrent runs, expiry/takeover, stale-owner writes, renew/release mismatch and stale target promotion are rejected. |
| Crash safety | Inject failure before/after every commit boundary and prove restart state is deterministic. |
| Isolation | No global fs monkey-patch; no durable dependence on /tmp; no long SQLite transaction during network or crypto work. |
| Regression | Genuine SentryIQ v0.1.2 attestation and negative signature tests still pass with the adapter active. |

## 7. Current status and release gate

The current PoC does not satisfy the real-integration or target rows. Draft PR #143 adds a Durable Object monotonic fencing epoch, token-hash-backed lease identity, and a fenced compare-and-set primitive for role-keyed TUF metadata. Its 15-test workerd run passes the metadata storage primitive and stale-owner cases. These primitives are not yet connected to the stock TUF updater, so they do not satisfy the real-integration or end-to-end root-rotation rows. The separate SQLite filesystem shim remains disconnected, and target staging is still outstanding.

Node A remains a non-production PoC until the full acceptance matrix is implemented and exercised in workerd, then validated in a Cloudflare account-backed staging environment. No release pin may be advanced until the full attestation, manifest/ZIP, origin/private-host, and Node 4 gates have passed.


## 8. Source-level integration findings (pinned upstream revisions)

A direct source review of Sigstore JS commit 3154029799fe44e6a037fc634e175abe091521b3 and tuf-js commit ce8ba9cd3f074531976ff4eef82af1f3adae3728 shows that the integration seam must cover more than the updater's metadata directory:

- Sigstore's TUFClient wrapper performs filesystem cache-directory creation, seeds root.json and optional seed targets, and constructs the tuf-js Updater with metadataDir and targetDir. Its target helper later reads the downloaded target from a local path. Therefore a tuf-js-only patch is insufficient unless the Sigstore wrapper is also changed or replaced by an explicitly reviewed SentryIQ integration.
- tuf-js Updater reads root metadata synchronously during construction; reads timestamp, snapshot and delegated metadata from local files; writes each accepted metadata role; checks cached targets; downloads targets to a temporary file; verifies target length/hash from a stream; then copies the verified target to its target path.
- tuf-js Fetcher itself creates a temporary file, streams response chunks into it with a maximum-length check, invokes a handler, and removes the temporary file. Its downloadBytes path reads that temporary file back into memory. Keep this request-scoped temporary staging distinct from durable metadata/target storage, and retain explicit size limits.
- The updater's loadRoot currently updates its in-memory TrustedMetadataStore before calling persistMetadata. If durable persistence fails after that in-memory mutation, the current updater instance must be treated as poisoned and discarded; do not continue a refresh with a trusted root that was not committed. On restart, rebuild the updater from the last durable root.
- The updater's timestamp/snapshot/delegated-role update methods similarly mutate the in-memory trusted set before persisting the accepted bytes. The integration must fail closed on a persistence error and discard the updater instance; no later stage or target may proceed on a partially committed in-memory view.

Implementation consequence: introduce a narrow TUF storage seam in tuf-js for metadata/target persistence and adapt the Sigstore wrapper's cache bootstrap and target-return behavior. A custom Fetcher alone is not enough because the stock Updater still owns metadata and target filesystem calls. Do not claim the adapter is integrated until a real refresh and target download execute through these seams with filesystem fallback disabled.


## 9. Implementation status update

As of the current review, draft PR #143 (based on the Sigstore compatibility branch) contains the first fenced metadata persistence primitive. Its latest workerd CI run passed 15/15 tests, including genuine release attestation verification, tampered DSSE rejection, Ed25519 regression, stale lease owner rejection after takeover, and TUF metadata compare-and-set/digest/rollback/equivocation/root-sequence/delegated-role tests.

This improves the Durable Object storage boundary but is not an implementation of the TUF adapter. The next code change must modify the pinned tuf-js updater and Sigstore wrapper call sites identified above so that:
- updater bootstrap reads the pinned root through durable storage;
- each candidate metadata role is verified by the existing TUF logic and then committed with the current run fence;
- a persistence failure discards the mutated updater instance;
- target temporary download, hash verification and final target retrieval use a fenced staging/promote/read path;
- tests prove the real @sigstore/tuf client refreshes and downloads targets without native filesystem fallback.

Do not mark root rotation or TUF acceptance complete based only on the DO metadata primitive tests.

## 10. Concrete pinned-source call-site inventory and patch order

The adapter patch must cover the following exact upstream responsibilities. This inventory is based on the pinned source revisions in section 8; it is deliberately not a blanket filesystem replacement.

### tuf-js 6.0.3 — packages/client/src/updater.ts

| Updater operation | Current filesystem behavior | Required replacement |
|---|---|---|
| Constructor / loadLocalMetadata(root) | fs.readFileSync(path.join(metadataDir, "root.json")) | Synchronous bootstrap from a preloaded, verified root byte snapshot supplied by the storage adapter; no implicit native disk access |
| loadLocalMetadata(role) | fs.readFileSync for timestamp, snapshot and delegated roles | Read exact role bytes from durable metadata storage; absence remains distinguishable from corrupt metadata |
| persistMetadata(role, bytes) | fs.writeFileSync after upstream validation | Await a fenced per-role commit with expected-current identity; persistence failure poisons the updater instance |
| findCachedTarget | existsSync plus createReadStream | Read a committed target through storage and verify it before returning a cache hit |
| downloadTarget | fetcher temp file, createReadStream verify, copyFileSync promote | Stream into bounded disposable stage, verify expected length/hash, then fenced atomic promotion |
| generateTargetPath | constructs local path | Return an opaque target handle/key from the adapter, not a filesystem path |

Root update sequencing must remain unchanged semantically: TrustedMetadataStore.updateRoot validates the candidate; after validation, the accepted root is committed durably before the next root version is fetched. Because the current upstream code mutates its in-memory trusted set before persistence, any persistence failure must mark the updater unusable. The wrapper must construct a fresh updater from the last durable state for any retry.

### @sigstore/tuf 5.0.1 — packages/tuf/src/client.ts and target helper

The wrapper currently creates cache and targets directories; seeds root.json from a supplied root path or embedded repository seed; constructs tuf-js with metadata and target directory paths; and returns a filesystem path through the target helper, which then reads the file.

Replace these with an explicit adapter option passed to tuf-js and a byte-returning verified-target API. Keep the existing public initTUF / target retrieval behavior compatible for non-Workers consumers if practical; the Workers integration must opt into the adapter explicitly. Embedded seeds are allowed only as the initial root/seed inputs and must be copied into durable storage under the run fence before refresh starts.

### Patch packaging and drift control

Use a narrowly scoped, reviewable patch against exact tuf-js@6.0.3 and @sigstore/tuf@5.0.1 sources. Pin both package tarball integrity values from the lockfile. The patch application must:
1. verify package versions and source file hashes before editing;
2. fail closed if an expected source fragment is absent or appears more than once;
3. replace every listed metadata/target filesystem operation, not just the root read;
4. expose no default native-filesystem fallback when the adapter option is selected;
5. have a drift test that enumerates the dependency's remaining filesystem call sites and fails on any unreviewed addition;
6. be reproducible from a clean npm ci, with the patch applied deterministically before tests/build.

Do not use runtime monkey-patching, module-loader interception, global fs replacement, or AsyncLocalStorage as a substitute for explicit adapter injection.

### Implementation slices

1. **Metadata bootstrap and commit:** inject adapter into tuf-js; bootstrap root; refresh root/timestamp/snapshot/targets/delegations; prove each accepted root version commits before the next fetch. Add failure injection immediately after each successful role validation and before its commit.
2. **Updater poisoning:** make every metadata persistence failure terminal for that updater object; test that a second refresh on the same instance is rejected, while a newly constructed instance resumes from the last committed root/metadata.
3. **Target staging:** implement bounded streaming stage, length/hash verification, atomic fenced promotion, and committed target byte retrieval. Ensure temporary fetcher files remain ephemeral and are never treated as durable cache.
4. **Sigstore wrapper:** route bootstrap, metadata and target reads through the adapter, then run the unchanged genuine SentryIQ release verification against the returned target bytes.
5. **Adversarial/restart matrix:** fail at each boundary, evict/reconstruct the DO instance, retry under a newer fence, and prove no stale run can commit or return an uncommitted target.

Acceptance remains blocked until all five slices run in the real Workerd integration test with native filesystem fallback disabled.