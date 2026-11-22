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
