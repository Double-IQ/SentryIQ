# Node A Cloudflare feasibility review

**Review date:** 2026-11-22  
**Scope:** Read-only source review and current Cloudflare platform documentation.  
**Status:** Feasibility assessment only; no Cloudflare account access, runtime proof, credentials, deployment, or production changes.

## Executive finding

The Worker + Cloudflare Container route is the lower-policy-drift first proof of concept because it can retain the existing PHP verifier and orchestration as the behavioral reference. It is not a drop-in deployment: the existing PHP stores assume a durable POSIX filesystem, while Cloudflare Container disks are ephemeral. A reviewed storage boundary is mandatory before any acceptance.

A Worker-native TypeScript implementation remains a fallback, not the preferred first implementation. It must reproduce the full Sigstore/Fulcio/Rekor/SLSA/TUF policy and solve Worker-compatible TUF metadata persistence. The existing architecture review already identified that the upstream JavaScript TUF cache uses synchronous filesystem and home-directory assumptions; enabling Node compatibility alone does not establish a Durable Object storage adapter.

No implementation path is accepted until the same genuine golden attestations and adversarial fixtures produce equivalent accept/reject outcomes to the PHP reference.

## 1. Existing PHP compatibility target

The current Node A source is a PHP composition of `IntegrityNodeA`, `IntegrityNodeScheduledRunner`, `NativeSigstoreIntegrityAttestationVerifier`, the per-node release-state store, the event exchange, and the private-host attestation gate.

The native verifier pins and checks:

- PHP extensions: cURL, OpenSSL and Sodium (per the Integrity Node adapter deployment contract).
- `k2gl/sigstore-verify` exactly `1.6.1`.
- Patched `k2gl/tuf` exactly `1.2.1`.
- Composer autoload and the pinned TUF bootstrap root under private storage.
- GitHub attestation API and bundle verification, Sigstore trusted-root refresh, Fulcio identity, SLSA provenance, repository/workflow/tag/source-commit policy, and exact subject digest/name.
- Two independently verified subjects: `release-manifest.json` and `sentryiq-<version>.zip`.

The PHP state implementations also depend on regular files, restrictive POSIX modes, `flock()`, temporary-file publication, `fsync()`, and atomic `rename()`. The release pin and TUF root stores therefore cannot be pointed at a container's local disk and treated as durable.

## 2. Option A — Worker + Container running PHP

Cloudflare's current Containers documentation says Containers run arbitrary Linux/runtime workloads, are available on Workers Paid, and are controlled by a Worker. The Durable Object Container API provides a Durable Object control plane with SQLite storage and alarms. This makes a PHP image technically plausible, subject to an actual build and runtime test.

Important platform facts:

- Containers are available on Workers Paid.
- Container disk is ephemeral by default. When a container sleeps, its next start receives a fresh disk from the image.
- Container snapshots are documented as public beta, immutable point-in-time filesystem snapshots tied to the image version. They are not a substitute for transactional mutable security state.
- Cron Triggers run in UTC. Current documentation gives scheduled invocations a 15-minute wall-time ceiling; CPU limits depend on the schedule interval and plan.
- SQLite-backed Durable Objects provide transactional storage and are suitable for authoritative release-pin, TUF metadata, lock/lease and run-record state.

### Required adaptation

Keep the PHP verifier and its temporary artifact files inside the container, but move authoritative mutable security state behind a narrow persistence interface implemented by the Durable Object's SQLite store.

At minimum, this adapter must support:

1. Atomic compare-and-advance of version, source commit, manifest digest and ZIP digest.
2. Monotonic TUF root/metadata persistence only after a successful TUF refresh.
3. A serialized run lease/lock with crash recovery and explicit lease expiry semantics.
4. Atomic commit of the approved release pin only after private-host attestation and Node 4 acknowledgement.
5. Bounded, redacted run records and replay/nonce state where required.
6. Fail-closed behavior on storage errors, stale leases, duplicate run attempts and partial commits.

Do not use container disk, process memory, snapshots, Workers KV, or an untested FUSE/R2 mount as the authoritative state store. Container disk may hold only disposable downloads, decompressed bundles and temporary working files.

The PHP refactor should isolate storage/locking from verification policy. Preserve the existing verification policy and wire contracts. Add adapter contract tests that run against both the existing filesystem test adapter and the Durable Object-backed implementation.

## 3. Option B — Worker-native TypeScript

A native Worker avoids the PHP container and may simplify direct Cron/Fetch/Web Crypto integration, but it requires a security-sensitive port of orchestration, Sigstore/TUF verification, provenance policy, private-host attestation, Node 4 exchange, state management and alert delivery.

The unresolved blocker is not basic TypeScript execution. It is the complete maintained Sigstore/TUF dependency graph and its storage behavior in the Workers runtime. The existing architecture review identified filesystem-cache operations in the upstream JavaScript TUF client (`fs.existsSync`, `mkdirSync`, `writeFileSync`, `copyFileSync`, and `os.homedir()` assumptions). A Worker-compatible, reviewed durable metadata adapter or a different maintained compatible implementation must be demonstrated. Do not treat `nodejs_compat` as proof of compatibility.

Acceptance must demonstrate the exact GitHub bundle formats and Rekor evidence generated by this repository, Fulcio identity and certificate transparency checks, TUF rotation, both attested subjects, and all current repository/workflow/builder/event/tag/commit/digest constraints.

## 4. Comparative assessment

| Area | Worker + PHP Container | Worker-native TypeScript |
|---|---|---|
| Reuse reviewed verifier | High | Low; security-sensitive port |
| PHP extension/runtime proof | Required | Not applicable |
| TUF persistence | Required adapter | Required adapter |
| Release policy drift risk | Lower if PHP policy retained | Higher until equivalence proven |
| Filesystem assumptions | Must be removed from authoritative state | Avoided in Worker, but upstream cache needs replacement |
| Runtime proof | Real Cloudflare Container | Real Cloudflare Worker |
| First PoC priority | **Preferred** | Parallel feasibility spike only if useful |

This is a prioritization for proof-of-concept work, not a final architecture approval. The PHP Container path must be rejected if the required storage boundary cannot be implemented without weakening the verifier's trust guarantees.

## 5. Bounded proof-of-concept sequence

### PoC A — PHP Container

1. Confirm Workers Paid and Containers entitlement in the owner's Cloudflare account; do not assume entitlement.
2. Build a minimal PHP image with the required PHP version and cURL/OpenSSL/Sodium extensions.
3. Install the exact private Composer artifact and assert the exact package versions at startup.
4. Execute a non-production CLI smoke test and a genuine golden attestation verification inside the container.
5. Demonstrate that container restart/sleep loses local working files without losing the authoritative DO-backed TUF root and release pin.
6. Implement and test the narrow DO persistence adapter; inject crashes between each verification and commit stage.
7. Verify concurrent scheduled/manual invocations serialize and that failed runs cannot advance the release pin.
8. Compare golden and adversarial fixtures against the PHP reference implementation.
9. Measure cold start, verification duration, CPU/memory, artifact sizes, outbound requests and cost using representative fixtures.

### PoC B — TypeScript runtime feasibility

1. Lock a maintained Sigstore JavaScript/TUF dependency graph.
2. Import and run the exact packages in a deployed non-production Worker.
3. Prove a Durable Object-backed TUF metadata adapter, including root rotation and restart/eviction persistence.
4. Verify the same genuine ZIP and manifest attestations and policy claims.
5. Run the same negative fixtures and compare outcomes with the PHP reference.

### Decision gate

Choose the implementation only after comparing actual runtime compatibility, durable-state correctness, golden attestation outcomes, adversarial test parity, operational complexity and measured cost. Do not provision production secrets or schedules during the PoCs.

## 6. Current conclusion and outstanding owner inputs

**Technical direction:** start with PoC A (PHP Container + Worker/SQLite Durable Object control plane). Keep PoC B as a fallback/benchmark if the JavaScript TUF storage obstacle can be resolved cleanly.

**Not yet verified:** Cloudflare account entitlement, account ownership/access, container build, PHP extension availability in the selected image, private Composer artifact retrieval, actual attestation verification in Cloudflare, Durable Object adapter correctness, alert delivery, schedule, runtime cost and deployment.

No owner action is needed to complete this repository-level feasibility assessment. Owner access/approval will be needed before any account inspection, credential provisioning, paid-plan change, production configuration or deployment.

## References

- Cloudflare Containers overview: https://developers.cloudflare.com/containers/
- Cloudflare Containers FAQ (ephemeral disk): https://developers.cloudflare.com/containers/faq/
- Durable Object Container API: https://developers.cloudflare.com/containers/api/durable-object-container/
- Container snapshots: https://developers.cloudflare.com/containers/guides/snapshots/
- Container limits and instance types: https://developers.cloudflare.com/containers/platform/limits/
- Durable Objects SQLite limits: https://developers.cloudflare.com/durable-objects/platform/limits/
- Workers limits and Cron execution: https://developers.cloudflare.com/workers/platform/limits/
- Cron Triggers: https://developers.cloudflare.com/workers/configuration/cron-triggers/
- Native Sigstore adapter contract: `docs/security/native-sigstore-integrity-node-adapter.md`
- Node A platform boundary: `docs/security/integrity-node-a-cloudflare-workers.md`
