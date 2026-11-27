# Node A Cloudflare feasibility review

**Review date:** 2026-11-22  
**Scope:** Read-only source review and current Cloudflare platform documentation.  
**Status:** Feasibility assessment only; no Cloudflare account access, runtime proof, credentials, deployment, or production changes.

## Executive finding

The repository already contains an active Worker-native TypeScript runtime/storage proof of concept in [PR #120](https://github.com/Double-IQ/SentryIQ/pull/120). It is materially ahead of the PHP Container alternative: it exercises the actual workerd runtime, the Sigstore verifier/TUF packages, Durable Object SQLite state, an expiring token-bound run lease, monotonic release-pin primitives, and a prototype filesystem bridge for TUF metadata. The next implementation work should continue that existing branch rather than create a parallel runtime prototype.

The TypeScript path is not accepted yet. The upstream TUF client is still not wired to the Durable Object filesystem bridge, so persistent metadata refresh/rotation remains a major technical blocker. The genuine SentryIQ v0.1.2 bundle's Rekor SET can be verified with the Node crypto path after importing the bare `crypto` module; the earlier KeyObject cross-realm hypothesis is disproven because the key is an instance of both `node:crypto.KeyObject` and the bare `crypto.KeyObject`. The complete Sigstore verifier still fails in workerd with `Failed to initialize verification context` during certificate-chain verification. Isolated diagnostics establish that the genuine Fulcio leaf verifies against one trusted intermediate CA using both native `X509Certificate.verify` and Sigstore's X.509 implementation, and that the self-signed trusted roots verify. The trusted root contains one single-certificate root authority and one intermediate-plus-root authority. Both the genuine leaf-to-intermediate edge and the intermediate-to-root edge verify successfully in native X.509 and Sigstore's X.509 implementation; the self-signed roots also verify. The embedded Fulcio SCT also verifies against its matching trusted CT log key in both native crypto and Sigstore. The certificate chain and SCT stage are positively demonstrated. For both the Rekor checkpoint signature and DSSE PAE signature, native `crypto.verify` succeeds with explicit SHA-256 but throws `Failed to initialize verification context` when passed an undefined algorithm. The actual installed `@sigstore/core@4.0.1` compiled package forwards the optional algorithm directly to `crypto.verify` and contains no algorithm-inference branch, despite newer repository source containing such logic. A diagnostic-only CI patch now adds EC/RSA SHA-256 inference using the key's `asymmetricKeyType`, while leaving EdDSA and RSA-PSS defaults unchanged. With that patch, CI verifies the genuine v0.1.2 bundle end to end, rejects a one-byte-tampered DSSE signature after trusted-key validation, preserves Ed25519 verification, and passes all 13 tests. The npm registry still lists `@sigstore/core@4.0.1` as latest, so there is no newer released package to consume directly. The patch remains test-harness-only at this point; production adoption requires a pinned, reviewed dependency patch/fork, committed lockfile and full runtime/TUF acceptance. No production acceptance is approved yet; the complete `Verifier.verify` path must pass with the genuine bundle, trusted root, and negative-signature tests before acceptance.

The Worker + PHP Container route remains a fallback if the TypeScript TUF integration cannot be made safe. It may preserve more of the reviewed PHP verifier policy, but is not a drop-in deployment: the existing PHP stores assume durable POSIX filesystem semantics, while Container disks are ephemeral. A Durable Object persistence boundary would still be mandatory.

No implementation path is accepted until genuine SentryIQ release attestations and adversarial fixtures pass in the target runtime with policy outcomes equivalent to the PHP reference.

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

## 2.1 Required Durable Object state contract and run protocol

The existing PHP implementation holds its filesystem lock for the complete run. Preserve the exclusion guarantee, not the implementation mechanism: never hold a SQLite transaction open while fetching GitHub assets, refreshing TUF, checking the origin, contacting the private-host collector, waiting for Node 4, or delivering an alert.

Use one dedicated Durable Object as the serialization authority for Node A. The minimum logical records are:

| Record | Required fields / invariant |
|---|---|
| Node state | Explicitly bootstrapped baseline and current approved version, full commit, manifest SHA-256, ZIP SHA-256, approval timestamp; baseline cannot be silently learned from the live origin |
| Run lease | Unique run ID, monotonically increasing fencing token, lease expiry, heartbeat/renewal time; only one live lease |
| TUF metadata | Exact accepted metadata bytes (or a lossless representation), role/version and digest; root versions monotonic, same-version different bytes rejected |
| Run record | Run ID, fencing token, phase, timestamps, candidate identities/digests and bounded redacted outcome; no secrets, bearer tokens, raw private-host payloads or report bodies |
| Challenge binding | Hash of nonce, run ID, candidate digests and expiry, if local durable replay diagnostics are required; never log the raw nonce |

### Lease and fencing rules

1. Acquire a lease in a short transaction. Increment the fencing token on every new lease acquisition; return the token to the caller.
2. Renew the lease in short transactions during long verification. A renewal succeeds only for the same run ID and current fencing token. Set the lease duration comfortably above the heartbeat interval and account for maximum expected pauses.
3. Before every durable mutation, check in the same transaction that the run ID, fencing token and unexpired lease still match. A run that wakes after expiry is stale even if its PHP process is still executing.
4. Release only the matching lease. An expired lease can be replaced by a later run; the later run receives a higher fencing token.
5. If renewal fails or the lease is lost, stop work and do not submit a new Node 4 report or advance state. If a remote request is already in flight, its eventual response must not authorize a local commit by the stale run.

A lease is not a transaction held open across the run. The fencing token is what prevents an expired process from committing after another run has taken ownership.

### Commit and crash boundaries

- **TUF refresh:** read the current persisted metadata; perform the network refresh and cryptographic verification outside a DB transaction; then atomically compare the current metadata version/digest and lease fence, and store the newly accepted metadata. A failed refresh must leave the last accepted metadata untouched. Preserve all metadata required by the TUF client, not only root.json, if its cache contract requires timestamp/snapshot/targets/delegations.
- **Candidate preparation:** stage the manifest and ZIP as disposable container files, hash them, and bind the candidate version/commit/digests to the run record. Re-hash the exact files after verification, as the PHP implementation does.
- **Verification:** perform attestation, provenance, public-origin, security-header and private-host checks outside transactions. Keep the existing requirement that both the manifest and ZIP are independently attested.
- **Node 4 exchange:** request a challenge bound to the target, release version, commit and both artifact digests; verify using its nonce; submit the signed report and require the expected acknowledgement. The current PHP flow performs this exchange before advancing the local release pin. Preserve that ordering.
- **Final pin commit:** in one short transaction, re-check the current lease fence and compare the candidate against the latest persisted pin. Reject downgrade, same-version commit retargeting, and same-version digest replacement. If approved, update the pin and mark the run successful atomically. This transaction is the only operation allowed to advance the pin.
- **Crash after Node 4 accepted but before local commit:** do not blindly replay the old signed report or assume the pin advanced. Record the run as indeterminate if possible, alert independently, and let a later run obtain a fresh challenge and repeat verification/reporting. Node 4's existing nonce/replay policy remains authoritative.
- **Crash before final commit:** previous approved pin remains authoritative. Expired leases are recoverable by a new fencing token; stale runs cannot commit.
- **Alert delivery:** preserve the direct owner-alert path independent of Node 4. Do not claim exactly-once alert delivery unless the selected provider exposes a tested idempotency contract. Record bounded delivery outcome without logging payloads or credentials.

### Adapter acceptance tests

The storage interface must have the same contract tests against the existing filesystem reference adapter and the Durable Object adapter. Include: two concurrent acquisitions; lease expiry and takeover; stale owner renewal/release/commit rejection; heartbeat during slow verification; crash after TUF verification but before metadata commit; root rollback and same-version byte replacement; crash after Node 4 acknowledgement but before pin commit; concurrent candidate pin compare-and-advance; same-version digest replacement; and container restart with all authoritative state retained. Test transactions under actual Durable Object SQLite semantics, not only a local SQLite emulator.

## 3. Option B — Worker-native TypeScript

A native Worker avoids the PHP container and is already represented by PR #120's isolated runtime/storage PoC. It still requires production integration of orchestration, Sigstore/TUF verification, provenance policy, private-host attestation, Node 4 exchange, state management and alert delivery.

The unresolved blocker is not basic TypeScript execution. It is the complete maintained Sigstore/TUF dependency graph and its storage behavior in the Workers runtime. The existing architecture review identified filesystem-cache operations in the upstream JavaScript TUF client (`fs.existsSync`, `mkdirSync`, `writeFileSync`, `copyFileSync`, and `os.homedir()` assumptions). A Worker-compatible, reviewed durable metadata adapter or a different maintained compatible implementation must be demonstrated. Do not treat `nodejs_compat` as proof of compatibility.

Acceptance must demonstrate the exact GitHub bundle formats and Rekor evidence generated by this repository, Fulcio identity and certificate transparency checks, TUF rotation, both attested subjects, and all current repository/workflow/builder/event/tag/commit/digest constraints.

## 3.1 Current Worker PoC results and the exact TUF storage blocker

The current implementation work is proceeding on the Worker-native TypeScript path in `cloudflare/node-a-poc`; the PHP Container path remains the fallback if the Worker storage boundary cannot be completed safely.

### Verified runtime and Sigstore result

- The actual `workerd` suite now validates the genuine SentryIQ v0.1.2 GitHub attestation bundle using the current Sigstore trusted root.
- CI run `45072007397` passed all 13 tests after applying the version-guarded `@sigstore/core@4.0.1` compatibility patch in a separate workflow step.
- The suite rejects a one-byte-tampered genuine DSSE signature after timestamp and trusted signing-key validation, and preserves Ed25519 verification.
- The patch only infers SHA-256 for EC/RSA keys. It does not change certificate, SCT, TUF, identity, provenance, digest or release policy checks. It is under review in PR #140 and is not yet production-approved.
- This is a genuine cryptographic verification proof, not full Node A acceptance. The manifest/ZIP policy, origin/private-host checks, Node 4 exchange, TUF persistence, alert path and production deployment remain incomplete.

### Confirmed upstream TUF filesystem seams

The pinned Sigstore wrapper is `@sigstore/tuf@5.0.1`, backed by `tuf-js@6.0.3`. The current Durable Object SQLite filesystem prototype is not connected to either package.

The source review identifies filesystem dependencies at both layers:

| Layer | Current filesystem dependency | Required replacement |
|---|---|---|
| `@sigstore/tuf` cache bootstrap | `existsSync`, `mkdirSync`, `copyFileSync`, `writeFileSync` for cache directories, seed root and seed targets | Explicit seed bytes and injected storage; no implicit cache directory |
| `@sigstore/tuf` target read | `fs.readFile` of the downloaded target path | Return verified target bytes directly |
| `tuf-js` updater constructor | Synchronous `readFileSync` of local root metadata | Async factory or explicit initial root bytes loaded from Durable Object storage |
| `tuf-js` metadata cache | `readFileSync` and `writeFileSync` for root, timestamp, snapshot and delegated targets | Async metadata storage interface |
| `tuf-js` target cache | `existsSync`, `createReadStream`, `copyFileSync` | Async target byte storage and re-verification on read |
| `tuf-js` fetcher | Temporary files, `createWriteStream` and `createReadStream` in `downloadFile` / `downloadBytes` | Bounded in-memory byte download for metadata and the Sigstore trusted-root target; no temp-file dependency |

A custom Fetcher alone is insufficient: it changes network transport, not metadata or target persistence. A global `node:fs` monkey-patch is explicitly rejected.

### Required storage interface

The maintained adapter should be a narrow patch/fork of the pinned `tuf-js` and Sigstore wrapper, exposing an explicit interface equivalent to:

```ts
interface TufStorage {
  getMetadata(role: string): Promise<Uint8Array | undefined>;
  putMetadata(role: string, bytes: Uint8Array, fence: RunFence): Promise<void>;
  getTarget(path: string): Promise<Uint8Array | undefined>;
  putTarget(path: string, bytes: Uint8Array, fence: RunFence): Promise<void>;
}
```

The updater needs an async creation path that loads the persisted root (or a pinned bootstrap seed) before constructing `TrustedMetadataStore`. All other local metadata reads become asynchronous. Metadata persistence is called only after the existing TUF verification/update operation succeeds.

Target download should use the existing verified `TargetFile` metadata, fetch bounded bytes, verify length and all advertised hashes using `TargetFile.verify(Readable.from([bytes]))`, and then commit the bytes to the target store. The Sigstore wrapper should expose the verified `trusted_root.json` bytes rather than returning a filesystem path.

### Durable Object commit semantics

- Store exact bytes for root, timestamp, snapshot, top-level targets and every delegated targets role needed by the updater. Store role, version, SHA-256 digest and accepted-at metadata alongside the bytes.
- Persist each verified root rotation separately and in order. Do not batch multiple root versions into one all-or-nothing commit: if root N is verified and accepted, commit it before fetching/verifying N+1.
- Fetch and cryptographically validate outside SQLite transactions. Each short write transaction checks the current run ID, monotonically increasing fencing token and unexpired lease in the same transaction as the metadata/target commit.
- The DO adapter must reject root version skips/rollback, same-version different bytes, timestamp rollback, snapshot rollback and stale-run writes. The upstream `TrustedMetadataStore` remains responsible for signature thresholds, root self-signature, expiry and TUF role/hash validation; the DO compare-and-store layer is an additional durability/fencing boundary, not a replacement verifier.
- A failed refresh leaves last-known-good metadata untouched. If persistence fails after an in-memory TUF update, abort the run; do not continue using uncommitted state.
- On Worker/DO restart, recreate the updater from persisted metadata. Never rely on `/tmp`, process memory, Container disk or a filesystem shim for authoritative TUF state.

### Adapter acceptance tests before production

1. Bootstrap from the pinned Sigstore TUF root seed and fetch the genuine `trusted_root.json` target through the actual adapter.
2. Refresh all metadata roles and any delegated roles; verify metadata expiry, timestamp/snapshot version binding, target length/hash and role thresholds.
3. Exercise sequential root rotation, including a crash after each accepted root version and restart from the last committed version.
4. Prove failed timestamp/snapshot/targets refresh preserves last-known-good bytes.
5. Reject root rollback, root version skip, same-version byte replacement, timestamp rollback, snapshot rollback, target hash/length mismatch and expired metadata.
6. Restart the Durable Object and prove the complete metadata set and cached target bytes survive.
7. Run two concurrent refresh attempts; stale fencing tokens must be unable to write metadata or targets.
8. Compare accept/reject outcomes against the PHP reference TUF implementation using the same golden and adversarial metadata fixtures.

Until this adapter is integrated into the real Sigstore TUF client and passes these tests, Node A remains a runtime/crypto PoC and is not production-ready.

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

**Technical direction:** continue PR #120 as the primary Node A implementation track. Prioritize the TUF Durable Object integration and fix the failing runtime CI. Keep Worker + PHP Container as a fallback only if the TypeScript TUF integration cannot meet the same trust and persistence requirements. Do not create a duplicate runtime PoC.

**Not yet verified:** Cloudflare account entitlement, account ownership/access, container build, PHP extension availability in the selected image, private Composer artifact retrieval, actual attestation verification in Cloudflare, Durable Object adapter correctness, alert delivery, schedule, runtime cost and deployment.

No owner action is needed for the next repository-level work on PR #120. Owner access/approval will be needed before Cloudflare account inspection, credential provisioning, paid-plan change, production configuration or deployment.

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
