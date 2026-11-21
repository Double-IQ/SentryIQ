# Integrity Node A — Cloudflare Workers implementation boundary

**Status:** platform selected; implementation and runtime acceptance not yet complete.  
**Owner-confirmed platform:** Cloudflare Workers.  
**Canonical target:** `https://sentryiq.bichet.co.za`.  
**Identity:** `integrity-a`.

## 1. Why the existing PHP entry point cannot simply be deployed

The current Node A composition is PHP-based. It constructs `IntegrityNodeA`,
`IntegrityNodeScheduledRunner`, `NativeSigstoreIntegrityAttestationVerifier`,
`IntegrityNodeReleaseStateStore`, `IntegrityNodeEventRunner`, and the
private-host attestation gate. Cloudflare Workers executes JavaScript/TypeScript
(or Python), not PHP. Node.js compatibility does not make a PHP application
runnable. Therefore the existing PHP CLI/config bootstrap and its filesystem
assumptions are not a deployable Worker.

The PHP implementation remains the behavioral/security reference. A Worker
implementation must preserve its verification policy and wire contracts; it
must not weaken checks merely to fit the platform.

## 2. Intended Worker composition

Use a Cloudflare Worker as the independent control plane. Two execution
shapes are viable and must be compared in a small proof of concept before
choosing the final one:

### Option A — Worker + Cloudflare Container (preferred first PoC)

A Worker Cron Trigger invokes a SQLite-backed Durable Object, which starts or
routes to a Cloudflare Container running the existing PHP CLI verifier. This
keeps the reviewed PHP `IntegrityNodeA`, Sigstore verifier, report signer,
private-host gate and event client as the reference implementation instead of
immediately rewriting all of their security-sensitive behavior in TypeScript.
Cloudflare Containers can run PHP/Linux workloads, but they are available only
on Workers Paid and container disk is ephemeral by default.

The PHP container may use ephemeral disk only for disposable downloaded
artifacts and temporary working files. It must not treat the container
filesystem, process memory, a warm instance, or a container snapshot as the
authoritative monotonic/TUF state. The Worker/ Durable Object control plane
must provide a reviewed durable state adapter for release pins and TUF metadata,
or another storage design whose atomicity and restart behavior are proven.
The existing filesystem-based PHP stores cannot simply be pointed at an
ephemeral container directory and called durable. A FUSE/R2 mount is not
accepted for lock/rename/fsync-sensitive security state unless those exact
semantics are adversarially tested.

### Option B — Worker-native TypeScript

A dedicated TypeScript Worker reimplements the scheduled-runner orchestration,
Sigstore/TUF adapter, release policy, origin checks, private-host attestation
and Node 4 exchange. Use this only if the complete maintained JavaScript
Sigstore/TUF stack can be made Worker-compatible without weakening trust checks.

Both options use:

- **Cron Trigger** for an independent UTC schedule and a `scheduled()` entry
  point. The schedule must be distinct from Node B's schedule.
- **Durable Object (SQLite-backed)** as the authoritative Node A state owner:
  monotonic deployed-release pin, TUF trusted-root/metadata state, run lock,
  replay/nonce state needed locally, and a minimal audit/run record. Use
  transactions for compare-and-advance and run serialization. Do not use
  Workers KV as the monotonic security state because its propagation model is
  not the required transactional state contract.
- **Worker secrets/bindings** for Node A's Ed25519 report-signing secret,
  GitHub read-only API token, Node 4 A-only bearer token, private-host
  collector bearer token and independently pinned collector public key.
  Never place secrets in source, Wrangler checked-in vars, logs, build output,
  or another node's configuration.
- **Native Fetch/Web Crypto** for HTTPS, SHA-256 and Ed25519 operations where
  applicable. Disable redirects for security-sensitive API calls and validate
  exact hosts, paths, status codes, response sizes and content types.
- **Direct owner alert transport** invoked by the Worker/provider itself. It
  must not route through Node 4 or the SentryIQ origin.
- **Node 4 event exchange** using the existing challenge/report protocol and
  Node A identity. Preserve challenge binding to target origin, release
  version, source commit, ZIP digest and manifest digest; preserve report
  signature verification and replay protection on Node 4.
- **Private-host attestation** using the existing collector endpoint and A-only
  bearer token. Verify the collector's Ed25519 signature against the
  independently pinned public key and enforce the same file/config policy
  maps as the PHP `PrivateHostAttestationGate`. Node A must not accept an
  unsigned or self-described approval.

The Worker is an independent observer, not an authority to rewrite the
release policy or trust root.

## 3. Sigstore/TUF and persistent state are the critical feasibility gates

The PHP native verifier currently uses pinned private Composer dependencies
(`k2gl/sigstore-verify 1.6.1` and patched `k2gl/tuf 1.2.1`) and
`NativeSigstoreReleaseVerifier`. Those PHP packages cannot be loaded in a
Worker. The Worker needs a separately pinned JavaScript implementation based
on the maintained Sigstore JavaScript client and its TUF support, or a
reviewed Worker-compatible adapter around those maintained libraries.

This is **not yet proven**, but the current compatibility picture is more
specific than a blanket statement that Workers lacks filesystem APIs:

- Cloudflare Workers provides `node:fs` with Node.js compatibility. For
  compatibility dates on or after 2026-08-04, Node.js compatibility is enabled
  by default. The Worker virtual filesystem supports synchronous filesystem
  operations, but it is memory-backed: writable `/tmp` files are unique to
  each request and are not shared with later or concurrent requests.
- The virtual filesystem does not implement file permissions or ownership;
  file timestamps are reported as the Unix epoch, and temporary files count
  against the Worker memory limit. These semantics are unsuitable for treating
  the filesystem as durable TUF state or for relying on POSIX permission
  checks.
- The current `@sigstore/tuf` package source uses `os.homedir()`,
  `process.env`, `fs.existsSync`, `fs.mkdirSync`, `fs.copyFileSync`,
  `fs.writeFileSync`, `fs.readFileSync` and `fs.createReadStream`.
  Its TUF client seeds and stores root, timestamp, snapshot, targets and
  downloaded target files in filesystem paths. The current package manifest
  declares Node.js engines `^22.22.2 || ^24.15.0 || >=26.0.0`; Workers'
  Node.js compatibility layer is not a promise of full Node runtime equivalence.
- The public `@sigstore/tuf` options expose a filesystem `cachePath`,
  `rootPath`, mirror/retry controls and cache flags, but no pluggable
  persistent storage interface. Its `tuf-js` updater accepts metadata and
  target directories plus an optional network fetcher; the fetcher does not
  replace the filesystem persistence layer.

Consequently, a smoke test may show that the package imports and executes in a
Worker, but its stock cache cannot survive separate Worker requests. The
implementation must provide a reviewed TUF metadata/target persistence layer
backed by Durable Object storage (including verified sequential root rotation,
timestamp/snapshot/targets, and crash-safe commit semantics), or select another
maintained Worker-compatible Sigstore/TUF implementation. A custom network
fetcher alone is insufficient. For the PHP-container option, separately prove
that the existing PHP TUF library's filesystem operations can be backed by a
durable store without changing its trust/atomicity guarantees; otherwise the
container approach still needs a TUF storage adapter or must be rejected. Any
fork/patch must be narrowly scoped, pinned, reviewed and covered by
upstream-equivalence tests; bypassing TUF is prohibited.

**Verifier-side compatibility is a separate, more promising question.** The
current Sigstore JavaScript `@sigstore/verify` package (source version 4.1.3)
separates bundle/certificate/Rekor verification from TUF retrieval. Its verifier
uses `@sigstore/core` for X.509 parsing and cryptographic operations; that core
wraps Node's `crypto` module for public-key creation, hashing, signature
verification and timing-safe equality. Cloudflare documents its `node:crypto`
API as fully supported, and also supports the relevant Buffer, stream and
`util` APIs. This makes the verifier package a credible Worker PoC candidate,
not a verified production choice. The exact bundle parser, certificate/SCT
checks, Rekor v1/v2 handling, and our repository-specific policy still require
golden-fixture and adversarial tests in the Workers runtime. Most importantly,
a working `@sigstore/verify` import does not solve the separate TUF bootstrap,
rotation and persistent-cache problem described above.

The upstream package manifests also declare modern Node.js engine ranges.
Cloudflare's Node compatibility layer exposes a subset of Node APIs, not a
promise of full Node.js runtime equivalence. Prove the exact locked package
graph in a real Worker deployment, including every imported API and the
persistent cache adapter.

In particular, verify in a real Cloudflare Worker runtime—not just Node.js locally—that the selected package versions support:

1. The exact GitHub attestation bundle format and Rekor entry types emitted by
   this repository's release workflow.
2. Fulcio certificate-chain and identity checks, certificate transparency
   evidence, Rekor inclusion/SET verification, and TUF trusted-root rotation.
3. The repository ID, canonical repository, exact release workflow path/ref,
   push event, GitHub-hosted builder identity, source commit and tag-to-commit
   binding already enforced by `SigstoreProvenance` and
   `ReleaseTrustPolicy`.
4. Both attested subjects independently: `release-manifest.json` and
   `sentryiq-<version>.zip`, with exact subject names and SHA-256 digests.
5. Persistent TUF metadata/root storage through an audited Durable Object
   storage adapter. A process-local cache or in-memory root is not sufficient.
6. Fail-closed behavior for expired metadata, invalid root rotation, missing
   transparency evidence, unsupported bundle types, GitHub/API errors,
   malformed JSON, oversized responses, and unavailable trust services.

Do not substitute a GitHub API response, adjacent checksum, pinned Fulcio
certificate alone, or a Worker secret containing a downloaded root for the
full Sigstore/TUF verification path. Do not use the production-origin manifest
as the trust source before its attestation has been verified.

## 4. Durable state and run protocol

The Worker must not assume local disk or process memory survives an invocation,
eviction, restart or deployment. Persist security state in the dedicated
SQLite-backed Durable Object.

At minimum, the durable state model must atomically preserve:

- the independently initialized known-good release baseline (version, commit,
  manifest SHA-256 and ZIP SHA-256);
- the current monotonic release pin and rejection of older releases or
  same-version identity/digest replacement;
- the last successfully refreshed TUF trusted root and metadata state;
- run serialization so overlapping Cron/manual invocations cannot race;
- replay protection for any challenge/nonce generated or consumed locally;
- a bounded, redacted execution record sufficient to detect missed/failed runs.

A candidate release pin advances only after all release attestations, trust
policy, public-origin asset/header checks, private-host attestation and Node 4
report acknowledgement have succeeded. A partial or failed run must preserve
the previous trusted state. Define and test transaction boundaries explicitly.
Do not treat Cron Trigger execution history as the authoritative security
audit log.

## 5. Public-origin and release verification sequence

The Worker run should follow this order:

1. Acquire the Node A durable run lock; load the independently provisioned
   baseline and persisted Sigstore/TUF state.
2. Fetch the canonical live `/VERSION`, resolve that exact tag to its full
   commit through GitHub, and reject malformed or non-canonical identities.
   Never choose GitHub's latest release as a proxy for what is deployed.
3. Fetch the release manifest and ZIP into bounded streaming/hash pipelines.
   Do not stage release artifacts in a public bucket or trust the origin copy.
4. Retrieve and verify each artifact's GitHub attestation independently using
   the maintained Sigstore JS implementation and persisted TUF state.
5. Apply the same repository/workflow/builder/event/source-commit/subject
   policy as `SigstoreProvenance` and `ReleaseTrustPolicy`.
6. Validate the manifest schema and verify every selected signed public asset,
   including `VERSION`; check required origin security headers and redirect
   policy. Do not claim byte-level validation of dynamic PHP responses.
7. Request a Node 4 challenge bound to the exact target and artifact digests.
8. Obtain and verify the private-host attestation with A-only credentials and
   pinned collector key. Confirm deployed file and private-config digests
   against independently approved policy maps.
9. Produce the Node A signed report, submit it to Node 4, and require the
   expected acknowledgement. Independently alert the owner on every rejection
   or operational failure; Node 4 is not the only alert route.
10. Atomically commit the successful monotonic pin and run result. Preserve the
    previous baseline/pin if any preceding step fails.

The implementation may rearrange network operations for efficiency only if it
preserves these trust dependencies and commit semantics.

## 6. Required implementation and acceptance tests

Create a Worker-specific test suite with deterministic fixtures and negative
cases. At minimum:

- **Runtime/package smoke test:** import and execute the exact pinned Sigstore
  and TUF packages in the deployed Workers runtime, not just Node.js.
- **Golden release test:** verify a genuine repository-produced attestation
  for both ZIP and manifest, checking all policy claims and exact digests.
- **TUF tests:** valid root rotation; restart/eviction persistence; expired root;
  invalid next-root threshold/signature; stale metadata; failed refresh must
  preserve last trusted root.
- **Policy tests:** wrong repository ID, workflow path/ref, builder, event,
  source commit, tag target, subject name/digest, and installed-version
  rollback all reject.
- **State tests:** concurrent runs serialize; compare-and-advance is atomic;
  crash between verification and commit leaves the old pin; same-version
  artifact replacement and older version reject.
- **Origin tests:** redirect, wrong host, missing/weak security headers,
  public asset tamper, manifest tamper and VERSION mismatch reject.
- **Private-host tests:** invalid signature, wrong collector key, wrong node
  identity, stale nonce, replay, changed file/config digest and unavailable
  collector reject.
- **Node 4 tests:** challenge digest binding, report signature/identity,
  acknowledgement failure and replay behavior.
- **Alert tests:** every failure class attempts direct owner alert; transport
  failure is surfaced; no path relies solely on Node 4.
- **Schedule/operations tests:** scheduled invocation, overlapping invocation,
  missed/failed invocation detection, deployment/restart and recovery.

Run the same golden and adversarial fixtures against the PHP reference
implementation and Worker implementation; compare accepted/rejected outcomes
to detect policy drift. A Node.js unit test alone is not runtime acceptance.

## 7. Cloudflare-specific operational gates

Before production acceptance, record and verify:

- Worker name, account/project, production environment and deployment version;
- whether the account has Workers Paid and Cloudflare Containers entitlement if
  Option A is selected; container instance type, vCPU/memory/disk sizing,
  network egress and measured cold-start/runtime behavior;
- account administrative access and separation from Node B and production-host
  administration;
- Durable Object class/namespace and SQLite storage binding;
- Cron Trigger schedule and evidence of successful scheduled invocations;
- secret names/bindings and rotation procedure (never record secret values);
- configured Worker and (if used) Container CPU/memory/request limits and
  measured worst-case verification cost for the actual release artifact size;
- confirmation that container disk is treated as ephemeral; any state needed
  after sleep/restart is committed to the Durable Object before success;
- bounded fetch/response sizes and request/subrequest counts;
- independent direct alert destination and successful delivery evidence;
- Worker deployment rollback procedure that does not roll back durable trust
  state or permit release rollback;
- monitored error/cron telemetry with no secrets, tokens, report payloads or
  sensitive private-host data in logs.

A Cron Trigger is a scheduler, not an independent trust anchor. Node A must
remain operationally independent of Node B and Node 4.

## 8. Current status and explicit non-claims

- Cloudflare Workers is the confirmed Node A platform.
- Existing PHP Node A code and tests define the reference behavior, but are
  not directly deployable as a plain Worker. Cloudflare Containers may allow
  the PHP runtime to be packaged under the Workers platform, subject to paid
  plan entitlement and a proven durable-state/TUF adapter.
- The first implementation task is a bounded A/B proof of concept: run the
  exact PHP dependency set inside a Cloudflare Container and, independently,
  run the maintained Sigstore JS/TUF stack in a plain Worker. Compare actual
  compatibility, state durability, resource cost and golden attestation
  results before committing to either implementation.
- No Worker implementation, account binding, Durable Object, Cron Trigger,
  secret, TUF adapter, alert integration or production deployment is claimed
  by this document.
- Node A remains **not deployed / not accepted** until the runtime, golden
  attestation, state durability, independent alerting and end-to-end scheduled
  report gates above pass.

## References

- [Cloudflare Workers Node.js compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/)
- [Cloudflare Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Cloudflare Containers overview and Workers integration](https://developers.cloudflare.com/containers/)
- [Cloudflare Containers FAQ (ephemeral disk and lifecycle)](https://developers.cloudflare.com/containers/faq/)
- [Cloudflare Durable Objects SQLite storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
- [Cloudflare Durable Objects limits](https://developers.cloudflare.com/durable-objects/platform/limits/)
- [Cloudflare Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
- [Sigstore JavaScript client](https://github.com/sigstore/sigstore-js)
- [Sigstore JavaScript client documentation](https://docs.sigstore.dev/language_clients/javascript/)


### Initial Cloudflare workerd proof-of-concept results (2026-11-21)

A dedicated, non-deploying workerd test harness has now established the following:

- The pinned `@sigstore/verify@4.1.3` package imports in workerd and executes Ed25519 verification and SHA-256 operations.
- An upstream Sigstore Rekor v2 certificate bundle and its upstream trusted-root fixture verify successfully inside workerd. This is a genuine verifier-path test, but it is not yet a SentryIQ release bundle and does not exercise our repository-specific release policy.
- A SQLite-backed Durable Object proof implements immutable baseline initialization, monotonic release-pin compare-and-advance, same-version digest replacement rejection, downgrade rejection, durable run locking, and audit retention. The tests exercise persistence across separate Durable Object stubs.
- The separate Durable Object filesystem prototype stages file writes, supports rollback/discard, and commits successful writes inside a SQLite storage transaction. It is **not wired into** the upstream TUF client.
- The stock `@sigstore/tuf@5.0.1` client can bootstrap and read its root cache under writable `/tmp`, but a persistent cache path outside `/tmp` fails with the Workers filesystem permission restriction (`operation not permitted`). The `/tmp` cache is ephemeral and is not a durable trust store. The workerd test stops at an expected loopback network failure; it does not claim a successful live TUF refresh.

**Current conclusion:** verifier feasibility is demonstrated at the upstream fixture level. Stock TUF can only use its ephemeral `/tmp` cache and is not yet backed by Durable Object storage. A reviewed adapter wired into the TUF verification path (or a maintained Worker-compatible alternative), genuine SentryIQ release-bundle verification, repository policy parity, and full adversarial/runtime acceptance remain mandatory. No Worker deployment, account binding, secret, Cron Trigger, production route, or production release has been created.
