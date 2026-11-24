# Legacy Topology and Component Disposition Inventory

**Status:** Initial pass — not exhaustive.  
**Target architecture:** SentryIQ at `https://sentryiq.bichet.co.za`; independent security verifier on HelioHost; owner's phone as master device.

This inventory prevents unsafe bulk deletion. A file is not removed merely because its former deployment topology is retired. Each component must be traced to callers, tests, workflows, and shared contracts first.

## Initial findings

| Area | Existing implementation / reference | Former assumption | Initial disposition |
|---|---|---|---|
| Cloudflare Worker | `cloudflare/node-a-poc/src/index.ts`, `wrangler.jsonc`, Worker runtime and tests | Node A runs as a Cloudflare Worker with Durable Objects, R2 and Cron | Retire as deployment target. Preserve source/tests temporarily; inspect for reusable monitor, TUF, fencing, and verification logic before deletion. |
| R2 target store | `cloudflare/node-a-poc/src/r2-tuf-target-store.ts` and TUF storage contract | Cloudflare R2 is target object storage | Cloudflare binding is obsolete. TUF metadata/target verification logic may be reusable only if the new app/update design still requires it. |
| Worker release asset client | `cloudflare/node-a-poc/src/release-assets.ts` | Worker polls the canonical application origin and GitHub release assets | Reusable concepts; current file hardcodes the correct canonical origin `https://sentryiq.bichet.co.za`. Review actual deployed asset verification design before adapting. |
| Worker private-host verifier client | `cloudflare/node-a-poc/src/private-host-attestation.ts` | Node A identifies as `integrity-a` and calls the application-host `/private-host-attestation` endpoint | Old A/B transport contract. Do not deploy unchanged. Extract schema, nonce, Ed25519 and freshness tests for reuse after redesign. |
| Worker Node 4 event client | `cloudflare/node-a-poc/src/node4-event-client.ts` | Node A sends a report to `/integrity_event.php` as `integrity-a` | Old topology-specific event plane. Review whether the new HelioHost verifier needs a minimal signed report/alert protocol; do not retain A identity or old dependency by default. |
| PHP private-host client | `app/Updates/PrivateHostAttestationClient.php` | Supports `integrity-a` and `integrity-b` bearer identities calling the application host | Old A/B client, not the new HelioHost verifier protocol. Preserve only if a reviewed reuse case remains. |
| PHP collector/handler/nonce store | `app/Updates/PrivateHostAttestationCollector.php`, `PrivateHostAttestationRequestHandler.php`, `PrivateHostAttestationNonceStore.php` | Application host exposes a collector for external A/B verifiers | Potentially reusable read-only inventory, nonce, and detached-signature primitives. Trust boundary must be redesigned: HelioHost should independently measure public delivery; private-file inspection requires a separately proven read-only isolation mechanism. |
| Node 4 endpoint | `integrity_event.php` and `app/Updates/IntegrityEvent*` | Node A/B challenge/report exchange | Existing endpoint may have other consumers. Do not delete until full repository-wide caller/config/test inventory is complete. |
| Private-host contract | `docs/security/private-host-attestation-contract.md` | A/B verifiers; HelioHost described as Node C | Replaced as active contract; historical copy retained at `private-host-attestation-contract-archive.md`. |
| Cloudflare runbooks | `cloudflare/node-a-poc/EXECUTION_PLAN.md`, `DEPLOYMENT.md`, `README.md` | Cloudflare deployment | Replaced with retirement notices; original content preserved in adjacent `*_ARCHIVE.md` files. |
| Candidate workflow PR | PR #150, `ci/node-a-candidate-build-dispatch` | Builds a candidate from old Node A feature branch | Closed without merging on 2026-11-24. It targeted the retired Cloudflare Node A source branch; generic package-build steps may be reused after review. |

## Canonical origin audit

The following inspected code already uses the correct origin `https://sentryiq.bichet.co.za`:
- `cloudflare/node-a-poc/src/release-assets.ts`
- `cloudflare/node-a-poc/src/private-host-attestation.ts`
- `cloudflare/node-a-poc/src/node4-event-client.ts`
- `app/Updates/PrivateHostAttestationClient.php`

The problem in those files is not the hostname; it is the former A/B/Cloudflare trust topology and protocol assumptions. Do not change the hostname blindly.

## Immediate constraints

- The new HelioHost verifier must not be implemented as a public endpoint on the SentryIQ application host.
- Public HTTP asset hashing does not prove integrity of private PHP files, server configuration, or the host OS.
- The verifier must not hold application write credentials, master-device keys, recovery material, or data-encryption keys.
- The application host must not be able to mint the verifier's signed reports or alter its pinned release policy.
- Existing PHP collector code is not automatically safe to run on HelioHost; first verify read-only access boundaries and provider capabilities.
- The PWA cannot self-attest to its own runtime. The phone must validate independently signed evidence, and residual browser/OS compromise risk must be addressed.

## Remaining inventory work

- Search all tracked files for Cloudflare product bindings, `workers.dev`, R2, Durable Objects, A/B/C node identifiers, Node 4 report coupling, old route names, and stale origin strings.
- Inspect package manifests, lockfiles, build scripts, release workflows, tests, docs, and configuration references before removing any code.
- Identify code used by the main PHP application or non-Node features.
- Review PR #150 and any open/merged release workflow dependencies.
- Produce a deletion/adaptation sequence with test coverage and rollback before source removal.


## Expanded code and architecture findings (main-tree inspection)

The repository tree contains 355 tracked paths on `main` and 360 on this documentation branch at the time of inspection. The main tree confirms that the former multi-node design is spread across application code, command-line runners, tests, CI workflows, ADRs, and deployment documentation.

### Node verifier implementations

| Component | Findings | New disposition |
|---|---|---|
| `IntegrityNodeA.php` | Read-only public-origin verifier; verifies release manifest and ZIP provenance, public static assets and origin headers; requires the A-bound private-host gate and direct alert transport; creates signed reports. | Do not deploy as-is. Reuse/test the public-asset and release-verification logic only after removing A identity, Node 4 coupling, and the old PHP collector trust model. |
| `IntegrityNodeB.php` | Substantially parallel to Node A, with its own `integrity-b` signing identity and independent gate/alert requirements. | No second node in target topology. Preserve only reusable shared logic/tests; avoid carrying duplicate B implementation into the new design. |
| `IntegrityNodeC.php` | Read-only public-origin verifier with release-artifact provenance, public asset and header checks, signed report generation, direct alerting, and no Node 4 event dependency. | Strongest existing starting point for a single HelioHost verifier, but not deployment-ready. Must adapt identity, trust bootstrap, private-file evidence boundary, master-phone trust integration, and recovery policy. |
| `IntegrityNodeScheduledRunner.php` | Generic scheduled execution, release-state locking/anti-rollback, artifact staging, verifier binding, and evidence persistence; currently accepts A/B/C identities and imposes different Node 4/evidence-store wiring rules. | Potentially reusable after simplifying to one verifier identity and eliminating Node 4/A-B branches; retain lock, anti-rollback and evidence semantics where tests support them. |
| `IntegrityNodeVerifierBinding.php` | Sealed binding only accepts concrete A/B/C classes. | Replace with a single verifier binding or remove if the new runtime can safely bind a concrete verifier directly. |
| `IntegrityReportSigner.php` / `IntegrityReportVerifier.php` | Detached Ed25519 report signing/verification primitives. | Reuse only with a new dedicated HelioHost verifier key, a versioned report schema, strict nonce/freshness checks, and no reuse of old node key material. |
| `IntegrityNodeEvidenceStore.php` | Node C evidence retention validates signed report envelopes and stores bounded local evidence with restrictive filesystem permissions. | Potentially reusable; review retention, append atomicity, permissions and evidence schema for the new verifier. |
| `IntegrityNodeReleaseStateStore.php` | Exclusive execution lock and monotonic release-state advancement to prevent overlapping checks and rollback. | Strong reusable primitive; retain and test against the single-node schedule and recovery model. |
| `NativeSigstoreIntegrityAttestationVerifier.php` | Uses native Sigstore/GitHub attestation verifier for manifest and ZIP, then applies release trust policy. | Reusable candidate; verify trust policy, workflow identity and keyless provenance assumptions remain appropriate. |
| `IntegrityDeployedReleaseResolver.php` | Resolves live `VERSION` from canonical origin and looks up corresponding GitHub tag commit. | Useful discovery helper but insufficient as trust authority alone; must be bound to signed manifest/provenance and anti-rollback. |

### Former private-host and Node 4 paths

- `PrivateHostAttestationGate.php` explicitly accepts only `integrity-a` or `integrity-b`, requires a node-bound collector client/key pin, and validates pinned file/config inventories. It cannot be carried forward unchanged.
- `PrivateHostAttestationClient.php`, `PrivateHostAttestationCollector.php`, `PrivateHostAttestationRequestHandler.php`, `PrivateHostAttestationNonceStore.php`, and `PrivateHostAttestationVerifier.php` implement the old A/B challenge/response contract. The PHP collector runs on the application host; this is not automatically an independent HelioHost inspection channel.
- `IntegrityNodeEventRunner.php`, `IntegrityEventClient.php`, `IntegrityNode4Monitor.php`, `IntegrityEventReportVerifier.php`, `FileIntegrityEventStore.php`, `IntegrityIncidentCorrelator.php`, and `integrity_event.php` implement the former Node 4/BTM-SA report and incident plane. The single-node target does not require a Node 4 service by default. Review whether any event/alert functionality is used by the application outside this retired monitoring topology before removal.
- `IntegrityNodeKeyGenerator.php` and `bin/integrity-node-keygen.php` support old node-specific keys. Do not reuse existing A/B/C private keys as the new HelioHost key. The new verifier signing key must be generated only after its custody boundary and host isolation are qualified.

### Workflow and CI dependencies

- `.github/workflows/integrity-node-tests.yml` and `.github/workflows/native-sigstore-integrity-node.yml` explicitly enumerate former A/B/C, collector, Node 4, and Node C test suites. They are active CI dependencies until replaced by architecture-aligned coverage.
- `.github/workflows/release.yml`, `native-release-attestation.yml`, `release-manifest-tests.yml`, `tuf-root-store.yml`, `tuf-patch-validation.yml`, and `validate-v012-attestation.yml` must be reviewed individually. Release artifact building, manifest generation, and provenance are potentially reusable; no workflow should be deleted solely because the node topology changed.
- Existing Node C documentation explicitly states that HelioHost is only an additional node and cannot replace A/B. That statement is now superseded; the old document is archived and replaced with a notice explaining Node C's potential reuse as the sole verifier base.

### Documentation status updated in this pass

The following old architecture documents have been archived and replaced by superseded notices on this branch:
- `docs/adr/2026-11-08-four-node-resilience-architecture.md`
- `docs/adr/2026-11-08-independent-integrity-nodes.md`
- `docs/security/integrity-node-c-heliohost.md`

The original text remains available in adjacent `*-archive.md` files. This is documentation retirement only; no implementation code or deployment was changed.

### Remaining proof required before code removal

The tree and selected call sites have been inspected, but this is not yet a complete call-graph audit. Before removing A/B/Node 4 code:
1. Search all PHP bootstrap, route, CLI, scheduler, config, tests, docs, and workflow references to each class and endpoint.
2. Identify whether the app's runtime invokes any Node 4 monitor, event client, private-host handler, or scheduled runner.
3. Check composer/autoload and PHP include patterns, including dynamic class references.
4. Confirm the new single verifier's minimal runtime can use the generic report, evidence, release-state, asset-policy and Sigstore primitives without pulling old topology dependencies.
5. Replace CI workflow path filters and test commands before deleting old tests.
6. Delete only in a separate reviewed PR after replacement tests pass and rollback is documented.


## Runtime entrypoint and call-site trace (focused)

The following entrypoints were inspected directly:

- `index.php` loads the application security bootstrap, private application config, vault engine, auth flow and UI. It contains no direct reference to Integrity Node A/B/C, Node 4, the private-host attestation collector, or the integrity event endpoint.
- `app/Security/SecurityBootstrap.php` loads application security and vault infrastructure. The inspected file contains no direct construction/reference of the old integrity-node classes or Node 4 services.
- `bin/integrity-node-run.php` is the explicit CLI entrypoint for the old scheduled verifier. It loads A/B/C classes, Node 4 event runner, private-host A/B gate, Sigstore verifier, evidence store and release-state store; its private configuration must return an `IntegrityNodeScheduledRunner`.
- `bin/integrity-node4-monitor.php` is a separate CLI entrypoint for the Node 4 event monitor and loads the old Node 4 runtime configuration, event store, correlator and alert dispatcher.
- `bin/integrity-node-baseline.php` initialises monotonic release state using a private config and release-state store.
- `bin/integrity-node-keygen.php` generates node-specific signing keys.
- `integrity_event.php` is a dedicated public HTTP endpoint for the old Node 4 challenge/report protocol. It requires private runtime configuration and validates A/B identities and keys.

### What this establishes — and what it does not

- The old monitoring runtime is separated from the normal `index.php` request path in the inspected entrypoints; it is invoked through explicit CLI scripts and a dedicated event endpoint.
- This focused trace did not inspect every dynamic include, external cron definition, hosting control-panel schedule, private runtime configuration, or deployment hook. Therefore it does not prove that the live host is not scheduling these scripts.
- The repository does not contain the owner's private `sentryiq_config.php` or live hosting scheduler state. No credentials or private config values were accessed.
- Before removing the Node 4 endpoint or CLI scripts, confirm whether the live HelioHost/application host has cron entries, direct URLs, monitoring integrations, or operational procedures that call them.
- The existing private-host collector is on the application host. It is not proof of independent HelioHost-side filesystem access and must not be presented as such.

### Current retirement recommendation

1. Keep old A/B/C and Node 4 code quarantined from new production wiring while Phase 0.5 completes.
2. Use Node C as the leading single-verifier prototype candidate, subject to full review of its verifier bootstrap and evidence schema.
3. Extract or reuse generic signed-report, public-asset-policy, release-state-locking, evidence-retention, and native Sigstore verification primitives where appropriate.
4. Design a new HelioHost-to-phone verification protocol; do not reuse the old Node 4 challenge/report endpoint by default.
5. Design private PHP/config integrity separately. If the application host cannot provide a safely isolated read-only collector, report that limitation explicitly rather than claiming full server-side verification.
6. Keep `integrity_event.php`, Node 4 classes, A/B private-host gate, and old CLI scripts until live scheduler and external caller dependencies are confirmed absent and replacement tests are in place.
