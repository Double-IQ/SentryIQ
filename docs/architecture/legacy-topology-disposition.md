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



## Second-pass verifier, test and release-pipeline trace (2026-11-24)

### Concrete Node C reuse boundary

The direct source review confirms that Node C is the closest existing verifier base, but its identity is embedded throughout the implementation and must be deliberately migrated rather than renamed at deployment time:

- `IntegrityNodeC` rejects any report signer whose identity is not exactly `integrity-c`; its direct alert callback is mandatory; its origin-header verifier is mandatory; it verifies both manifest and exact ZIP provenance before trusting manifest contents; it hashes selected public HTTP assets and signs a schema-v2 report.
- The verifier itself does not call Node 4. It creates a local 32-byte random nonce in the scheduled runner path. Some comments still describe the nonce as an “event-plane” nonce, which is stale terminology and should be corrected during adaptation.
- The report schema and evidence store are also explicitly Node-C-bound. `IntegrityNodeEvidenceStore` requires `node_id=integrity-c`, uses a Node-C-specific directory name, and verifies the corresponding public key. Do not reuse the old identity or old key material.
- `IntegrityNodeVerifierBinding` requires all three A/B/C classes and accepts only the matching A/B/C identities. The scheduled runner likewise accepts only those three IDs, requires A/B to use the Node 4 event exchange, and requires C to use local evidence storage without Node 4.
- `IntegrityNodeScheduledRunner` is therefore not yet a single-verifier runtime. Its lock, staging, digest re-check, anti-rollback and evidence append flow are useful candidates, but the constructor and execution branches need an explicit one-verifier design and tests.

### Test coverage and what it proves

- `tests/integrity_node_c.test.php` tests Node C with injected synthetic attestation/fetch/header callbacks. It exercises signature report shape, public asset match/mismatch, direct alert invocation, unsafe paths, and attestation failure handling. It does not prove the production Sigstore verifier, HelioHost runtime, real alert channel, or host isolation.
- `tests/integrity_node_scheduled_runner.test.php` constructs a Node C runner and checks constructor policy. Its own comment says the runner is intentionally not executed because network access is excluded from the unit test. It also verifies that the A path cannot start without the retired Node 4 exchange.
- `tests/integrity_node_cli_bootstrap.test.php` verifies private config location/mode and required class preloading. Its fixture currently asserts that private-host A/B classes are preloaded, a dependency that should be removed from the new one-verifier bootstrap.
- The current integrity-node workflows explicitly lint and execute A/B/C, private-host collector/gate/client, Node 4 event, and old scheduled-runner tests. They must be replaced with tests for the new identity, report schema, offline phone verification, direct alert path, release-state bootstrap, and the production runtime before old tests are deleted.
- At this audit point, all five PR #151 checks on head `f32c34c0f8bb058ba8710e43122995b8c022f0ae` completed successfully: PHP Syntax Check, Integrity Node Tests, Native Sigstore Integrity Node Tests, Release Manifest Tests, and Gallery Security Checks. These are checks for the documentation branch's current head, not a production deployment or a test of a future HelioHost installation.

### Release provenance and build trust

- `.github/workflows/release.yml` is tag-triggered, checks that the tag and VERSION match, builds a canonical package/inventory, validates the package, obtains GitHub build-provenance attestations for both ZIP and manifest, and publishes the release. It grants contents-write, id-token-write and attestations-write permissions to the release job.
- The release workflow is potentially reusable as the package/provenance source. Its permissions and tag protection are security-critical and must not be broadened or weakened as part of verifier simplification.
- `.github/workflows/release-manifest-tests.yml` independently builds and validates the package on pull requests and main pushes. Keep this generic release assurance.
- `.github/workflows/native-release-attestation.yml` is a separate native PHP release-verifier regression path; inspect its full command list and path filters before deciding which parts remain necessary.
- The repository tree has no tracked `composer.json` at the root and no Composer autoload manifest was found in the inspected tree. Current PHP runtime wiring uses explicit `require_once` statements in the CLI entrypoint and private configuration. This means class-load dependencies must be traced through explicit includes and private config rather than assuming Composer autoload resolves them.

### Runtime dependency boundary confirmed so far

- `index.php` loads `security_bootstrap.php`, private application config, vault engine, auth flow and dashboard components; no direct reference to the old integrity node, scheduled runner, Node 4 or event endpoint appears in the inspected entrypoint.
- `app/Security/SecurityBootstrap.php` is application session/security bootstrap logic and does not construct the old integrity verifier services in the inspected source.
- `bin/integrity-node-run.php` is a CLI-only entrypoint. It explicitly preloads A/B/C, Node 4 event client/runner, private-host attestation classes, Sigstore/release trust, evidence and release-state classes before requiring the private runtime config. It enforces a mode-0700 private data directory, mode-0600 config, and config placement outside the public webroot.
- This confirms separation from the inspected web request path only. It does not establish whether the live hosting scheduler invokes the CLI or whether an external service calls `integrity_event.php`. Those remain live-host operational dependencies and must be checked before retiring entrypoints.

### Adaptation sequence (not yet authorized for production)

1. Specify a new verifier identity and versioned phone-verifiable report contract; generate a new key only after HelioHost isolation and key custody are qualified.
2. Refactor the Node C verifier identity, evidence store, report verifier, CLI configuration and scheduled runner as one coherent change. Remove A/B/Node 4 branches only after replacement tests exist.
3. Add a real execution integration test around a local fixture origin and test double attestation verifier; retain a separate production Sigstore integration test.
4. Test phone-side verification of signed reports, expiry, nonce replay, target origin, manifest/artifact digests, and device authorization/recovery.
5. Preserve the generic release package and provenance workflows. Narrow or replace the old integrity-node workflows only after the replacement test suite passes.
6. Confirm live cron entries, external event endpoint callers, and deployment hooks before removing old scripts or endpoint code.
7. Keep deployment, baseline initialization, private-key generation, and release publication as separately approved operations.


## Third-pass endpoint, public inventory and runtime policy findings (2026-11-24)

### Node 4 endpoint and live app coupling

- `integrity_event.php` is a dedicated POST-only HTTPS JSON endpoint. It loads `IntegrityNode4RuntimeConfig`, requires the canonical SentryIQ host, and authenticates the former A/B node tokens and signed reports. It is not included by the inspected normal `index.php`, `update.php`, `update_apply.php`, or `update_check.php` paths.
- `IntegrityNode4RuntimeConfig` loads the public `sentryiq_config.php` pointer and then the private configuration from the data directory. When enabled, it requires the exact A/B identities, tokens and public keys. The endpoint and its private config schema are therefore old-topology-specific.
- The endpoint is a direct public PHP entrypoint, not an application front-controller route. Its continued existence is not proof it is used. No live request logs, hosting cron table, provider panel, external caller list, or private `sentryiq_config.php` was inspected. Before retirement, check those operational sources; do not expose or request secret values.
- The repository's `.htaccess` has explicit rewrite protection for private configuration and internal source directories, but no rule in the inspected file disables `integrity_event.php`. The endpoint itself enforces POST, HTTPS, canonical Host, content type, body size, bearer authentication and request schema. Retiring it requires checking external clients first.

### Public asset coverage limitation

- The release manifest builder inventories every packaged file and divides the inventory into `public_files` and `runtime_files`. The current format-2 builder does not emit a separate `public_http_files` list.
- `IntegrityPublicAssetPolicy` therefore falls back to selecting static assets from the signed `public_files` inventory. Node C can hash the expected static public paths and reject missing/unavailable or byte-mismatched responses.
- This HTTP strategy does not enumerate the live webroot. It cannot independently discover an unexpected extra file at an unknown path, and a configured subset can omit otherwise eligible assets. The architecture acceptance claim for detecting added public files needs a concrete mechanism (for example, an independently generated and protected deployed-path inventory or host-side read-only inventory), not just per-path HTTP hashing.
- Public HTTP hashes still do not verify private PHP source or runtime configuration. The current private-host collector runs on the application host and uses the retired A/B challenge model; it is not yet an approved isolated HelioHost-to-host measurement channel.

### Security-header policy consistency

- `.htaccess` sets `Referrer-Policy: strict-origin-when-cross-origin`, which matches `IntegrityOriginSecurityHeaderVerifier`'s expected policy.
- `app/Security/SecurityBootstrap.php` also sends `Referrer-Policy: no-referrer` from PHP for application requests. Depending on Apache/FPM header handling and the `Header always set` directive, the live response may expose one or conflicting duplicate values. The verifier probes `/VERSION`, not the PHP front-controller response, so this is not yet evidence of a live mismatch. Confirm the actual deployed response headers for both `/VERSION` and `/` before changing either policy.
- The architecture's header acceptance test should explicitly define whether it checks the static VERSION endpoint, the application HTML response, or both. Avoid weakening the stricter application policy merely to satisfy a monitor expectation.

### Dependency and runtime packaging notes

- No root `composer.json` or tracked Composer autoload file appears in the branch tree. The native Sigstore adapter can load a Composer autoloader supplied at a private path, and the normal application updater likewise accepts a private vendor autoload path. The HelioHost runtime will therefore need a reproducible, pinned dependency provisioning process outside the application release package, or a reviewed self-contained verifier build.
- Do not assume the app release ZIP contains the native Sigstore Composer dependencies. Keep those dependencies outside the public webroot and verify their exact versions, hashes/provenance and update policy independently.
- The normal update routes inspected do not invoke the retired Node 4/report verifier classes. The old report-verifier family is not automatically part of the app updater's active request path; still trace all remaining CLI, test, configuration and dynamic-reference dependencies before deletion.

### Open evidence items

1. Obtain a read-only confirmation of live application host cron entries and any external caller/monitor configuration for `integrity_event.php` and the old CLI scripts.
2. Probe actual response headers on `/VERSION` and `/` to resolve the Apache/PHP Referrer-Policy interaction.
3. Define a defensible mechanism for detecting unexpected added public files, and test it against the deployed webroot inventory.
4. Specify and pin the private HelioHost Sigstore verifier dependency bundle.
5. Keep PWA manifest/service-worker absence as a repository finding only; verify the live deployed origin before deciding whether PWA shell work is missing or externally generated.


## Fourth-pass device-authority and recovery trace (2026-11-24)

- The repository contains WebAuthn/passkey login and credential management (`app/Auth/PasskeyAuth.php`, `PasskeySetup.php`, `Passkeys.php`, `WebAuthnChallenge.php`). The passkey UI supports adding another passkey after fresh authentication and describes each credential as receiving a protected copy of the existing vault key.
- This is not yet the owner-approved master-phone device-authority model. The inspected global passkey flow does not establish a distinguished master-device role, require approval signed by that master for each new device, maintain a separate authorised-device registry/epoch, or provide a master-loss replacement ceremony.
- The repository also has Gallery-specific device inventory/removal and recovery tests. Those are scoped to Gallery credential envelopes and explicitly do not remove the global SentryIQ sign-in passkey; they must not be mistaken for global device authorisation.
- Existing vault recovery and Gallery recovery are distinct mechanisms. Neither, by itself, implements the requested offline authority for replacing a lost master phone while preserving device enrolment trust.
- Therefore the existing passkey system is useful authentication infrastructure, not proof that the new device-rooted security architecture is implemented. Phase 1 must design and test the global master-device role, device enrolment approvals, revocation, registry rollback protection, recovery authority, and the interaction with existing passkey-based vault unlock before modifying current passkey behaviour.
- No general PWA manifest, service-worker entrypoint, or offline app-shell asset appears in the tracked branch tree. The current app has mobile viewport and Apple touch icon tags, but those do not establish installable PWA behaviour. Verify the live deployment and externally generated assets before concluding the deployed app lacks them.
