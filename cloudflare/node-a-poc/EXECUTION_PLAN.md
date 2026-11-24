# Node A — Execution Runbook (Atomic Steps)

**Scope:** Phase 2 operational completion of Node A: Cloudflare Workers security monitoring and asynchronous TUF updater.

**Accepted baseline:** Phase 1 complete (30/30). PR #145 merged to `feat/node-a-monotonic-run-fence`; PRs #146/#147 merged to `main`. Lockfile and existing CI evidence are closed baseline items. Do not repeat unless a new change invalidates them.

## Execution contract
1. This file is the sole plan and status source. No parallel checklists.
2. Resume at the first unchecked atomic item. Never restart because a new message arrived.
3. Each item is one bounded operation with observable evidence.
4. Record evidence here after each operation, then continue without asking the owner to say “continue”.
5. Attempted/planned/described is not complete. Complete means checked evidence exists.
6. No repeated PR/lockfile/CI summaries, paraphrased status, invented subtasks, or claims of background work.
7. Use available tools before asking the owner. Ask only for a specific missing permission/capability.
8. Continue safe repository/read-only work when external access is blocked.
9. Never request secrets in chat; use an approved secret channel.
10. Mark exact blockers and continue independent safe work.
11. No unapproved production deployment, production secret provisioning, release publication, baseline initialization, destructive change, or irreversible account mutation.
12. At turn boundaries, leave the exact next unchecked item here; resume there next time.

Status: [ ] not done | [x] done with evidence | [!] blocked with exact reason.

## A. Repository configuration inventory

### A1. Configuration extraction
- [x] A1.1 List relevant files. **Evidence:** GitHub directory listing of `cloudflare/node-a-poc` on `feat/node-a-monotonic-run-fence`: `wrangler.jsonc`, `src/`, `DEPLOYMENT.md`, `README.md`, `package.json`, `vitest.config.ts`, `scripts/`, `test/`, `docs/`.
- [x] A1.2 Read Wrangler config. **Evidence:** `wrangler.jsonc` blob `ddc494d07cd424521a6abcb481495d82073cbbc6`: Worker `sentryiq-node-a-poc`; entry `src/index.ts`; compatibility date `2026-11-21`; flag `nodejs_als`; observability disabled; R2 binding `NODE_A_TARGETS` → `sentryiq-node-a-targets`; DO binding `NODE_A_STATE` → `NodeAState`; migration `v1` adds SQLite class `NodeAState`; cron `*/15 * * * *`; no routes, vars, or named environments declared in this file.
- [x] A1.3 Read Worker entry point. **Evidence:** `src/index.ts` blob `8a86f14457138dd951321ba8c5dd8cc47446def5`: default export implements `scheduled` and `fetch`; `/health`, `/runtime-check`, authenticated internal monitor/baseline routes, and authenticated TUF refresh/target routes; unknown paths return 404.
- [x] A1.4 Identify Durable Object classes/storage. **Evidence:** `src/index.ts` defines `NodeAState extends DurableObject<Env>`; constructor creates SQLite tables for release baseline/pin, run lease/fence, TUF metadata/files/target pointers/staging/GC, and run audit.
- [x] A1.5 Map migrations to classes. **Evidence:** `wrangler.jsonc` migration `v1` declares `new_sqlite_classes: ["NodeAState"]`, matching the class exported from `src/index.ts`.
- [x] A1.6 Identify R2 binding/reference. **Evidence:** `wrangler.jsonc` binds `NODE_A_TARGETS` to bucket `sentryiq-node-a-targets`; `src/index.ts` declares `NODE_A_TARGETS: R2Bucket` and passes it to the async TUF updater.
- [x] A1.7 Identify environment/secret names. **Evidence:** `Env` in `src/index.ts` declares `NODE_A_API_TOKEN`, `TUF_ROOT_B64`, `TUF_METADATA_URL`, `TUF_TARGET_URL`, `NODE_A_GITHUB_TOKEN`, `NODE_A_EVENT_TOKEN`, `NODE_A_REPORT_PRIVATE_KEY_B64`, `NODE_A_PRIVATE_HOST_TOKEN`, `NODE_A_COLLECTOR_PUBLIC_KEY_B64`, `NODE_A_EXPECTED_FILES_JSON`, `NODE_A_EXPECTED_PRIVATE_CONFIG_JSON`, `NODE_A_ALERT_URL`, `NODE_A_ALERT_HOST`, `NODE_A_ALERT_TOKEN`, and `NODE_A_BASELINE_APPROVAL_TOKEN`. Values intentionally not inspected or recorded.
- [x] A1.8 Identify external service URLs and map caller/purpose. **Evidence:** `src/release-assets.ts` calls canonical origin `https://sentryiq.bichet.co.za/VERSION` and GitHub release assets under `https://github.com/Double-IQ/SentryIQ/releases/download/`; `src/private-host-attestation.ts` calls `https://sentryiq.bichet.co.za/private-host-attestation`; `src/node4-event-client.ts` calls `https://sentryiq.bichet.co.za/integrity_event.php`; `src/node-a-owner-alert.ts` uses operator-supplied independent HTTPS endpoint/hostname. `DEPLOYMENT.md` confirms the private-host route has no deployed listener/adapter and the alert provider is not selected/provisioned. **Documentation defect:** the same deployment doc still says PR #145 is draft/unmerged, contradicted by the verified GitHub merge record; correct this during documentation reconciliation, not by repeating PR checks.
- [x] A1.9 Identify cron handler/cadence. **Evidence:** Wrangler cron is every 15 minutes; `scheduled()` in `src/index.ts` checks for an initialized pin, records a minimal failed outcome and returns if absent, otherwise runs the release monitor and records outcome; uncaught failures invoke independent alert path.
- [ ] A1.10 Consolidate A1.2–A1.9 into a source-backed inventory with file/line references.

## B. Deployment topology and gap analysis
- [ ] B1.1 Extract intended topology from existing docs/code.
- [ ] B1.2 Compare required bindings with Wrangler configuration.
- [ ] B1.3 Compare Durable Object classes with migrations/bindings.
- [ ] B1.4 Compare R2 use with configured bucket and documented bucket name.
- [ ] B1.5 Compare routes, environments, and cron triggers with intended topology.
- [ ] B1.6 Produce configured/missing/inconsistent/unknown delta.
- [ ] B1.7 Separate repository-fixable gaps from account-access gaps.

## C. Cloudflare access and non-production preparation
- [ ] C1.1 Discover authorized Cloudflare connector/action.
- [ ] C1.2 If available, inspect account and non-production resources read-only.
- [ ] C1.3 Compare actual resource state with Section B; record identifiers/environment, never secrets.
- [ ] C1.4 If access unavailable, record exact required permission/owner action.
- [ ] C1.5 Prepare non-production-only change set.
- [ ] C1.6 Review for production targets, destructive operations, secret exposure.
- [ ] C1.7 Obtain explicit owner approval before account mutations unless specifically pre-authorized.
- [ ] C1.8 Apply approved non-production changes and capture identifiers/results.
- [ ] C1.9 Run non-production configuration validation.

## D. Private-host attestation feasibility and implementation
- [ ] D1.1 Inspect collector, handler, nonce store, PHP-FPM entry point.
- [ ] D1.2 Trace Worker request/response/signature contract.
- [ ] D1.3 Record host isolation requirements.
- [ ] D1.4 Distinguish evidenced capabilities from unknowns.
- [ ] D1.5 Perform read-only host checks if access exists; otherwise specify exact access.
- [ ] D1.6 Make go/no-go decision; do not deploy if key/process isolation cannot be guaranteed.
- [ ] D1.7 Only after feasibility and approval, implement isolated service.
- [ ] D1.8 Verify key/nonce ownership and public PHP identity cannot read key.
- [ ] D1.9 Verify endpoint exposure and absence of public key-operation route.
- [ ] D1.10 Test valid/invalid signature, replay, and service-unavailable paths.

## E. Worker attestation integration
- [ ] E1.1 Compare Worker contract to private service contract.
- [ ] E1.2 Fix mismatches and add focused tests.
- [ ] E1.3 Configure non-production endpoint through approved channel.
- [ ] E1.4 Confirm secret names/consumers; never record values.
- [ ] E1.5 Run non-production challenge request.
- [ ] E1.6 Run report/acknowledgement flow.
- [ ] E1.7 Verify invalid signature/replay cannot advance release pin.
- [ ] E1.8 Verify unavailable service fails closed and alerts.

## F. Node 4 integration
- [ ] F1.1 Inspect Node 4 API contract and Node A client.
- [ ] F1.2 Record public-key registration fields and credential scope.
- [ ] F1.3 Identify approved registration/credential channel.
- [ ] F1.4 Register/provision only after owner authorization.
- [ ] F1.5 Execute real non-production challenge/report/ack exchange.
- [ ] F1.6 Verify valid report and correlated acknowledgement.
- [ ] F1.7 Verify invalid/stale/replay reports rejected without pin advance.
- [ ] F1.8 Save redacted correlation evidence.

## G. Independent alert delivery
- [ ] G1.1 Identify alert adapter/destinations from source.
- [ ] G1.2 Identify independent destination and authorized credential channel.
- [ ] G1.3 Configure non-production delivery after authorization.
- [ ] G1.4 Trigger success notification and verify receipt.
- [ ] G1.5 Trigger failure notification and verify receipt.
- [ ] G1.6 Verify credential independence without recording values.

## H. Manifest-bearing release candidate (prepare, do not publish)
- [ ] H1.1 Inspect release packaging/manifest implementation.
- [ ] H1.2 Identify manifest schema and required fields.
- [ ] H1.3 Build candidate (v0.1.3 only if existing version plan supports it).
- [ ] H1.4 Generate ZIP, manifest, checksums, attestations without publishing.
- [ ] H1.5 Validate schema and artifact inventory.
- [ ] H1.6 Recompute checksums independently.
- [ ] H1.7 Verify signatures, attestation chain, root metadata, origin constraints.
- [ ] H1.8 Record candidate evidence and obtain owner review before publication.

## I. Non-production end-to-end and resilience acceptance
- [ ] I1.1 Normal update/acknowledgement.
- [ ] I1.2 Interrupted download/recovery.
- [ ] I1.3 R2 unavailable/fail-safe.
- [ ] I1.4 DO concurrency/fencing/stale-run rejection.
- [ ] I1.5 Invalid attestation/nonce replay.
- [ ] I1.6 Node 4 acknowledgement failure/no unsafe pin advance.
- [ ] I1.7 Alert destination unavailable/fallback.
- [ ] I1.8 Rollback/recovery.
- [ ] I1.9 Consolidated evidence and unresolved defects.

## J. Production authorization, deployment, and acceptance
- [ ] J1.1 Exact production change list, targets, secret names, risks, rollback.
- [ ] J1.2 Present non-production evidence for explicit owner approval.
- [ ] J1.3 Confirm approval covers exact actions.
- [ ] J1.4 Deploy only approved change set and record deployment IDs.
- [ ] J1.5 Production health/integrity/alert/Node 4/rollback checks.
- [ ] J1.6 Obtain explicit approval for immutable baseline.
- [ ] J1.7 Initialize baseline and record identifier/evidence.
- [ ] J1.8 Final acceptance report and owner sign-off.

## Current cursor
**Next item: A1.10 — consolidate the configuration inventory and evidence.**