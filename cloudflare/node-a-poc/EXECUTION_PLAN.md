# Node A — Execution Runbook (Atomic Steps)

**Scope:** Phase 2 operational completion of Node A: Cloudflare Workers security monitoring and asynchronous TUF updater.

**Baseline already accepted for this runbook:** Phase 1 is complete (30/30). PR #145 is merged to `feat/node-a-monotonic-run-fence`; PRs #146 and #147 are merged to `main`. The Node A lockfile and the associated CI evidence have already been checked. These are CLOSED. Do not repeat them unless a new change invalidates that evidence.

## Operating contract — written for reliable execution

This is the procedure to execute, not a request for status updates.

1. This file is the only plan and status source of truth. Do not create parallel checklists.
2. Resume at the first unchecked atomic item. Never restart because a new message arrived.
3. Each item is one bounded operation with one observable result.
4. After the operation, record evidence here, then proceed without asking the owner to say “continue”.
5. Complete means evidence exists and has been checked; intention or attempt is not completion.
6. No repeated PR/lockfile/CI summaries, paraphrased status messages, invented subtasks, or claims of background work.
7. Use available tools before asking the owner. Ask only for a specifically identified missing permission/capability.
8. Continue repository-only and read-only work when external access is blocked, provided dependencies allow it.
9. Never request secrets in chat. Use an authorized secret manager or owner-provisioned channel.
10. If blocked, mark the exact item BLOCKED, state the missing access/decision, and continue with independent safe items.
11. No unapproved production deployment, production secret provisioning, release publication, baseline initialization, destructive change, or irreversible account mutation.
12. At turn boundaries, leave the exact next unchecked item here. On resumption, continue there without making the owner reconstruct context.

## Status key
- [ ] Not done
- [x] Done — evidence recorded
- [!] Blocked — exact blocker recorded

## A. Repository configuration inventory

### A1. Identify configuration files
- [x] A1.1 List relevant files under `cloudflare/node-a-poc`. **Evidence:** GitHub directory listing on `feat/node-a-monotonic-run-fence` returned `wrangler.jsonc`, `src/`, `DEPLOYMENT.md`, `README.md`, `package.json`, `vitest.config.ts`, `scripts/`, `test/`, and `docs/`; lockfile files were present but are closed baseline items.
- [ ] A1.2 Read `wrangler.jsonc` and record entry point, compatibility date/flags, environments, routes, vars, bindings, and cron triggers.
- [ ] A1.3 Read Worker entry point(s) and record exported handlers and route dispatch.
- [ ] A1.4 Read Durable Object classes and record class names, storage use, and expected bindings.
- [ ] A1.5 Read migration declarations and map each migration to its Durable Object class.
- [ ] A1.6 Find every R2 binding/reference and record expected binding name and purpose.
- [ ] A1.7 Find every environment variable and secret binding name; record names only, never values.
- [ ] A1.8 Find external service URLs and record endpoint, caller, and purpose.
- [ ] A1.9 Find cron/scheduled handler logic and record cadence and safety controls.
- [ ] A1.10 Consolidate A1.2–A1.9 into a source-backed configuration inventory. Mark A complete only when every item has a file/line reference.

## B. Deployment topology and gap analysis
- [ ] B1.1 Extract intended deployment topology from existing project documentation and code. Do not invent account resource names.
- [ ] B1.2 Compare each required binding with Wrangler configuration.
- [ ] B1.3 Compare each Durable Object class with its migration and binding.
- [ ] B1.4 Compare each R2 use with configured bucket binding and documented bucket name.
- [ ] B1.5 Compare routes, environments, and cron triggers with intended topology.
- [ ] B1.6 Produce a delta table: configured correctly / missing / inconsistent / not yet knowable.
- [ ] B1.7 Separate repository-fixable gaps from account-access gaps and record evidence.

## C. Cloudflare access and non-production preparation
- [ ] C1.1 Discover whether an authorized Cloudflare connector/action is available.
- [ ] C1.2 If available, perform read-only inspection of intended account and non-production resources.
- [ ] C1.3 Compare actual resource state against Section B; record identifiers/names and environment, not secrets.
- [ ] C1.4 If access is unavailable, mark account-inspection items BLOCKED and specify exact permission/owner action required.
- [ ] C1.5 Prepare a non-production-only change set for missing R2/DO/Worker resources and migrations.
- [ ] C1.6 Review change set for production targets, destructive operations, and secret exposure.
- [ ] C1.7 Obtain explicit owner approval before account mutations unless already explicitly authorized.
- [ ] C1.8 Apply approved non-production changes only; capture results and resource identifiers.
- [ ] C1.9 Run non-production configuration validation and record exact output.

## D. Private-host attestation feasibility and implementation
- [ ] D1.1 Inspect existing private-host collector, attestation handler, nonce store, and PHP-FPM entry point in repository.
- [ ] D1.2 Trace Worker request contract and expected response/signature fields from source.
- [ ] D1.3 Record host requirements: separate OS identity, key outside docroot, restrictive permissions, isolated nonce storage, private socket/loopback, controlled HTTPS reverse proxy.
- [ ] D1.4 Determine which host capabilities are evidenced and which remain unknown. Do not infer cPanel capabilities.
- [ ] D1.5 Perform read-only host capability checks if access exists; otherwise record exact access needed.
- [ ] D1.6 Make a go/no-go decision. If isolation is impossible, do not deploy this design; prepare alternative-host/design decision for owner.
- [ ] D1.7 Only after feasibility and required approval, implement service under a distinct OS identity.
- [ ] D1.8 Verify key and nonce-store ownership/permissions and prove public PHP-FPM identity cannot read signing key.
- [ ] D1.9 Verify private endpoint exposure is restricted to intended HTTPS path; no public PHP route exposes key operations.
- [ ] D1.10 Run valid-signature, invalid-signature, nonce-replay, and service-unavailable tests; save redacted results.

## E. Worker attestation integration
- [ ] E1.1 Compare Worker request/response handling against private service contract; list mismatches.
- [ ] E1.2 Fix contract mismatches in repository code and add focused tests.
- [ ] E1.3 Configure non-production endpoint using approved configuration channel.
- [ ] E1.4 Confirm required secret names and consumers; never copy secret values into code, logs, or this file.
- [ ] E1.5 Run non-production challenge request and capture correlation IDs.
- [ ] E1.6 Run report and acknowledgement flow; verify expected state transition.
- [ ] E1.7 Verify invalid signature and replay are rejected without advancing release pin.
- [ ] E1.8 Verify unavailable attestation service fails closed and emits expected alert/event.

## F. Node 4 integration
- [ ] F1.1 Locate and inspect Node 4 API contract and current Node A client implementation.
- [ ] F1.2 Record required public-key registration fields and event API credential scope.
- [ ] F1.3 Identify authorized channel for registering Ed25519 public key and provisioning least-privilege credential.
- [ ] F1.4 Register/provision only after owner authorization; never request credential values in chat.
- [ ] F1.5 Execute real non-production challenge/report/acknowledgement exchange.
- [ ] F1.6 Verify Node 4 accepts valid report and returns correlated acknowledgement.
- [ ] F1.7 Verify invalid, stale, and replayed reports are rejected and do not advance release pin.
- [ ] F1.8 Save request IDs, outcomes, and redacted evidence.

## G. Independent alert delivery
- [ ] G1.1 Identify configured alert adapter and supported destinations from source.
- [ ] G1.2 Identify independently controlled destination and authorized credential channel.
- [ ] G1.3 Configure non-production delivery after authorization.
- [ ] G1.4 Trigger controlled success notification and verify receipt.
- [ ] G1.5 Trigger controlled failure notification and verify receipt.
- [ ] G1.6 Confirm alert credentials are independent from host and Node 4 credentials; record evidence without values.

## H. Manifest-bearing release candidate (prepare, do not publish)
- [ ] H1.1 Inspect existing release packaging and manifest-generation implementation.
- [ ] H1.2 Identify exact manifest schema and required fields from repository source/specification.
- [ ] H1.3 Build candidate artifact (target v0.1.3 only if supported by existing version plan).
- [ ] H1.4 Generate ZIP, manifest, checksums, and attestations locally/in CI without publishing.
- [ ] H1.5 Validate manifest schema and artifact inventory.
- [ ] H1.6 Independently recompute checksums and compare with manifest.
- [ ] H1.7 Verify signatures, attestation chain, root metadata, and origin constraints.
- [ ] H1.8 Record candidate identifiers/results; request owner review before publication.

## I. Non-production end-to-end and resilience acceptance
- [ ] I1.1 Test normal update and successful acknowledgement.
- [ ] I1.2 Test interrupted/partial download and safe recovery.
- [ ] I1.3 Test R2 unavailable and verify fail-safe behavior.
- [ ] I1.4 Test Durable Object concurrency/fencing and stale-run rejection.
- [ ] I1.5 Test invalid attestation and nonce replay.
- [ ] I1.6 Test Node 4 acknowledgement failure and verify no unsafe release-pin advance.
- [ ] I1.7 Test alert destination unavailable and record fallback behavior.
- [ ] I1.8 Test rollback/recovery from failed candidate.
- [ ] I1.9 Consolidate test evidence, expected vs actual outcomes, and unresolved defects.

## J. Production authorization, deployment, and acceptance
- [ ] J1.1 Produce exact production change list, resource targets, secret names, risk, and rollback plan.
- [ ] J1.2 Present non-production evidence and production change list for explicit owner approval.
- [ ] J1.3 Confirm approval covers exact production actions; general project authorization is insufficient.
- [ ] J1.4 Deploy only approved change set and capture deployment identifiers.
- [ ] J1.5 Run production health checks for monitoring, update integrity, alerting, Node 4 acceptance, and rollback readiness.
- [ ] J1.6 Obtain explicit approval before immutable baseline initialization.
- [ ] J1.7 Initialize baseline and capture identifier and integrity evidence.
- [ ] J1.8 Produce final acceptance report with pass/fail evidence, remaining risks, rollback status, and owner sign-off.

## Current cursor

**Next item: A1.2 — read `wrangler.jsonc` and extract the configured Worker settings.**

The only completed item in this runbook is A1.1, backed by the directory listing above. PRs #145/#146/#147, lockfile, and existing CI are closed baseline work and are not to be rechecked as progress.