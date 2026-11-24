# Node A — Execution Runbook (Atomic Steps)

**Scope:** Phase 2 operational completion of Node A: Cloudflare Workers security monitoring and asynchronous TUF updater.

**Baseline already accepted for this runbook:** Phase 1 is complete (30/30). PR #145 is merged to `feat/node-a-monotonic-run-fence`; PRs #146 and #147 are merged to `main`. The Node A lockfile and the associated CI evidence have already been checked. These are CLOSED. Do not repeat them unless a new change invalidates that evidence.

## Operating contract — written for reliable execution

This is not a suggestion to provide status updates. It is the procedure to execute.

1. **Maintain one source of truth:** this file. Update its checkboxes and evidence links as work happens. Do not create another plan, checklist, or parallel task list.
2. **Resume from the first unchecked atomic item.** Read this file and the relevant source files only as needed for that item. Never restart at the beginning because a new message arrived.
3. **One atomic item means one bounded operation and one observable result.** Examples: fetch one config file; inspect one binding; run one targeted test; make one focused code change.
4. **After each operation:** record the result in this file, including the exact path/commit/test output or the exact blocker. Then proceed to the next unchecked item without asking the owner to say “continue”.
5. **Do not report an action as complete because it was planned, attempted, or described.** Complete means the evidence exists and has been checked.
6. **No progress theatre:** no repeated PR/lockfile/CI summaries, no paraphrased status messages, no invented subtasks, no claiming background work. Only report a meaningful completed artifact/result or a genuine blocker.
7. **Use available tools before asking the owner.** Inspect repository/configuration and discover connected integrations first. Ask for access only after identifying the exact missing permission or capability.
8. **Keep work moving within authorization.** Read-only inspection, local code changes, tests, documentation, and non-production preparation may proceed under the existing project authorization. Do not perform production-impacting actions without explicit approval.
9. **Never request secrets in chat.** Use an authorized secret manager or ask the owner to provision the named secret through the approved channel.
10. **If blocked:** mark the exact atomic item BLOCKED, state what is missing and why, and continue with later independent repository-only items where safe. Do not silently skip dependencies or pretend a blocked external action is done.
11. **No unapproved production deployment, production secret provisioning, release publication, baseline initialization, destructive change, or irreversible account mutation.**
12. **At a turn boundary:** leave this file with the precise next unchecked item and its dependency. On the next turn, resume there. Do not make the user reconstruct context.

## Status key
- [ ] Not done
- [x] Done — evidence recorded
- [!] Blocked — exact blocker recorded

## A. Repository configuration inventory

### A1. Identify configuration files
- [ ] A1.1 List files under `cloudflare/node-a-poc` relevant to Worker configuration, deployment, migrations, and runtime.
- [ ] A1.2 Read the Wrangler configuration and record entry point, compatibility date/flags, environments, routes, vars, bindings, and cron triggers.
- [ ] A1.3 Read the Worker entry point(s) and record exported handlers and route dispatch.
- [ ] A1.4 Read Durable Object classes and record class names, storage use, and expected bindings.
- [ ] A1.5 Read migration declarations and map each migration to its Durable Object class.
- [ ] A1.6 Find every R2 binding/reference and record the expected binding name and purpose.
- [ ] A1.7 Find every environment variable and secret binding name; record names only, never values.
- [ ] A1.8 Find all external service URLs and record endpoint, caller, and purpose.
- [ ] A1.9 Find cron/scheduled handler logic and record expected cadence and safety controls.
- [ ] A1.10 Consolidate A1.2–A1.9 into a source-backed configuration inventory. Mark A complete only when every item has a file/line reference.

## B. Deployment topology and gap analysis
- [ ] B1.1 Extract the intended deployment topology from existing project documentation and code. Do not invent account resource names.
- [ ] B1.2 Compare each required binding with Wrangler configuration.
- [ ] B1.3 Compare each Durable Object class with its migration and binding.
- [ ] B1.4 Compare each R2 use with the configured bucket binding and documented bucket name.
- [ ] B1.5 Compare routes, environments, and cron triggers with the intended topology.
- [ ] B1.6 Produce a delta table: configured correctly / missing / inconsistent / not yet knowable.
- [ ] B1.7 Mark which gaps can be fixed in repository code and which require account access. Record exact evidence.

## C. Cloudflare access and non-production preparation
- [ ] C1.1 Discover whether an authorized Cloudflare connector/action is available. Do not assume access.
- [ ] C1.2 If available, perform read-only inspection of the intended account and non-production resources.
- [ ] C1.3 Compare actual resource state against Section B; record IDs/names and environment, not secrets.
- [ ] C1.4 If access is unavailable, mark only account-inspection items BLOCKED and specify the exact role/permission or owner action required.
- [ ] C1.5 Prepare a non-production-only change set for missing R2/DO/Worker resources and migrations.
- [ ] C1.6 Review the change set for accidental production targets, destructive operations, or secret exposure.
- [ ] C1.7 Obtain explicit owner approval before applying account mutations if that approval is not already explicit.
- [ ] C1.8 Apply approved non-production changes only; capture command/action results and resource identifiers.
- [ ] C1.9 Run non-production configuration validation and record exact output.

## D. Private-host attestation feasibility and implementation
- [ ] D1.1 Inspect the existing private-host collector, attestation handler, nonce store, and PHP-FPM entry point in the repository.
- [ ] D1.2 Trace the Worker request contract and expected response/signature fields from source.
- [ ] D1.3 Record host requirements: separate OS identity, key outside docroot, restrictive permissions, isolated nonce storage, private socket/loopback, controlled HTTPS reverse proxy.
- [ ] D1.4 Determine which host capabilities are evidenced by existing access and which remain unknown. Do not infer cPanel capabilities.
- [ ] D1.5 If host access is available, perform read-only capability checks; otherwise record exact access needed.
- [ ] D1.6 Make a documented go/no-go decision. If process/key isolation is impossible, do not deploy this design; prepare an alternative-host/design decision for the owner.
- [ ] D1.7 Only after feasibility passes and required approval exists, implement service configuration under a distinct OS identity.
- [ ] D1.8 Verify key and nonce-store ownership/permissions and prove public PHP-FPM identity cannot read the signing key.
- [ ] D1.9 Verify private endpoint exposure is restricted to the intended HTTPS path and no public PHP route exposes key operations.
- [ ] D1.10 Run valid-signature, invalid-signature, nonce-replay, and service-unavailable tests; save results with secrets redacted.

## E. Worker attestation integration
- [ ] E1.1 Compare Worker request/response handling against the private service contract; list any mismatches.
- [ ] E1.2 Fix contract mismatches in repository code and add focused tests.
- [ ] E1.3 Configure the non-production endpoint using the approved configuration channel.
- [ ] E1.4 Confirm required secret names and consumers; do not copy secret values into code, logs, or this file.
- [ ] E1.5 Run a non-production challenge request and capture correlation IDs.
- [ ] E1.6 Run report and acknowledgement flow; verify the expected state transition.
- [ ] E1.7 Verify invalid signature and replay are rejected without advancing the release pin.
- [ ] E1.8 Verify unavailable attestation service fails closed and emits the expected alert/event.

## F. Node 4 integration
- [ ] F1.1 Locate and inspect the Node 4 API contract and current Node A client implementation.
- [ ] F1.2 Record required public-key registration fields and event API credential scope.
- [ ] F1.3 Identify the authorized channel for registering the Ed25519 public key and provisioning the least-privilege credential.
- [ ] F1.4 Register/provision only after owner authorization; never request credential values in chat.
- [ ] F1.5 Execute a real non-production challenge/report/acknowledgement exchange.
- [ ] F1.6 Verify Node 4 accepts a valid report and returns a correlated acknowledgement.
- [ ] F1.7 Verify invalid, stale, and replayed reports are rejected and do not advance the release pin.
- [ ] F1.8 Save request IDs, response outcomes, and redacted evidence.

## G. Independent alert delivery
- [ ] G1.1 Identify the configured alert adapter and supported destinations from source.
- [ ] G1.2 Identify the independently controlled destination and its authorized credential channel.
- [ ] G1.3 Configure non-production delivery after authorization.
- [ ] G1.4 Trigger one controlled success notification and verify receipt.
- [ ] G1.5 Trigger one controlled failure notification and verify receipt.
- [ ] G1.6 Confirm alert credentials are independent from host and Node 4 credentials; record evidence without values.

## H. Manifest-bearing release candidate (prepare, do not publish)
- [ ] H1.1 Inspect existing release packaging and manifest-generation implementation.
- [ ] H1.2 Identify the exact manifest schema and required fields from repository source/specification.
- [ ] H1.3 Build the candidate artifact (target v0.1.3 only if supported by the existing version plan).
- [ ] H1.4 Generate ZIP, manifest, checksums, and attestations locally/in CI without publishing.
- [ ] H1.5 Validate manifest schema and artifact file inventory.
- [ ] H1.6 Independently recompute checksums and compare them with the manifest.
- [ ] H1.7 Verify signatures, attestation chain, root metadata, and origin constraints.
- [ ] H1.8 Record candidate identifiers and validation results; request owner review before publication.

## I. Non-production end-to-end and resilience acceptance
- [ ] I1.1 Test normal update and successful acknowledgement.
- [ ] I1.2 Test interrupted/partial download and safe recovery.
- [ ] I1.3 Test R2 unavailable and verify fail-safe behavior.
- [ ] I1.4 Test Durable Object concurrency/fencing and stale-run rejection.
- [ ] I1.5 Test invalid attestation and nonce replay.
- [ ] I1.6 Test Node 4 acknowledgement failure and verify no unsafe release-pin advance.
- [ ] I1.7 Test alert destination unavailable and record fallback behavior.
- [ ] I1.8 Test rollback/recovery from a failed candidate.
- [ ] I1.9 Consolidate test evidence, expected vs actual outcomes, and unresolved defects.

## J. Production authorization, deployment, and acceptance
- [ ] J1.1 Produce exact production change list, resource targets, secrets required (names only), risk, and rollback plan.
- [ ] J1.2 Present non-production evidence and production change list for explicit owner approval.
- [ ] J1.3 Confirm approval is explicit and covers the exact production actions; general project authorization is not sufficient.
- [ ] J1.4 Deploy only the approved change set and capture deployment identifiers.
- [ ] J1.5 Run production health checks and verify monitoring, update integrity, alerting, Node 4 acceptance, and rollback readiness.
- [ ] J1.6 Obtain explicit approval before immutable baseline initialization.
- [ ] J1.7 Initialize baseline and capture its identifier and integrity evidence.
- [ ] J1.8 Produce final acceptance report with pass/fail evidence, remaining risks, rollback status, and owner sign-off.

## Current cursor

**Next item: A1.1 — list the relevant files under `cloudflare/node-a-poc`.**

No other item is active. Do not re-check PR #145/#146/#147, the lockfile, or the already-passing CI suite as a substitute for A1.1.