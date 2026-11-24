# Node A — Small-Step Execution Plan

**Scope:** Phase 2 operational completion of Node A (Cloudflare Workers security monitoring and asynchronous TUF updater).

**Baseline:** Phase 1 is complete (30/30). PR #145 is merged to `feat/node-a-monotonic-run-fence`; PRs #146 and #147 are merged to `main`. The Node A lockfile and CI evidence have already been checked. Those checks are closed items and must not be repeated unless a later change directly invalidates them.

**Rule:** Work exactly one numbered step at a time. A step is complete only when its stated evidence exists. Then move to the next step without asking for permission to continue. Stop only at an explicit owner-approval or access gate. Never claim an account-side action occurred unless the account confirms it.

## Execution controls

- Keep this file as the sequence and status source of truth.
- Update a step's status and evidence when it is completed; do not create parallel checklists.
- Do not re-run completed PR, lockfile, or CI checks as progress.
- No production deployment, production secrets, release publication, baseline initialization, or irreversible account change without explicit owner approval.
- Prefer read-only inspection and non-production validation before any mutation.
- If blocked, record the exact missing permission, credential, endpoint, or owner decision. Do not substitute unrelated repository work.

## Ordered steps

### 1. Inventory the existing Node A Worker configuration
**Action:** Inspect the current Wrangler configuration, Worker entry points, Durable Object bindings/migrations, R2 references, cron triggers, environment variable names, and documented endpoints. Do not change account resources.

**Evidence required:** A concise inventory listing each required Cloudflare resource/binding, its configured name, and whether it is present in code/config.

**Status:** Not started.

### 2. Produce the Cloudflare resource delta
**Action:** Compare the inventory from Step 1 with the intended Node A deployment topology. Identify only resources that are missing or mismatched: R2 bucket, Durable Object namespace/migration, Worker environment, routes, and cron schedule.

**Evidence required:** Exact create/update/no-op list, with environment (development/staging/production) identified for each item.

**Status:** Not started.

### 3. Confirm Cloudflare access without changing production
**Action:** Use an authorized Cloudflare connection, if available, for read-only inspection of the target account and non-production environment. If no connection is available, identify the precise owner-provided access needed; do not ask for secrets in chat.

**Evidence required:** Account/environment access confirmed and actual resource state recorded, or a specific access blocker documented.

**Owner gate:** Account authorization is required if no authorized connection exists.

**Status:** Not started.

### 4. Prepare and validate non-production Cloudflare resources
**Action:** Create or correct only the approved non-production R2/DO/Worker resources and bindings. Apply migrations only to the non-production namespace.

**Evidence required:** Resource identifiers, successful migration result, and a non-production Worker configuration/build check. No secret values in logs or documentation.

**Owner gate:** Explicit approval before any account mutation if not already covered by an approved non-production authorization.

**Status:** Not started.

### 5. Establish private-host attestation feasibility
**Action:** Inspect the actual hosting capabilities for the private attestation service: process isolation, OS identities, filesystem permissions, private socket/loopback support, reverse-proxy control, and persistent nonce storage. Current known constraint: cPanel SSH access has not been established.

**Evidence required:** Host capability matrix with pass/fail/unknown for each requirement and a clear go/no-go decision.

**Owner gate:** Host-panel or provider access may be needed. Do not deploy a public PHP route or expose a signing key to the public PHP-FPM identity.

**Status:** Not started.

### 6. Implement the isolated attestation service
**Action:** Only after Step 5 passes, deploy the service under a distinct OS identity; keep signing key and nonce store outside the document root with restrictive permissions; expose only the exact HTTPS reverse-proxy path to the Worker.

**Evidence required:** Service health check, permission/identity evidence, nonce replay rejection test, valid signature test, and proof the public web identity cannot read the signing key.

**Owner gate:** If the existing host cannot provide isolation, stop and obtain approval for a separate host or a redesigned trust boundary.

**Status:** Not started.

### 7. Connect Worker to the attestation endpoint
**Action:** Configure the non-production Worker endpoint and required secret bindings, then exercise the challenge/report/acknowledgement path against the isolated service.

**Evidence required:** Successful end-to-end non-production exchange, plus negative tests for invalid signature, replay, and unavailable service. Never print credentials or private key material.

**Owner gate:** Owner-controlled secret provisioning is required if no authorized secret manager connection exists.

**Status:** Not started.

### 8. Integrate Node 4
**Action:** Register the Node A Ed25519 public key and provision the least-privilege event API credential through the approved secret channel. Exercise the real Node A → Node 4 challenge/report/acknowledgement flow.

**Evidence required:** Correlated request IDs and Node 4 acceptance record; invalid or stale reports are rejected and do not advance the release pin.

**Owner gate:** Node 4 access and credential authorization.

**Status:** Not started.

### 9. Verify independent alert delivery
**Action:** Configure the separately controlled alert destination and test one success and one failure notification from the non-production environment.

**Evidence required:** Delivery receipts at the destination and confirmation that alert credentials are separate from the monitored host/Node 4 credentials.

**Owner gate:** Alert destination authorization and credential provisioning.

**Status:** Not started.

### 10. Prepare the manifest-bearing release candidate
**Action:** Build the next release candidate (target v0.1.3 as previously identified) with the required manifest, ZIP, checksums, and attestations. Do not publish it.

**Evidence required:** Reproducible artifact inventory, manifest validation, checksum verification, signature/attestation verification, and origin/root validation.

**Owner gate:** Owner review of release contents before publication.

**Status:** Not started.

### 11. Run non-production end-to-end and fault-injection tests
**Action:** Exercise normal update, interrupted download, unavailable R2, Durable Object fencing/race, invalid attestation, replay, failed Node 4 acknowledgement, alert failure, and rollback/recovery paths.

**Evidence required:** Test report with inputs, expected result, actual result, logs stripped of secrets, and pass/fail for every scenario.

**Status:** Not started.

### 12. Request production authorization and deploy
**Action:** Present the complete non-production evidence and exact production change list to the owner. Deploy only after explicit approval. Do not infer approval from earlier general permission to work on the project.

**Evidence required:** Explicit approval record, deployment identifier, health checks, and rollback readiness.

**Owner gate:** Mandatory.

**Status:** Not started.

### 13. Initialize the immutable baseline and complete acceptance
**Action:** Initialize the production baseline only after successful deployment and explicit owner approval. Verify monitoring, update integrity, alerting, rollback, and Node 4 acceptance.

**Evidence required:** Baseline identifier, end-to-end acceptance report, unresolved-risk register, and owner sign-off.

**Owner gate:** Mandatory for baseline initialization and final acceptance.

**Status:** Not started.

## Current next action

**Only Step 1 is active:** inspect the existing Node A Worker configuration and produce the resource/binding inventory. Do not start Steps 2–13 until Step 1 has evidence. Do not repeat the already-completed PR, lockfile, or CI checks.
