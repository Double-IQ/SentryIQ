# Node A Cloudflare Worker deployment and acceptance

**This is an operational runbook, not evidence of a completed deployment.** PR #145 contains the Worker-native implementation and authenticated manual monitor/baseline routes. No production Cloudflare account, secrets, baseline, Cron trigger, or deployment has been provisioned. Keep the PR draft and do not deploy without explicit owner approval.

## Current control-plane behavior

The Worker exposes:

- `GET /health` — basic Worker health.
- `GET /runtime-check` — runtime/binding diagnostics; `productionReady` deliberately remains false until account-backed acceptance is complete.
- `POST /internal/tuf/refresh` — bearer-authenticated online TUF refresh.
- `GET /internal/tuf/targets/<URL-encoded-target-path>` — bearer-authenticated retrieval of a target matching the currently trusted TUF descriptor.
- `POST /internal/baseline/initialize` — one-time baseline initialization after the complete release, origin, private-host and Node 4 evidence flow succeeds. Requires both the normal API bearer token and a separate one-time approval header. The request has no body; the baseline candidate is derived from verified live release evidence, never from caller-supplied hashes.
- `POST /internal/monitor/run` — manual monitor execution after an immutable baseline exists. The release pin advances only after the signed Node 4 report is acknowledged.

There is **no Cron trigger or scheduled execution configured**. The monitoring cadence must be selected and approved by the owner before a Cron trigger is added. The baseline route is not a scheduled operation.

## Provisioning prerequisites

1. Confirm the intended Cloudflare account and that its administrative/failure boundary is independent of the SentryIQ application host.
2. Review `wrangler.jsonc`, the Durable Object binding `NODE_A_STATE`, and R2 binding `NODE_A_TARGETS`.
3. Authenticate Wrangler only after the account owner approves:
   ```sh
   npx wrangler login
   ```
4. Create the R2 bucket declared in `wrangler.jsonc`:
   ```sh
   npx wrangler r2 bucket create sentryiq-node-a-targets
   ```
5. Provision the secrets and pinned configuration below through Wrangler's secret/variable interface. Never commit them, place them in checked-in `.dev.vars`, or paste them into a PR/issue.

## Required Worker secrets

| Secret | Purpose and validation |
|---|---|
| `NODE_A_API_TOKEN` | 32–512-byte high-entropy bearer credential for internal Worker routes |
| `NODE_A_GITHUB_TOKEN` | Least-privilege read-only GitHub credential for SentryIQ release/tag and attestation evidence |
| `NODE_A_EVENT_TOKEN` | A-only Node 4 challenge/report API credential |
| `NODE_A_REPORT_PRIVATE_KEY_B64` | Canonical base64 of the Node A Ed25519 64-byte secret-key representation (32-byte seed + matching 32-byte public key); verify the public key against Node 4's registered Node A key |
| `NODE_A_PRIVATE_HOST_TOKEN` | A-only bearer credential for the private-host collector |
| `NODE_A_COLLECTOR_PUBLIC_KEY_B64` | Canonical base64 of the collector's pinned 32-byte Ed25519 public key |
| `NODE_A_ALERT_URL` | Exact HTTPS URL for the independent owner-alert webhook; no query or fragment |
| `NODE_A_ALERT_HOST` | Exact hostname for `NODE_A_ALERT_URL`; must match and must not be `sentryiq.bichet.co.za` or any `*.bichet.co.za` host |
| `NODE_A_ALERT_TOKEN` | 40–128-character URL-safe bearer credential for the independent webhook |
| `TUF_ROOT_B64` | Canonical base64 of the independently verified TUF bootstrap root metadata bytes |
| `TUF_METADATA_URL` | HTTPS TUF metadata mirror base URL, ending in `/` |
| `TUF_TARGET_URL` | HTTPS TUF target mirror base URL, ending in `/` |

The TUF root in `TUF_ROOT_B64` is the bootstrap root metadata used by the TUF updater. The Sigstore trusted root used for GitHub attestation verification is retrieved as the verified `trusted_root.json` TUF target after online refresh; do not substitute an unverified static file.

Example secret provisioning commands (run only in the approved Cloudflare account; Wrangler prompts for values):

```sh
npx wrangler secret put NODE_A_API_TOKEN
npx wrangler secret put NODE_A_GITHUB_TOKEN
npx wrangler secret put NODE_A_EVENT_TOKEN
npx wrangler secret put NODE_A_REPORT_PRIVATE_KEY_B64
npx wrangler secret put NODE_A_PRIVATE_HOST_TOKEN
npx wrangler secret put NODE_A_COLLECTOR_PUBLIC_KEY_B64
npx wrangler secret put NODE_A_ALERT_URL
npx wrangler secret put NODE_A_ALERT_HOST
npx wrangler secret put NODE_A_ALERT_TOKEN
npx wrangler secret put TUF_ROOT_B64
npx wrangler secret put TUF_METADATA_URL
npx wrangler secret put TUF_TARGET_URL
```

## Required pinned inventory configuration

Configure these JSON values as Worker vars or secrets, according to the operator's data-handling policy:

- `NODE_A_EXPECTED_FILES_JSON`: JSON object mapping each required private-host release path to its expected lowercase SHA-256 digest. Every configured path must exist in the verified release manifest and in the collector's signed inventory.
- `NODE_A_EXPECTED_PRIVATE_CONFIG_JSON`: JSON object mapping each approved private-configuration policy ID to its expected lowercase SHA-256 digest. Use `{}` only if the approved private-host policy genuinely has no private-config entries.

The Worker rejects invalid paths, missing inventory entries, digest mismatches, stale/nonced collector responses, invalid signatures, and collector decisions inconsistent with the signed evidence.

## One-time baseline approval

The baseline initializer additionally requires:

- `NODE_A_BASELINE_APPROVAL_TOKEN`: a separately generated high-entropy 32–512-byte token. Do not reuse `NODE_A_API_TOKEN`.
- An independently reviewed, manifest-bearing release. The currently published v0.1.2 predates the required manifest and is not suitable for this monitor.

Provision the one-time token only when the owner is ready to approve the initial baseline:

```sh
npx wrangler secret put NODE_A_BASELINE_APPROVAL_TOKEN
```

Then, after all other secrets and pinned inventories are verified, invoke the baseline route with both credentials. The request has no body:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer ${NODE_A_API_TOKEN}" \
  -H "x-node-a-baseline-approval: ${NODE_A_BASELINE_APPROVAL_TOKEN}" \
  -X POST "https://<worker-host>/internal/baseline/initialize"
```

The Worker derives the candidate from the live `VERSION`, GitHub release tag, signed manifest/ZIP attestations, canonical-origin byte checks, private-host collector response, and Node 4 challenge/report acknowledgement. The Durable Object baseline is immutable. After successful initialization, remove or rotate `NODE_A_BASELINE_APPROVAL_TOKEN`; it is not needed for normal monitor runs.

## Manual monitor invocation

After baseline initialization:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer ${NODE_A_API_TOKEN}" \
  -X POST "https://<worker-host>/internal/monitor/run"
```

A successful response reports the verified release version/commit and whether the pin advanced. A signed rejection returns HTTP 409 and does not advance the pin. Missing configuration fails closed. Operational failures attempt the independent owner-alert webhook and return a generic error response.

## Owner-alert webhook contract

The configured endpoint must:

- be HTTPS and match the exact `NODE_A_ALERT_HOST`;
- be independently controlled from the SentryIQ application host and Node 4;
- accept a JSON POST with a Bearer token;
- reject redirects (the Worker uses `redirect: "error"`);
- acknowledge successful delivery with HTTP 200, 202, or 204.

The Worker sends only a constrained operational context (node ID, phase/release version, commit, mismatch count, and exception class); it does not send secrets, private configuration values, or raw exception messages. No provider or endpoint is selected/provisioned by this repository change.

## Cron and production acceptance

Do not add or enable a Cron trigger until the owner chooses the cadence and confirms the independent alert path. Before production sign-off, complete all of the following in a non-production Cloudflare account:

- Confirm the deployed Worker belongs to the intended account and has the intended Durable Object and private R2 bindings.
- Verify the new manifest-bearing release and its GitHub/Sigstore attestations against the refreshed Sigstore trusted root.
- Confirm the canonical origin's public assets match the signed manifest and all required security headers are present.
- Confirm the private-host collector verifies the challenge nonce, release identity, all pinned deployed-file digests, and all approved private-config policy entries.
- Confirm Node 4 has the matching Node A public signing key and accepts the challenge/report contract.
- Confirm the independent owner-alert provider acknowledges success and that a simulated failure reaches the owner independently of Node 4.
- Exercise TUF root rotation, timestamp rollback/equivocation, metadata expiry, delegated-role failures, and failed refresh preserving last-known-good state.
- Interrupt R2 target staging, take over the run lease, and prove stale owners cannot commit metadata or publish pointers.
- Verify abandoned stage cleanup, superseded-object reader grace, delayed garbage collection, and target digest comparison after restart/eviction.
- Rehearse rollback and record run IDs, account/bucket identifiers, secret names (never values), evidence, and owner sign-off.

Do not mark Node A production-ready from Workerd tests or a Wrangler dry-run alone. PR #145 remains draft/unmerged, no live deployment has been performed, and `productionReady` remains false.
