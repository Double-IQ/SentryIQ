# Node A async TUF Worker deployment

This is an operational checklist, not evidence of a completed production deployment. The code path is covered by Workerd tests and a Wrangler dry-run build; the target Cloudflare account still needs provisioning and account-backed R2 acceptance.

## Provision the target account

1. Authenticate Wrangler against the intended Cloudflare account:

   ```sh
   npx wrangler login
   ```

2. Create the R2 bucket declared in `wrangler.jsonc`:

   ```sh
   npx wrangler r2 bucket create sentryiq-node-a-targets
   ```

3. Set the runtime secrets. Wrangler prompts for each value; do not commit them, place them in a checked-in `.dev.vars`, or paste them into an issue/PR.

   ```sh
   npx wrangler secret put NODE_A_API_TOKEN
   npx wrangler secret put TUF_ROOT_B64
   npx wrangler secret put TUF_METADATA_URL
   npx wrangler secret put TUF_TARGET_URL
   ```

   - `NODE_A_API_TOKEN`: a high-entropy bearer token held by the trusted caller; the Worker rejects configured values shorter than 32 bytes, longer than 512 bytes, or containing control characters.
   - `TUF_ROOT_B64`: canonical base64 (no line breaks) of the explicitly provisioned TUF root metadata bytes. Verify its provenance and digest out of band before setting it.
   - `TUF_METADATA_URL`: HTTPS metadata mirror base URL, ending in `/`.
   - `TUF_TARGET_URL`: HTTPS target mirror base URL, ending in `/`.

   The updater rejects non-HTTPS base URLs, embedded credentials, query strings, and fragments. Target paths are resolved as encoded relative segments beneath the configured target base.

4. Review the account, bucket name, Durable Object binding, compatibility date/flags, and secret values, then deploy:

   ```sh
   npx wrangler deploy
   ```

## Configure the scheduled integrity monitor

The Worker is configured with a 15-minute Cron trigger (`*/15 * * * *`). The scheduled handler runs the complete release monitor under the Durable Object run lease: refreshes Sigstore TUF, verifies the deployed release manifest and ZIP against GitHub attestations, checks canonical-origin assets/headers, obtains the Node 4 challenge, verifies the signed private-host collector response, submits the signed Node A report, and only then advances the release pin. Rejections and operational failures use the independent owner-alert webhook. A missing or invalid configuration fails closed; the Cron trigger does not initialize the release baseline.

Before enabling a production deployment, provision and independently verify all of the following in the intended account. Never commit these values or paste them into PRs/issues.

**Secrets / credentials**

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

- `NODE_A_API_TOKEN`: high-entropy 32–512-byte bearer token for the internal manual monitor/baseline endpoints.
- `NODE_A_GITHUB_TOKEN`: least-privilege GitHub token that can read the SentryIQ release/tag and GitHub attestation evidence; do not grant write access.
- `NODE_A_EVENT_TOKEN`: Node 4 A-only event API credential.
- `NODE_A_REPORT_PRIVATE_KEY_B64`: canonical base64 encoding of the Node A Ed25519 64-byte secret-key representation (32-byte seed followed by its matching 32-byte public key). Verify the public key against the Node 4 registered Node A key before setting it.
- `NODE_A_PRIVATE_HOST_TOKEN`: strong A-only bearer credential for the private-host collector.
- `NODE_A_COLLECTOR_PUBLIC_KEY_B64`: canonical base64 encoding of the collector's 32-byte Ed25519 public key; pin this out of band.
- `NODE_A_ALERT_URL` and `NODE_A_ALERT_HOST`: exact HTTPS webhook URL and its exact hostname. The host must be independently controlled and must not be the SentryIQ application host or a `*.bichet.co.za` host.
- `NODE_A_ALERT_TOKEN`: independent 40–128-character URL-safe bearer credential for that webhook.
- `TUF_ROOT_B64`, `TUF_METADATA_URL`, `TUF_TARGET_URL`: as specified above.

**Pinned inventory configuration**

Set these non-secret JSON values as Worker vars (or use the secret store if preferred):

- `NODE_A_EXPECTED_FILES_JSON`: JSON object mapping each required private-host release path to its expected lowercase SHA-256 digest. This must be reviewed against the approved release manifest and private-host policy.
- `NODE_A_EXPECTED_PRIVATE_CONFIG_JSON`: JSON object mapping each approved private configuration key to its expected policy digest/value. Use `{}` only if the approved private-host policy genuinely has no private-config entries.

The one-time baseline initializer additionally requires `NODE_A_BASELINE_APPROVAL_TOKEN`, a separately generated high-entropy 32–512-byte value. Keep it unavailable to routine scheduled execution; use it only for the owner-authorized initial baseline request, then rotate/remove it. Do not initialize the baseline until the release and all independent evidence have been reviewed.

**Operational checks before activation**

- Confirm the Node 4 endpoint has the matching Node A public signing key and accepts the challenge/report schema.
- Confirm the private-host collector returns the exact signed nonce/release/file/config envelope expected by the pinned collector public key.
- Confirm the independent alert endpoint acknowledges POSTs with HTTP 200, 202, or 204 and rejects redirects.
- Confirm the configured GitHub token can read both required attestation subjects and the release tag, without repository write permissions.
- Confirm the 15-minute cadence and alert routing with the service owner before deploying the Cron trigger.

## Verify the deployed Worker

- `GET /health` should return the basic Worker health response.
- `GET /runtime-check` reports loaded runtime components and bindings. `productionReady` intentionally remains false until account-backed acceptance is completed.
- `POST /internal/monitor/run` executes a manual monitor run and requires the API bearer token.
- `POST /internal/baseline/initialize` requires both the API bearer token and the separate one-time baseline approval header. It is not part of scheduled execution.
- `POST /internal/tuf/refresh` requires `Authorization: Bearer <NODE_A_API_TOKEN>`.
- `GET /internal/tuf/targets/<URL-encoded-TUF-target-path>` requires the same bearer token and returns only a target matching the currently trusted TUF descriptor.

Example request shape (use a secure secret manager/environment variable; never place the real token in shell history):

```sh
curl --fail-with-body \
  -H "Authorization: Bearer ${NODE_A_API_TOKEN}" \
  -X POST "https://<worker-host>/internal/tuf/refresh"
```

## Required acceptance before production sign-off

- Confirm the deployed Worker is attached to the intended Cloudflare account and R2 bucket.
- Refresh against the approved TUF mirror and verify root rotation, timestamp/snapshot linkage, and delegated-role traversal.
- Retrieve a known target and compare its bytes/digests independently with the signed TUF metadata.
- Verify wrong/missing bearer tokens fail closed.
- Interrupt a target upload, acquire a newer run fence, and confirm the next run removes the old private R2 stage without publishing it.
- Force lease takeover during metadata and target work; prove the stale owner cannot commit metadata or publish a pointer.
- Verify same-path target updates invalidate older cached pointers.
- Inspect R2 objects and Durable Object pointer/staging records after success, failure, and restart.
- Record the run IDs, account/bucket identifiers, test evidence, and rollback procedure in the deployment record.

Do not mark production readiness from the dry-run build or unit tests alone. The account-backed R2 and fault-injection checks above are still required.
