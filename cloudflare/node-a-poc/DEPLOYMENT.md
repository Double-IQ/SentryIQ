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

## Verify the deployed Worker

- `GET /health` should return the basic Worker health response.
- `GET /runtime-check` reports loaded runtime components and bindings. `productionReady` intentionally remains false until account-backed acceptance is completed.
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
