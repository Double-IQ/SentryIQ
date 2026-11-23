# Node A Cloudflare Workers proof of concept

**Status: Worker-native implementation, authenticated manual monitor routes, and a 15-minute scheduled monitor handler are in draft PR #145; not production-deployed or operationally accepted.**

This directory is deliberately separate from the PHP production application. Node A's owner-confirmed platform is Cloudflare Workers. The implementation uses a Worker-native TypeScript TUF runtime, Durable Object fencing/metadata persistence, private R2 target staging, and a release-integrity monitor composition.

## Run

From this directory:

```sh
npm install
npm test
```

Direct dependencies are exact-version pinned in `package.json`. The CI workflow generates an exact `package-lock.json` for each run, installs from it, and uploads it for review. That lockfile is **not yet committed to this branch**, so committing a reviewed lockfile remains a reproducibility/deployment gate.

## Implemented on the draft branch

- **Async TUF and target storage:** pinned `tuf-js@6.0.3` trusted metadata is persisted through fenced Durable Object operations; sequential root rotation, timestamp rollback/equivocation checks, online timestamp/snapshot refresh, consistent-snapshot naming, bounded metadata transport, delegated-role verification, private R2 staging, atomic pointer publication, and fenced cleanup are covered by Workerd tests.
- **Release evidence:** strict duplicate-key-safe manifest parsing, exact repository/release/tag/commit identity, complete public/runtime inventory, exact `VERSION` byte binding, bounded GitHub release asset retrieval with a redirect allowlist, streaming ZIP SHA-256, Snappy bundle decoding, and authenticated GitHub/SLSA attestation policy.
- **Canonical origin:** byte length and SHA-256 checks for signed public assets, fixed canonical HTTPS origin, redirect rejection, and required security-header checks.
- **Private host:** A-only collector request, pinned Ed25519 response verification, nonce/freshness/release binding, and exact pinned deployed-file/private-config inventory checks.
- **Node 4 exchange:** challenge request, A-only Ed25519 report signing, bounded report submission, and acknowledgement validation.
- **Independent owner alert:** generic HTTPS webhook transport pinned to an exact external hostname, with redirects rejected and a strict non-sensitive event context.
- **Monitor composition:** TUF refresh and trusted-root loading, deployed VERSION and release assets, GitHub release evidence, canonical-origin checks, private-host attestation, Node 4 report, direct owner alerts, and release-pin advancement under a Durable Object run lease.
- **Worker orchestration:** `POST /internal/monitor/run` performs a manual monitor run after baseline initialization. `POST /internal/baseline/initialize` performs the same verification and can initialize the immutable baseline only with both the normal API bearer token and a separate one-time baseline approval token. The scheduled handler runs the same monitor every 15 minutes under the Durable Object run lease; it never initializes the baseline. Until the owner-approved baseline exists, it records a failed/blocked outcome and skips without generating a recurring alert. After baseline initialization, operational failures attempt the independent owner-alert path. It records only minimal success/rejection/failure outcomes. All monitor entry points fail closed when required configuration is absent.

The Worker suite passes **129/129 tests across 21 files** on exact head `9eba8ef303685072d08a1ec71495566923bd921f`; the pinned upstream TUF trusted-state atomicity job, Wrangler production dry-run, and Worker bundle scan also pass ([CI run 45186103006](https://github.com/Double-IQ/SentryIQ/actions/runs/45186103006)). The monitor now emits the neutral `integrity_run_failed` alert reason for both manual and scheduled runs. The run also generated and uploaded a reviewable npm lockfile (lockfile v3, 214 package entries; SHA-256 `6c4f6f25f261d0dfa525d059c2b9cdb01e945c1381bbacdc2c3d037139445ae2`, artifact `14822104840`). It is not committed yet, so the reproducibility gate remains open. GitHub bundle retrieval is restricted to the trusted numeric repository ID, repository-scoped Azure Blob path, and read-only SAS URLs. The CI test job also retrieves the genuine published v0.1.2 release asset and GitHub attestation bundle and injects the current Sigstore trusted root into the workerd integration tests.

## Operational boundary and non-claims

- The published v0.1.2 release predates the required embedded canonical manifest and has no `release-manifest.json`; the new monitor intentionally cannot accept it. A new manifest-bearing release is required before a live monitor run can pass.
- The stock `@sigstore/tuf@5.0.1` filesystem-backed wrapper remains in isolated compatibility tests only. It is removed from the Worker production dependency path. The Worker uses the async `tuf-js` adapter and the pinned upstream atomicity patch.
- The Worker entry point includes a `*/15 * * * *` Cron trigger in `wrangler.jsonc`, but it has not been deployed or activated in a Cloudflare account. The service owner must confirm the cadence and alert routing before a production deployment.
- The baseline has not been initialized. No one-time baseline approval token has been provisioned.
- No Cloudflare production account/bucket, TUF bootstrap secret/mirror, GitHub API token, Node 4 token, report signing key, private-host token/collector key, expected inventory maps, independent alert endpoint, or production Worker deployment has been provisioned or verified.
- The generic direct-alert transport is implemented, but its external endpoint and credential must be selected and provisioned by the owner. It must be independently controlled and not hosted on the SentryIQ application origin.
- The Node A client targets `/private-host-attestation`, but the PHP collector/request-handler/nonce-store classes have no deployed HTTP listener or `.htaccess` route. The contract requires an isolated host service outside the public PHP request path, with a dedicated OS identity and signing key inaccessible to PHP-FPM; a public PHP endpoint holding the signing key is not acceptable. An owner-approved isolated service/reverse-proxy route, private nonce-store provisioning, A/B credentials, and collector key/inventory configuration are required before the private-host exchange can work end to end.
- The Durable Object release pin is advanced only after the signed Node 4 report is acknowledged. A rejected or unacknowledged event does not advance the pin.
- `GET /runtime-check` deliberately reports `productionReady: false` until account-backed acceptance is completed.
- PRs #143 and #145 remain draft/unmerged. No production changes have been made.

## Acceptance sequence still required

1. Commit and review the CI-generated dependency lockfile; retain the pinned upstream TUF patch or replace it only with a separately reviewed upstream release.
2. Provision the intended Cloudflare account, R2 bucket, Durable Object, TUF bootstrap/mirror configuration, GitHub/Node 4/private-host credentials, pinned inventories, and independent owner-alert webhook.
3. Independently review the current manifest-bearing release and initialize the immutable baseline through the one-time approval route. Do not use v0.1.2 for this path.
4. Exercise the manual monitor against the live non-production Worker and verify the actual Node 4, private-host collector, and owner-alert provider acknowledgements.
5. Confirm the proposed 15-minute monitoring cadence and independent alert routing with the service owner, then deploy to non-production and verify actual Cron invocations, failure recording, and alert delivery.
6. Complete account-backed R2 fault injection, lease takeover, stale-owner rejection, target digest comparison, restart/eviction, rollback rehearsal, and deployment evidence.
7. Only then consider production readiness and merge/deploy approval.

The Workerd suite and Wrangler bundle scan are not substitutes for a Cloudflare account-backed staging deployment.

### Historical implementation notes

Earlier feasibility notes below this heading were superseded by the Worker-native async TUF adapter, pinned upstream trusted-state atomicity patch, Durable Object metadata store, and R2 staging implementation described above. The current acceptance gates are the operational and account-backed requirements listed above; do not treat earlier statements that these components remain unimplemented as current status.
