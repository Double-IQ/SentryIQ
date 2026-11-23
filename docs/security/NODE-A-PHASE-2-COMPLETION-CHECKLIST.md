# Node A Phase 2 Completion Checklist

**Workstream:** SentryIQ Node A — Cloudflare Workers security monitoring and asynchronous TUF update service  
**Tracking PR:** #145  
**Working branch:** `feat/node-a-async-target-staging`  
**Status:** Implementation and automated verification are progressing; production readiness is not established.

This checklist is the execution record for completing Node A in Phase 2. Mark an item complete only when supported by repository evidence, test output, or recorded owner-approved operational evidence. Do not repeat completed work. Do not claim production readiness from unit tests or a Wrangler dry-run.

## Execution rules

1. Continue repository-side implementation, documentation, tests, and CI verification without waiting for owner input.
2. Keep changes in review; do not merge, publish releases, change production DNS/hosting, provision credentials, alter Cloudflare accounts, or deploy without explicit owner approval.
3. Never commit secret values. Record secret names and verification evidence only.
4. The private-host signing key must remain outside the public PHP-FPM/application request identity. A public PHP endpoint holding that key is prohibited.
5. Update this checklist as work is completed or a blocker is evidenced. Each completed item should have a commit, test, artifact, or owner sign-off reference where applicable.

## 1. Repository and release readiness

- [x] Worker-native TUF updater implementation.
- [x] Durable Object trusted metadata and fencing controls.
- [x] Private R2 target staging and publication logic.
- [x] Authenticated refresh and target retrieval routes.
- [x] Scheduled monitoring handler.
- [x] Release manifest and canonical-origin verification logic.
- [x] Node 4 challenge/report integration code.
- [x] Security regression tests and Worker bundle checks.
- [ ] Commit the recovered, verified `cloudflare/node-a-poc/package-lock.json` to the branch.
- [ ] Review and approve PR #145.
- [ ] Merge PR #145 after approval.
- [ ] Configure repository branch protection and required checks.

**Evidence:** CI run #45195405974 on commit `169d34bffacf7de50dd91da05acf42346604d747` passed 130/130 tests across 21/21 test files, the pinned upstream TUF atomicity tests, Wrangler dry-run, and Worker bundle filesystem-fallback inspection. After adding this checklist, CI run #45196175494 also completed successfully; both jobs passed, including the lockfile generation/install, Workerd integration, Wrangler build/bundle scan and pinned upstream TUF tests. The latest lockfile artifact (ID `14833619068`, produced by CI run #45208792655) was downloaded and independently verified: SHA-256 `27e07ef79be29ea155d8664f7fba6a15692c8a3986a8fdf572f62efb8a04aadc`, 114,566 bytes, lockfile v3, 214 package entries. An earlier artifact had a different digest, so the latest run's artifact is the current reference. The file is verified but not committed; the repository branch still generates and installs the lockfile during CI. The 24-hour retired-object grace-period regression test is committed as `4d02540837b73ebc71e76c468daa22c0e1073c65`. CI run #45208792655 passed both jobs on the PR head: Workers runtime/DO tests and pinned upstream TUF trusted-state atomicity tests. PR #145 remains draft/open/unmerged.

## 2. Cloudflare infrastructure

- [ ] Confirm the production Cloudflare account and administrative boundary.
- [ ] Create the `sentryiq-node-a-targets` R2 bucket.
- [ ] Provision the Durable Object binding and migration.
- [ ] Provision required Worker secrets using the deployment runbook; never commit values.
- [ ] Configure pinned TUF root and metadata/target mirror URLs.
- [ ] Configure expected release-file and private-configuration inventories.
- [ ] Obtain owner approval for the 15-minute Cron schedule.
- [ ] Deploy to a non-production Cloudflare environment after explicit approval.

## 3. Private-host attestation service — integration blocker

- [ ] Implement the isolated private-host attestation service.
- [ ] Implement its HTTPS/reverse-proxy adapter for `/private-host-attestation`.
- [ ] Run it under a dedicated OS identity, separate from PHP-FPM.
- [ ] Restrict filesystem access to approved read-only inspection paths.
- [ ] Provision and protect the isolated Ed25519 signing key.
- [ ] Provision separate Node A and collector bearer credentials.
- [ ] Configure nonce storage with the required directory/file permissions.
- [ ] Pin and verify the collector public key in Cloudflare.
- [ ] Configure approved file and private-configuration inventories.
- [ ] Test the complete Cloudflare-to-host attestation exchange.

**Security constraint:** The existing contract requires isolation from the public application process. Do not implement a public PHP route that holds or can access the collector signing key. Host-specific service installation, credentials, ACLs, TLS and routing require owner-controlled infrastructure access and approval.

## 4. Release and supply-chain verification

- [ ] Prepare an owner-reviewed, manifest-bearing v0.1.3 release.
- [ ] Publish the release ZIP, checksums and `release-manifest.json` after explicit approval.
- [ ] Generate and verify GitHub attestations for the release assets.
- [ ] Verify the manifest against the actual release files.
- [ ] Verify the release against the refreshed Sigstore trusted root.
- [ ] Verify the canonical production origin against the signed release inventory.

**Known gap:** Published stable releases currently extend through v0.1.2, which predates the required manifest-bearing release process. Do not publish v0.1.3 without owner approval.

## 5. Node 4 integration

- [ ] Register the Node A Ed25519 public key with Node 4.
- [ ] Verify the registered key matches the Worker signing key.
- [ ] Provision the Node A event API credential.
- [ ] Execute a real challenge/report exchange.
- [ ] Verify signed report acceptance and acknowledgement.
- [ ] Verify rejected or invalid reports cannot advance the release pin.

## 6. Independent alerting

- [ ] Select and approve an independent alert destination.
- [ ] Provision the alert URL, hostname and credential.
- [ ] Verify independence from the SentryIQ application host and Node 4.
- [ ] Test successful alert delivery.
- [ ] Inject a monitoring failure and verify owner notification.
- [ ] Confirm alerts contain no secrets or sensitive configuration.

## 7. Staging security and failure testing

- [ ] Test TUF root rotation.
- [ ] Test timestamp rollback and equivocation rejection.
- [ ] Test expired and invalid metadata.
- [ ] Test delegated-role failures.
- [ ] Test interrupted R2 uploads.
- [ ] Test Durable Object lease takeover and stale-owner rejection.
- [ ] Test abandoned staging-object cleanup.
- [ ] Test superseded-object grace periods and garbage collection.
- [ ] Test recovery after Worker restart or cache eviction.
- [ ] Verify last-known-good trusted state survives failed refresh.
- [ ] Complete an end-to-end rollback rehearsal.

## 8. Production acceptance

- [ ] Complete non-production deployment acceptance.
- [ ] Verify actual Cloudflare bindings and account configuration.
- [ ] Complete the real private-host attestation exchange.
- [ ] Complete the real Node 4 exchange.
- [ ] Verify independent alert delivery.
- [ ] Initialize the immutable monitoring baseline with owner approval.
- [ ] Run the complete monitoring workflow.
- [ ] Record test evidence, run IDs and deployment configuration.
- [ ] Obtain explicit owner sign-off.
- [ ] Approve production deployment.

## Current assessment

**Code/CI:** Current implementation passes its recorded automated checks.  
**Integration:** Private-host service, Cloudflare account configuration, release v0.1.3, Node 4 trust, and independent alert delivery remain outstanding.  
**Repository gap:** The generated lockfile is recovered and hash-verified, but still needs to be inserted into the repository branch.  
**Production:** Not ready; no live deployment or owner acceptance is evidenced.

The checklist is complete only when all required sections are evidenced and the owner has approved production acceptance.