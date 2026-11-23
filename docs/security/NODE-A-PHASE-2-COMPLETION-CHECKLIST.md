# Node A Phase 2 Completion Checklist

**Workstream:** SentryIQ Node A — Cloudflare Workers security monitoring and asynchronous TUF update service  
**Tracking PR:** #145  
**Working branch:** `feat/node-a-async-target-staging`  
**Status:** Repository implementation and automated verification are complete for the current branch; external integration and operational acceptance remain outstanding. Production readiness is not established.

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

**Evidence:** CI run #45195405974 on commit `169d34bffacf7de50dd91da05acf42346604d747` passed 130/130 tests across 21/21 test files, the pinned upstream TUF atomicity tests, Wrangler dry-run, and Worker bundle filesystem-fallback inspection. After adding this checklist, CI run #45196175494 also completed successfully; both jobs passed, including the lockfile generation/install, Workerd integration, Wrangler build/bundle scan and pinned upstream TUF tests. The lockfile artifact (ID `14835779417`, produced by CI run #45212063874) was downloaded and independently verified: SHA-256 `216927e6ad9766041c73c1fd95e4f4979485bf959d175c4e0f0659f2060bf79e`, 114,564 bytes, lockfile v3, 214 package entries. The previous generated lockfiles differed because the transitive `brace-expansion` dependency floated from 5.0.13 to 5.1.0. The package now pins `brace-expansion@5.1.0`, and CI verifies the generated lockfile against `cloudflare/node-a-poc/package-lock.sha256` before `npm ci`. An earlier artifact had a different digest, so the latest run's artifact is the current reference. The file is verified but not committed; the repository branch still generates and installs the lockfile during CI. The 24-hour retired-object grace-period regression test is committed as `4d02540837b73ebc71e76c468daa22c0e1073c65`. During the integration review, Node A was found to reuse Node 4's challenge nonce for the private-host collector, contrary to the documented independent replay domain. This was corrected: Node A now generates a fresh 32-byte cryptographic nonce for private-host attestation, performs that check independently before contacting Node 4, and retains Node 4's nonce only for the signed event-plane report. The collector fetch now has a 10-second abort timeout. Regression coverage asserts nonce separation and that private-host attestation still runs when Node 4 is unavailable. Changes are committed through `af66eabe23e092b0f2f2611dda87f9f8949adc3b`. CI run #45209828232 passed both jobs on that PR head: Workers runtime/DO tests and pinned upstream TUF trusted-state atomicity tests. The generated lockfile artifact from run #45212063874 (ID `14835779417`) matches the pinned SHA-256 and size. Both Node A CI jobs passed on that run: 132/132 Workerd/DO tests across 21 files, 9 pinned upstream TUF CLIENT suites / 44 tests, the generated lockfile digest check, Wrangler production dry-run, and Worker bundle scan. A further collector audit found that monitored directories flagged unexpected regular files and symlinks but silently ignored special filesystem entries such as FIFOs, sockets and device nodes. The collector now rejects every unexpected non-directory entry, and a regression test creates a FIFO when POSIX support is available. Commits `7c33af0475d0cadd972fa2b7454d7e112de6139d` and `9ead0c4ceb1445872211efc6e83ec716eba3fd03`; CI run #45213844387 passed both Node A jobs on the FPM-adapter implementation head: 132/132 Workers tests across 21 files, 9 upstream TUF CLIENT suites / 44 tests, Wrangler dry-run/bundle scan and lockfile digest verification. Native PHP CI run #45213844341 passed all five versions (8.1–8.5), including FPM entrypoint syntax and security-contract tests. The TUF root-rotation limit was also hardened: reaching the configured maximum no longer silently stops on a potentially stale root. Node A probes the next sequential root; only 403/404 confirms the chain ended, while another available root fails closed. Regression tests cover the end probe and cap exhaustion. The first CI attempt exposed outdated fixtures and a test CAS identity mismatch; those were corrected, and the successful run above includes the corrected tests. PR #145 remains draft/open/unmerged.

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

- [x] Collector core, framework-neutral authenticated request handler, durable single-use nonce store, Ed25519 response signing, and regression tests (integrated into main by PR #99).
- [x] Add a reference PHP-FPM entrypoint and deployment template requiring a dedicated FPM pool, owner-only config outside the webroot, a 0700 private directory, bounded request bodies and no-store responses (`deploy/private-host-attestation/`).
- [ ] Provision and verify the provider-specific HTTPS listener/reverse-proxy route for `/private-host-attestation`; the reference Nginx/FPM template is not a live host configuration and must not expose the signing key through the public PHP-FPM identity.
- [ ] Run the collector under a dedicated OS identity, separate from PHP-FPM.
- [ ] Restrict that identity to approved read-only inspection paths.
- [ ] Provision and protect the isolated Ed25519 signing key.
- [ ] Provision separate Node A and collector bearer credentials.
- [ ] Provision nonce storage with the required directory/file permissions.
- [ ] Pin and verify the collector public key in Cloudflare.
- [ ] Configure independently approved file and private-configuration inventories.
- [ ] Test the complete Cloudflare-to-host attestation exchange.

**Security constraint:** The existing contract requires isolation from the public application process. Do not implement a public PHP route that holds or can access the collector signing key. The recorded production host is cPanel with no shell/SSH access confirmed; provider capability for a persistent daemon under a separate OS identity, read-only ACLs, private socket/loopback listener, and HTTPS reverse proxy is unverified. The provider must confirm these capabilities before a deployable adapter can be selected. If unsupported, this host cannot meet the required boundary and an independently approved isolated host/service is needed. Host-specific service installation, credentials, ACLs, TLS and routing require owner-controlled infrastructure access and approval.

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

- [x] Test TUF root rotation, sequential durable commits, and fail-closed rotation-cap exhaustion.
- [x] Test timestamp rollback and same-version equivocation rejection.
- [x] Test expired/corrupt cached metadata recovery and invalid trusted-role rejection.
- [x] Test delegated-role authorization, traversal bounds, and upstream verifier failures.
- [x] Test interrupted/short/oversized R2 target streams, digest failures, and durable chunk-write failures.
- [x] Test Durable Object lease takeover, stale-owner chunk rejection, and stale-owner publication rejection.
- [x] Test abandoned staging-object cleanup after a newer fencing epoch.
- [x] Test superseded-object grace periods and garbage collection, including the 24-hour reader grace.
- [x] Test trusted-state reconstruction from durable metadata after restart and cache-miss recovery for missing/truncated R2 objects.
- [x] Verify last-known-good durable trusted state is not replaced by rejected metadata; poison ambiguous in-memory verifier state.
- [ ] Complete an account-backed end-to-end rollback rehearsal.

**Evidence boundary:** These code-level failure/recovery tests are covered by the Node A Workerd/DO suite and pinned upstream TUF client suite in CI run #45213844387 (132/132 tests across 21 files; 9 upstream suites / 44 tests). They do not substitute for live Cloudflare R2/DO fault injection, actual Worker restart/cache eviction, or a production-like rollback rehearsal.

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