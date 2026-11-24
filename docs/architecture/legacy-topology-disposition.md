# Legacy Topology and Component Disposition Inventory

**Status:** Initial pass — not exhaustive.  
**Target architecture:** SentryIQ at `https://sentryiq.bichet.co.za`; independent security verifier on HelioHost; owner's phone as master device.

This inventory prevents unsafe bulk deletion. A file is not removed merely because its former deployment topology is retired. Each component must be traced to callers, tests, workflows, and shared contracts first.

## Initial findings

| Area | Existing implementation / reference | Former assumption | Initial disposition |
|---|---|---|---|
| Cloudflare Worker | `cloudflare/node-a-poc/src/index.ts`, `wrangler.jsonc`, Worker runtime and tests | Node A runs as a Cloudflare Worker with Durable Objects, R2 and Cron | Retire as deployment target. Preserve source/tests temporarily; inspect for reusable monitor, TUF, fencing, and verification logic before deletion. |
| R2 target store | `cloudflare/node-a-poc/src/r2-tuf-target-store.ts` and TUF storage contract | Cloudflare R2 is target object storage | Cloudflare binding is obsolete. TUF metadata/target verification logic may be reusable only if the new app/update design still requires it. |
| Worker release asset client | `cloudflare/node-a-poc/src/release-assets.ts` | Worker polls the canonical application origin and GitHub release assets | Reusable concepts; current file hardcodes the correct canonical origin `https://sentryiq.bichet.co.za`. Review actual deployed asset verification design before adapting. |
| Worker private-host verifier client | `cloudflare/node-a-poc/src/private-host-attestation.ts` | Node A identifies as `integrity-a` and calls the application-host `/private-host-attestation` endpoint | Old A/B transport contract. Do not deploy unchanged. Extract schema, nonce, Ed25519 and freshness tests for reuse after redesign. |
| Worker Node 4 event client | `cloudflare/node-a-poc/src/node4-event-client.ts` | Node A sends a report to `/integrity_event.php` as `integrity-a` | Old topology-specific event plane. Review whether the new HelioHost verifier needs a minimal signed report/alert protocol; do not retain A identity or old dependency by default. |
| PHP private-host client | `app/Updates/PrivateHostAttestationClient.php` | Supports `integrity-a` and `integrity-b` bearer identities calling the application host | Old A/B client, not the new HelioHost verifier protocol. Preserve only if a reviewed reuse case remains. |
| PHP collector/handler/nonce store | `app/Updates/PrivateHostAttestationCollector.php`, `PrivateHostAttestationRequestHandler.php`, `PrivateHostAttestationNonceStore.php` | Application host exposes a collector for external A/B verifiers | Potentially reusable read-only inventory, nonce, and detached-signature primitives. Trust boundary must be redesigned: HelioHost should independently measure public delivery; private-file inspection requires a separately proven read-only isolation mechanism. |
| Node 4 endpoint | `integrity_event.php` and `app/Updates/IntegrityEvent*` | Node A/B challenge/report exchange | Existing endpoint may have other consumers. Do not delete until full repository-wide caller/config/test inventory is complete. |
| Private-host contract | `docs/security/private-host-attestation-contract.md` | A/B verifiers; HelioHost described as Node C | Replaced as active contract; historical copy retained at `private-host-attestation-contract-archive.md`. |
| Cloudflare runbooks | `cloudflare/node-a-poc/EXECUTION_PLAN.md`, `DEPLOYMENT.md`, `README.md` | Cloudflare deployment | Replaced with retirement notices; original content preserved in adjacent `*_ARCHIVE.md` files. |
| Candidate workflow PR | PR #150, `ci/node-a-candidate-build-dispatch` | Builds a candidate from old Node A feature branch | Still open at initial inspection. Do not merge as-is; determine whether generic package-build steps should be retained in a new release workflow. |

## Canonical origin audit

The following inspected code already uses the correct origin `https://sentryiq.bichet.co.za`:
- `cloudflare/node-a-poc/src/release-assets.ts`
- `cloudflare/node-a-poc/src/private-host-attestation.ts`
- `cloudflare/node-a-poc/src/node4-event-client.ts`
- `app/Updates/PrivateHostAttestationClient.php`

The problem in those files is not the hostname; it is the former A/B/Cloudflare trust topology and protocol assumptions. Do not change the hostname blindly.

## Immediate constraints

- The new HelioHost verifier must not be implemented as a public endpoint on the SentryIQ application host.
- Public HTTP asset hashing does not prove integrity of private PHP files, server configuration, or the host OS.
- The verifier must not hold application write credentials, master-device keys, recovery material, or data-encryption keys.
- The application host must not be able to mint the verifier's signed reports or alter its pinned release policy.
- Existing PHP collector code is not automatically safe to run on HelioHost; first verify read-only access boundaries and provider capabilities.
- The PWA cannot self-attest to its own runtime. The phone must validate independently signed evidence, and residual browser/OS compromise risk must be addressed.

## Remaining inventory work

- Search all tracked files for Cloudflare product bindings, `workers.dev`, R2, Durable Objects, A/B/C node identifiers, Node 4 report coupling, old route names, and stale origin strings.
- Inspect package manifests, lockfiles, build scripts, release workflows, tests, docs, and configuration references before removing any code.
- Identify code used by the main PHP application or non-Node features.
- Review PR #150 and any open/merged release workflow dependencies.
- Produce a deletion/adaptation sequence with test coverage and rollback before source removal.
