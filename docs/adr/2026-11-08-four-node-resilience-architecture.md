# ADR: Four-node resilience and independent integrity monitoring

- **Status:** Proposed
- **Date:** 2026-11-08
- **Related:** [Security roadmap: signed releases and dual independent Integrity Nodes](https://github.com/Double-IQ/SentryIQ/issues/13)
- **Branch:** `feature/four-node-resilience-architecture`

## Context

SentryIQ is a self-hosted PHP application that protects highly sensitive user data. Its production origin must therefore be treated as a potentially compromisable target, not as the authority that decides whether its own files are trustworthy.

The existing security roadmap calls for two independently hosted Integrity Nodes and signed release verification. The four-node design must preserve that requirement. A design with only one monitor, one scheduler, and one alert service would not provide two independent integrity verdicts.

The four nodes below are logical trust domains. They do not require four identical VPS instances, and they must not share a single provider account, deployment credential, or administrative boundary where avoidable.

## Decision

Adopt four logical nodes:

1. **Node 1 — Core application (production origin).** Runs the existing SentryIQ PHP application and serves the user interface and APIs. It is the monitored target, not a trust authority. It must not possess the release-signing private key or be able to change monitor software, monitor trust roots, monitor schedules, or independent alert destinations.
2. **Node 2 — Integrity Node A.** Independently retrieves the trusted signed release manifest, checks the live public origin against it, performs its own health and freshness checks, signs its own report, and sends alerts through an independent path.
3. **Node 3 — Integrity Node B and independent schedule.** Performs the same verification independently from a different provider, credentials, network, and preferably administrative boundary. Its schedule and trigger path must not depend on Node 2 or Node 1. It compares signed reports where useful, but never treats Node 2's verdict as proof.
4. **Node 4 — Security event and alert plane.** Receives and correlates signed reports, records incidents, and provides an additional owner-notification path. It is an aggregation and response aid, not the root of trust: it cannot rewrite the trusted manifest, change the nodes' pinned trust roots, approve releases, or suppress the nodes' direct owner alerts.

The term **four-node architecture** describes these four trust domains. The two independent Integrity Nodes are mandatory. Scheduling is deliberately distributed: each Integrity Node has its own schedule and an independently controlled trigger. A cron provider or serverless scheduler may trigger checks, but is not itself a release trust anchor. Node 4 must not become a single point of failure for detection or notification.

## Trust and communication rules

- Each node has its own identity and narrowly scoped credentials. No shared master API key.
- Node-to-node reports are authenticated and signed. Reports include node identity, target origin, release/manifest identity, sequence, check time, result categories, and evidence references; they must not include vault content, passwords, session cookies, encryption keys, or other secrets.
- Each Integrity Node pins the release-signing public key independently. The release-signing private key remains offline or in a separately controlled hardware-backed signing environment and is never deployed to Nodes 1–4.
- The production origin cannot change monitor code, pinned public keys, schedules, alert destinations, or retained evidence.
- Node 2 and Node 3 independently fetch and validate the signed manifest and independently inspect the public origin. A disagreement is an incident to investigate, not a majority-vote release approval.
- Node 4 may correlate and notify, but Nodes 2 and 3 retain direct fallback notification paths to the owner so Node 4 outage or compromise cannot silently suppress all alerts.
- A missing, invalid, expired, or rollback manifest fails closed for verification. A single unverified node report must not automatically lock users out or trigger destructive remediation.
- External HTTP checks can verify publicly served files, headers, redirects, TLS, and exposed assets. They cannot read private PHP source, private runtime configuration, or server-side files outside the public origin.
- Private server-side integrity requires a separate authenticated, read-only host attestation/collector with narrowly scoped access. It reports deployment identity and file hashes, never secrets or user data.
- Use separate providers and administrative accounts where practical. Different hostnames on the same compromised account do not constitute independent nodes.

## What the Integrity Nodes verify

At minimum, both nodes independently verify:

- The canonical signed manifest, signature, expiry, version, and anti-rollback sequence.
- Public HTML, JavaScript, CSS, images, service-worker files and web-app manifest when present, redirects, security headers, and externally loaded scripts/domains.
- Expected public file inventory and SHA-256 hashes, detecting changed, added, missing, or unexpectedly exposed files.
- TLS/certificate posture and security-header drift, clearly distinguishing advisory configuration drift from a confirmed release-integrity mismatch.
- Node health, last successful check, clock freshness, report signature, and stale or missing reports.

A check result must distinguish at least: verified, confirmed mismatch, expected deployment transition, invalid or stale manifest, target unavailable, TLS/header drift, verifier failure, and stale/missing node.

## Release trust

The release pipeline is the source of the expected artifact identity:

- CI runs relevant PHP/JavaScript syntax, unit/integration, dependency, secret, and static-security checks on pull requests and protected main-branch changes.
- Protected branches and release tags require the repository's approved review and successful checks.
- A release build produces an immutable artifact and canonical manifest with file paths, sizes, SHA-256 hashes, version, commit, build identity, and monotonic sequence/anti-rollback metadata.
- The manifest and artifact provenance are signed outside the production host. A checksum published beside an artifact by the same release account is not an independent signature.
- The signed manifest is published through a channel the production origin cannot rewrite.
- The updater verifies the approved signature and anti-rollback policy before applying an artifact. Signature verification must not be enabled with an unapproved or improvised key-custody model.

The release signing trust model and key custody must be approved before production signing or updater enforcement is implemented.

## Detection versus prevention

The Integrity Nodes provide independent detection and notification. They do not guarantee that a malicious script served by a compromised origin is blocked before a user's browser or iPhone PWA executes it.

The architecture must document expected detection latency and residual risk. Client-side delivery hardening, CSP, dependency minimization, signed/reproducible builds, and user-verifiable release hashes are complementary controls, not substitutes for the independent monitors.

## Failure and compromise behaviour

- **Node 1 compromised:** Nodes 2 and 3 continue checking independently; Node 4 receives reports; direct owner alerts remain available.
- **Node 2 unavailable or compromised:** Node 3 continues independently and reports missing or inconsistent Node 2 status. Node 2 cannot change Node 3's trust roots.
- **Node 3 unavailable or compromised:** Node 2 continues independently and reports missing or inconsistent Node 3 status.
- **Node 4 unavailable or compromised:** Nodes 2 and 3 continue verification and direct owner notification. Node 4 cannot approve a release or alter verifier trust.
- **One cron provider unavailable:** The other Integrity Node's independently controlled schedule continues.
- **GitHub or release channel compromised:** Nodes reject artifacts whose manifest cannot be validated against the pinned signing key and release policy. Incident response must include signing-key and repository recovery procedures.

No single node may automatically authorize a production update, overwrite evidence, or make a destructive lockout decision based only on its own uncorroborated finding.

## Implementation sequence

1. **Inventory and threat model:** confirm production origin, hosting providers, deployment path, DNS/TLS, current public inventory, runtime attestation options, owner alert channels, and release-key custody.
2. **Release assurance:** broaden CI gates, protect main and release tags, define canonical manifest serialization and anti-rollback metadata, then select and test the signing model.
3. **Verifier prototype:** implement a small read-only verifier with pinned trust roots, manifest validation, public asset inventory/hash checks, freshness checks, signed reports, and adversarial tests.
4. **Independent deployment:** deploy Node 2 and Node 3 on genuinely separate providers and administrative boundaries, each with independent schedules and direct alert paths.
5. **Security event plane:** implement Node 4 as a limited report receiver/correlator with append-only or externally retained evidence and independent notification. Do not make it the sole alert path.
6. **Private host attestation:** only where hosting permits, add a read-only collector for private PHP/configuration integrity. Do not expose private files through a public endpoint.
7. **Adversarial verification:** test tampering, added/deleted files, rollback, invalid/expired signatures, stale manifests, single-node compromise, provider outage, alert-channel failure, and recovery.

## Non-goals and constraints

- This ADR does not authorize DNS changes, production deployment, hosting purchases, or changes to the live SentryIQ runtime.
- It does not move vault data or encryption keys to monitoring providers.
- It does not claim that monitoring prevents a compromised origin from serving malicious code before detection.
- It does not claim external HTTP monitors can inspect private server files.
- It does not require four identical paid VPS instances; provider selection follows the trust boundaries and the actual capabilities of each service.

## Acceptance criteria

- Four documented logical trust domains exist, with two genuinely independent Integrity Nodes.
- Nodes 2 and 3 independently validate the same signed release manifest and live public deployment.
- Compromising Node 1 cannot modify either Integrity Node, their pinned trust roots, schedules, or independent owner alert paths.
- Compromising one Integrity Node does not let it change the other node's verdict or suppress all owner notifications.
- Node 4 outage or compromise does not stop independent verification or all alert delivery.
- Changed, added, missing, and rolled-back public assets are detected with useful evidence.
- Invalid, expired, missing, and rollback manifests fail closed.
- Private PHP/configuration integrity has a defined authenticated read-only attestation path or is explicitly marked out of scope for external HTTP checks.
- Detection latency, alert behaviour, rollback, and residual PWA/browser risk are documented and tested.
