# BTM-SA / Integrity Node 4 report contract

- **Status:** Implementation specification
- **Date:** 2026-11-17
- **Deployment mapping:** BTM-SA is Node 4 and runs on the same host as the SentryIQ application.
- **Related:** `docs/adr/2026-11-08-four-node-resilience-architecture.md`

## Purpose and trust boundary

BTM-SA receives signed reports from Integrity Nodes A and B, verifies each report independently, prevents replay, retains evidence, correlates node results, and sends an additional owner notification.

BTM-SA is a separate logical service but shares the SentryIQ host. It is **not** an independent infrastructure failure domain. A host-level outage or administrator compromise can affect both SentryIQ and BTM-SA. Nodes A and B remain the independent monitors and must retain direct owner-alert paths that do not depend on BTM-SA.

BTM-SA is not a release authority. It must not approve updates, change node trust roots, rewrite reports, or suppress direct alerts from A or B.

## Report format

Node A and Node B emit a detached Ed25519 envelope:

```json
{
  "payload": "<base64 of exact UTF-8 JSON payload bytes>",
  "signature": "<base64 Ed25519 detached signature>"
}
```

The signature covers the exact decoded payload bytes. BTM-SA must verify those bytes directly; it must not decode and re-encode JSON before signature verification.

For Node 4 ingestion, require `schema_version: 2`. Version 2 binds the following fields inside the node signature:

- `node_id`, `decision`, `issued_at`, `expires_at`, `nonce`
- `repository`, immutable `repository_id`, `release_version`, `tag`, `commit`, `artifact_sha256`, `workflow_path`
- `target_origin`, `manifest_sha256`, `checked_paths`, `mismatches`

Version 1 reports remain supported by the updater's existing two-node release verifier for compatibility, but they are insufficient for Node 4 evidence ingestion because they do not cryptographically bind the target origin or file-check evidence.

## Challenge and report API

The following paths are a logical API contract; concrete routing may follow the existing BTM-SA application conventions.

### 1. Issue a challenge

`POST /api/integrity/v1/challenges`

Authenticate the caller as exactly one configured node identity. Use separate credentials for A and B; never use a shared master token. Prefer mutual TLS where the host and providers support it. If bearer credentials are used, store only verifiable hashes, scope each credential to one node, and support independent rotation.

Request body:

```json
{
  "target_origin": "https://sentryiq.bichet.co.za",
  "repository_id": "1345956206",
  "release_version": "0.1.3",
  "tag": "v0.1.3",
  "commit": "<40-character Git SHA>",
  "artifact_sha256": "<64-character SHA-256>"
}
```

BTM-SA must validate the canonical repository identity, HTTPS origin, version/tag relationship, commit and digest formats. It generates 32 cryptographically random bytes and stores the challenge bound to the authenticated node identity and every request field. Return the nonce as 64 lowercase hexadecimal characters and an expiry no longer than five minutes.

Challenge response:

```json
{
  "schema_version": 1,
  "node_id": "integrity-a",
  "nonce": "<64 lowercase hex characters>",
  "issued_at": 1794200000,
  "expires_at": 1794200300
}
```

The nonce is node-specific, single-use, short-lived, and unpredictable. A challenge must not be reusable for another target, release, node, or artifact.

### 2. Submit a signed report

`POST /api/integrity/v1/reports`

The request body is the signed envelope emitted by the node. Do not accept caller-supplied unsigned metadata as authoritative.

BTM-SA must:

1. Enforce a small request-body limit before JSON parsing.
2. Strictly decode the envelope and base64 fields.
3. Read `node_id` from the signed payload and select only that node's pinned Ed25519 public key.
4. Verify the detached signature over the exact decoded payload bytes.
5. Require schema version 2, a known node identity, canonical repository identity and workflow path, valid decision, valid timestamps, and an unexpired report.
6. Validate `target_origin`, `manifest_sha256`, checked paths, and mismatch records. Reject traversal paths, absolute paths, backslashes, query/fragment delimiters, control characters, duplicates, oversized arrays, and unknown mismatch reasons.
7. Match the signed node, nonce, target origin, repository, version, tag, commit, and artifact digest against the stored challenge.
8. Atomically consume the nonce and persist the accepted report in one database transaction. The consume operation must succeed only once under concurrent submissions.
9. Return the stored report identifier and accepted timestamp. Duplicate, expired, unknown, or mismatched challenges fail closed.

Do not use the existing `IntegrityReportVerifier::assertTwoNodeApproval()` as the event-ingestion verifier. That class intentionally requires exactly two approvals for an update decision. Node 4 must authenticate one report at a time, including signed rejections, and must be able to record missing, stale, or unavailable peers.

## Persistence and replay protection

Use a transactional store supported by the actual BTM-SA host runtime. The storage implementation must provide:

- Unique nonce records with node identity, target/release binding, issue/expiry times, and a consumed marker.
- An atomic conditional consume operation (`consumed_at IS NULL AND expires_at > now`) so concurrent replay attempts cannot both succeed.
- Unique report identifiers and immutable accepted report records.
- Retention timestamps and bounded evidence size.
- A transaction covering nonce consumption and report persistence, so a crash cannot consume a challenge while losing its report.

Do not assume SQLite, MySQL, or a filesystem path until the BTM-SA runtime is inspected. Keep storage behind a narrow interface so the service can use the database already supported by the host.

Retain the exact signed envelope and its decoded signed payload. Never retain credentials, cookies, vault content, user data, or private keys. Evidence on the shared host is not tamper-proof against host administrators; where available, export a hash-chained evidence digest or immutable copy to storage outside the SentryIQ host.

## Correlation and incident classes

Correlate independently accepted reports by target origin and release identity, using configured freshness windows rather than requiring A and B to run at the same instant.

At minimum, BTM-SA must distinguish:

- `verified`: both fresh nodes agree on the target and release, with no mismatch.
- `confirmed_mismatch`: a signed node report records a public file mismatch.
- `node_disagreement`: fresh reports disagree on release identity or result.
- `stale_node`: a node has not reported within its configured freshness window.
- `target_unavailable`: a node reports fetch failure or cannot reach the target.
- `invalid_or_replayed_report`: signature, challenge, expiry, identity, or replay validation fails.
- `verifier_failure`: a node reports that its own verification could not complete.

Do not infer that an absent report means the target is healthy. Do not treat one report as a two-node consensus. A signed rejection is evidence and must be retained, not discarded.

## Notifications and failure handling

- BTM-SA sends an additional owner notification for confirmed mismatches, node disagreement, stale/missing nodes, and repeated verifier/target failures.
- Nodes A and B continue to notify the owner directly through their own independent alert credentials and destinations.
- BTM-SA cannot edit, disable, or proxy those direct alert paths.
- A BTM-SA process outage must not stop A/B checks or direct alerts.
- A host-level outage or compromise can affect both SentryIQ and BTM-SA; the independent nodes must detect and report that condition.
- Never lock users out, roll back production, or authorize an update based solely on one unverified report.

## Shared-host hardening

Because BTM-SA and SentryIQ share a host, separate them at the strongest level the host permits:

- Separate OS/PHP-FPM identities or equivalent process users.
- Separate private configuration and data directories with restrictive ownership and permissions.
- Separate database credentials and least-privilege grants.
- No SentryIQ application write access to BTM-SA code, trust keys, challenge store, evidence store, or alert credentials.
- BTM-SA has no access to vault data or application secrets.
- No public directory contains private keys, bearer tokens, raw evidence stores, or database files.
- BTM-SA may read only the public release identity and approved report inputs it needs.
- Host administrator/root compromise remains a common-mode risk and must be documented, not hidden by the logical node numbering.

## Acceptance tests

Before enabling the service:

1. A valid Node A v2 report is accepted and stored.
2. A valid Node B v2 report is accepted and stored independently.
3. A forged signature, unknown node, altered payload, wrong target, wrong release, wrong artifact, or wrong manifest digest is rejected.
4. An expired, unknown, already consumed, or concurrently replayed nonce is rejected.
5. A signed rejection and its mismatch evidence are retained and trigger the correct incident class.
6. A report with unsafe paths, oversized evidence, malformed JSON, or unknown fields/reasons is rejected.
7. One missing node becomes stale without suppressing the other node's result.
8. BTM-SA process failure does not prevent A/B direct alerts.
9. Shared-host outage is detected by A/B and does not produce a false claim that Node 4 survived.
10. Evidence records can be exported and verified without exposing secrets.

No deployment, DNS, hosting, or production runtime change is authorized by this specification.
