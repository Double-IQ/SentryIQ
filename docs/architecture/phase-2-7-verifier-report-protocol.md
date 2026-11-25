# Phase 2.7 — Challenge-bound verifier report protocol

**Status:** Design artifact complete; owner/security review and implementation remain pending.  
**Verifier:** One specialised HelioHost verifier.  
**Relying authority:** Owner's master phone.  
**Target:** https://sentryiq.bichet.co.za  
**Safety:** No verifier key, master key, trust root, endpoint, or production service was created or changed.

## 1. Protocol goals

The HelioHost verifier produces a short-lived signed report that the master's phone can independently validate. A report is not trusted because it is hosted at HelioHost or because the application says it is current. The phone verifies the signature, key identity, challenge, target, release identity, measurement scope, policy, timestamps, and result.

The protocol must provide:
- Challenge binding to a fresh phone-generated nonce.
- Exact binding to the canonical origin and deployment profile.
- Exact binding to the authorised release version, source commit, release sequence, manifest digest, ZIP digest, and release-authorisation record digest.
- A dedicated verifier identity and key ID, separate from all other SentryIQ keys.
- Bounded validity and freshness.
- One-use challenge consumption and replay prevention.
- Explicit distinction between pass, fail, insufficient evidence, and unavailable.
- No secret/user-content disclosure.
- Fail-closed phone acceptance.

A report proves what the verifier measured under its declared policy and trust boundary. It does not prove benign source code, a safe browser/OS, or that the browser executed only measured bytes.

## 2. Protocol objects

The protocol uses three separate objects:
1. **Challenge request** — created by the phone and submitted to the verifier.
2. **Canonical verifier report** — created by the measurement worker and signed by the verifier key.
3. **Detached signature envelope** — carries the verifier key ID, algorithm identifier, and signature over the canonical report bytes.

The signature envelope is not included inside the signed report, avoiding recursive signing. The report is canonical JSON under the Phase 2.2 JCS rules. Unknown critical fields, duplicate JSON keys, invalid UTF-8, and unsupported schema/policy versions are rejected.

## 3. Challenge request

The phone creates:
- A cryptographically random 32-byte nonce.
- A separate random challenge ID with at least 128 bits of entropy.
- The exact target origin and deployment profile.
- The supported report schema and minimum verifier policy version.
- An issue time and a short expiry.
- The current master public key ID used to authenticate the challenge request.

Proposed challenge payload:

```json
{
  "schema": "https://sentryiq.bichet.co.za/security/verifier-challenge/v1",
  "protocol_version": 1,
  "challenge_id": "<random 128-bit-or-stronger identifier>",
  "nonce": "<32-byte random value, canonical base64url>",
  "target_origin": "https://sentryiq.bichet.co.za",
  "deployment_profile": "sentryiq-production-v1",
  "minimum_report_schema": 1,
  "minimum_verifier_policy": "1",
  "issued_at": "<UTC RFC 3339 timestamp>",
  "expires_at": "<UTC RFC 3339 timestamp>",
  "master_key_id": "<currently trusted master public key ID>"
}
```

### 3.1 Challenge authentication

Preferred protocol: the phone signs the canonical challenge payload with its current master-device signing key using a domain-separated challenge-request context. The verifier holds only the current public master key and authority epoch needed to validate the request; it never receives the master private key.

The verifier validates the challenge signature and key status but does not gain device-approval authority. It uses the signature only to authenticate a report request from the enrolled owner phone. The master public key and epoch must be registered through the owner-controlled bootstrap channel; the application host cannot supply or replace them.

If challenge-request authentication cannot be implemented without weakening key custody, the fallback is an unauthenticated nonce-only intake with strict queue bounds, rate limits, and abuse controls. That fallback can cause denial of service but cannot forge a report accepted by the phone. The chosen mode must be explicit in policy; never accept an app-host-generated nonce as a substitute for the phone challenge.

### 3.2 Challenge lifetime and validation

Proposed default challenge lifetime is five minutes, subject to owner/security review. The verifier:
- Rejects expired, future-dated beyond clock tolerance, malformed, duplicate, or previously consumed challenge IDs/nonces.
- Requires the exact canonical origin and an allowlisted deployment profile.
- Accepts only supported report/policy versions.
- Validates the phone signature and current master key status when challenge authentication is enabled.
- Atomically records challenge consumption before producing a report.
- Does not accept caller-supplied file paths, URLs, digests, release versions, or trust roots as authoritative values.

The expected release is selected from the independently verified current release authorisation and deployed measurement, not from a caller-provided version string.

## 4. Canonical verifier report schema

Proposed report payload:

```json
{
  "schema": "https://sentryiq.bichet.co.za/security/verifier-report/v1",
  "report_id": "<random opaque identifier>",
  "report_sequence": "42",
  "verifier": {
    "id": "sentryiq-heliohost-verifier",
    "key_id": "<pinned verifier key ID>",
    "policy_version": "1",
    "build_digest": "<verifier software/policy build SHA-256>"
  },
  "challenge": {
    "challenge_id": "<exact request challenge ID>",
    "nonce": "<exact request nonce>",
    "master_key_id": "<requesting master key ID>",
    "issued_at": "<phone challenge issue time>",
    "expires_at": "<phone challenge expiry>"
  },
  "target": {
    "origin": "https://sentryiq.bichet.co.za",
    "deployment_profile": "sentryiq-production-v1"
  },
  "release": {
    "version": "1.3.0",
    "release_sequence": "3",
    "source_commit": "<40-character Git SHA>",
    "manifest_sha256": "<64-character SHA-256>",
    "zip_sha256": "<64-character SHA-256>",
    "authorisation_sha256": "<64-character SHA-256>"
  },
  "measurement": {
    "started_at": "<UTC RFC 3339 timestamp>",
    "completed_at": "<UTC RFC 3339 timestamp>",
    "issued_at": "<UTC RFC 3339 timestamp>",
    "expires_at": "<UTC RFC 3339 timestamp>",
    "result": "pass",
    "public_http": {},
    "private_runtime": {},
    "unexpected_surface": {},
    "failure_codes": []
  }
}
```

The example is illustrative. The final schema must define exact types, bounds, required fields, enums, canonical timestamp rules, and closed-object behaviour. Identifiers and 64-bit counters are represented as canonical decimal strings where cross-language integer precision could otherwise be lost.

### 4.1 Verifier identity

The report identifies:
- Stable verifier service ID.
- Active verifier key ID pinned by the phone.
- Report schema and verifier policy versions.
- Verifier software/policy build digest.
- Report sequence for this verifier identity.

A key ID must never be reused. The verifier cannot choose or introduce its own trust key; Phase 2.3 controls pinning and rotation.

### 4.2 Release binding

The report must bind the exact:
- Release version.
- Owner-authorised monotonic release sequence.
- Source commit.
- Canonical manifest digest.
- Release ZIP digest.
- Detached release-authorisation record digest.

These values are derived from independently verified release evidence and the actual measured deployment. A value supplied only by the application host or challenge request is not trusted.

### 4.3 Public HTTP result

The public_http section records:
- HTTP measurement policy/profile version.
- Expected, measured, failed, and unmeasurable asset counts.
- Per-asset logical path/ID, expected and observed digest/size, status, media type, content encoding, cache/variant result, and stable failure code.
- Redirect count (zero under the initial policy).
- Required response-header profile and result.
- Dynamic entrypoint reference validation result.
- Explicit statement that HTTP-only checks cannot enumerate arbitrary unknown webroot paths.

It does not contain response bodies, cookies, query strings, session data, or unfiltered response headers.

### 4.4 Private runtime result

The private_runtime section records:
- Inspection assurance level: HTTP-only, account-level read-only file service, provider-controlled snapshot, or a separately approved stronger mechanism.
- Source channel and snapshot ID where applicable.
- Number of required files measured, failed, and unavailable.
- Logical path IDs, expected/observed digests, size and permission result for release-managed files.
- Directory enumeration outcome for approved code roots.
- Configuration metadata-only checks and explicit exclusions.
- Whether the channel can resist a privileged application-host attacker.

It never includes private file contents, secret values, raw private paths beyond approved logical identifiers, or secret-derived hashes.

If private inspection is required by policy but unavailable, the overall result cannot be pass.

### 4.5 Unexpected surface

The report distinguishes:
- No unexpected item found within a fully enumerated approved scope.
- Unexpected executable/code file or resource reference found.
- Scope could not be enumerated.
- A particular root or route was not measured.

It must never say "no unexpected files exist" when only manifest-listed public URLs were fetched.

## 5. Result taxonomy

The overall result is one of:

| Result | Meaning | Phone behaviour |
|---|---|---|
| pass | Every required evidence class was measured and matched active policy | May proceed only if all other phone-side gates also pass |
| fail | A digest, signature, policy, release, path, header, freshness, or security check failed | Deny and surface a security failure |
| insufficient_evidence | A required evidence class was unavailable, partial, unenumerated, or below required assurance | Deny; do not downgrade to warning |
| unavailable | Verifier, origin, trust metadata, or required dependency was unreachable or the run could not complete | Deny operations requiring fresh verification |

A report may include detailed sub-statuses, but the top-level result cannot be pass if any required check is missing, failed, stale, or below the configured assurance level.

Failure codes are stable machine-readable identifiers. They are bounded in count and length, contain no stack traces or secrets, and are suitable for a phone UI and audit log.

## 6. Detached signature envelope

The report is canonicalised under the agreed JCS profile. The signature is computed over a domain-separated message:

```text
"SentryIQ/VerifierReport/v1" || 0x00 || JCS(report)
```

Proposed detached envelope:

```json
{
  "schema": "https://sentryiq.bichet.co.za/security/signature-envelope/v1",
  "purpose": "verifier-report",
  "algorithm": "<approved signature algorithm identifier>",
  "key_id": "<pinned verifier key ID>",
  "report_sha256": "<SHA-256 of canonical report bytes>",
  "signature": "<canonical base64url signature bytes>"
}
```

The signature algorithm is selected only after owner/security approval and platform interoperability testing. Ed25519 is a Phase 1 candidate, not an instruction to generate or provision a key now.

The verifier stores and serves the exact canonical report bytes and detached signature. The report digest is computed over canonical report bytes, not a pretty-printed representation. The phone rejects a signature envelope whose purpose, algorithm, key ID, digest, or schema is unexpected.

## 7. Freshness and expiry

Proposed defaults, subject to owner/security review:
- Challenge validity: at most five minutes from phone issue time.
- Measurement completion must occur after the challenge issue time and before challenge expiry.
- Report expiry: no more than five minutes after report issuance.
- Phone acceptance requires report issuance and measurement completion within the phone's current freshness window.
- The phone rejects a report if its current time is before issue time beyond defined clock tolerance or after expiry.
- A verifier report is never extended by re-serving it or re-signing old measurements.

The phone validates the time relationship:
1. challenge issued_at <= measurement.started_at
2. measurement.started_at <= measurement.completed_at
3. measurement.completed_at <= measurement.issued_at
4. measurement.issued_at < measurement.expires_at
5. challenge.expires_at >= measurement.completed_at
6. report lifetime <= policy maximum

The trusted-time and clock-skew policy must be reviewed with the supported phone platform. If time cannot be established within the allowed tolerance, the phone fails closed for operations requiring fresh evidence.

## 8. Replay prevention and monotonic state

Two independent protections are required:

### 8.1 One-use challenge
- Verifier stores challenge ID and nonce in durable private state.
- Consumption is atomic and occurs once.
- Duplicate request, duplicate nonce, expired challenge, or reused challenge ID is rejected.
- Completed report is immutable; it cannot be replaced with a different result under the same challenge.
- Phone records accepted challenge IDs/nonces and rejects any previously consumed report.

### 8.2 Monotonic report and release state
- Verifier maintains a strictly increasing report_sequence for its key identity.
- Phone stores the highest accepted report_sequence for that verifier identity and rejects lower or equal sequence values.
- Phone stores the highest accepted release_sequence and exact accepted release digests.
- A release rollback requires a separate owner-signed rollback statement naming the exact previous version, manifest digest, ZIP digest, and permitted transition.
- Verifier state is protected from public handler writes and concurrent worker races.
- State loss, backup restore, or sequence rollback does not reset the phone's high-water marks; it requires an explicit recovery/re-pinning process.

A report with a fresh nonce but an old release sequence is still a rollback and must be rejected.

## 9. Phone-side verification algorithm

The master phone accepts a report only after all of the following checks pass:

1. Parse strict schema; reject duplicate keys, unknown critical fields, invalid types, and non-canonical serialization.
2. Reconstruct canonical report bytes and verify report_sha256.
3. Confirm the verifier ID, key ID, algorithm, and purpose are currently pinned and not expired/revoked.
4. Verify the detached signature over the exact domain-separated canonical report bytes.
5. Match challenge ID, nonce, target origin, deployment profile, and master key ID to the phone's outstanding request.
6. Confirm the challenge has not expired or already been consumed.
7. Validate issue, completion, expiry, and clock-skew relationships.
8. Match release version, source commit, release sequence, manifest digest, ZIP digest, and authorisation digest to independently verified release evidence.
9. Confirm report policy version meets the phone's minimum policy and trust-store sequence.
10. Confirm every required public asset and response-header check is measured and passes.
11. Confirm private runtime assurance level meets the active owner policy; unavailable evidence cannot pass.
12. Confirm unexpected surface checks are complete for the required scope.
13. Confirm result is exactly pass and failure_codes is empty.
14. Confirm report_sequence and release_sequence are not lower than phone-held high-water marks.
15. Atomically persist accepted report digest, report sequence, release sequence, challenge consumption, and acceptance time before enabling the gated operation.

A successful signature alone is never sufficient. A signed fail, insufficient_evidence, or unavailable report is still a denial.

## 10. Transport and endpoint rules

- Phone submits the challenge to the verifier's fixed HTTPS origin using certificate/hostname validation.
- Request and report retrieval use bounded body sizes, strict content types, rate limits, and no redirects by default.
- Challenge submission returns only an opaque request/report identifier and status; it does not return private files or verifier key material.
- Report retrieval returns canonical report bytes and detached signature only.
- Report endpoints do not expose private filesystem paths, internal stack traces, configuration, secrets, or raw measurement response bodies.
- The application host is not a report relay authority. It may display the signed result but cannot change it.
- If report delivery is unavailable, the phone does not accept a cached prior report as current.

## 11. Outage, partial evidence, and alert semantics

- Origin outage, verifier outage, trust metadata outage, scheduler delay, worker lock contention, dependency failure, or incomplete private measurement produces unavailable or insufficient_evidence.
- A mismatch produces fail.
- No previous pass report is reused for a new challenge.
- Alert delivery is independent and is not part of the signature trust chain. A failed alert cannot convert a failure to a pass.
- The phone shows the exact result category and reason code; no green/approved UI is displayed for partial evidence.
- The verifier retains bounded signed evidence for audit, with a reviewed retention policy and no user content or secrets.
- A recovery/override action must be a separate owner-visible ceremony; it cannot be a hidden server flag or an operator-set boolean.

## 12. Required protocol tests

1. Valid challenge, exact release, current key, complete measurements, fresh pass report is accepted.
2. Wrong verifier key ID, revoked key, wrong algorithm, wrong purpose, altered report byte, wrong digest, and invalid signature are rejected.
3. Wrong challenge ID/nonce, expired challenge, duplicate challenge, replayed report, and already consumed report are rejected.
4. Wrong origin, deployment profile, release version, source commit, release sequence, manifest digest, ZIP digest, or authorisation digest is rejected.
5. Expired report, future-dated report, invalid timestamp ordering, excessive clock skew, and excessive lifetime are rejected.
6. Lower/equal report sequence, lower release sequence, changed release digest under same version, and unauthorised rollback are rejected.
7. Pass with missing required asset, incomplete private runtime, or unenumerated required directory is rejected.
8. fail, insufficient_evidence, and unavailable are never accepted as pass.
9. Unknown critical schema fields, duplicate JSON keys, invalid UTF-8, and non-canonical base64url are rejected.
10. Challenge queue race, duplicate worker, process crash, report-store tamper, and state rollback cannot produce two conflicting successful reports.
11. Report contains no secrets, private config values, file contents, cookies, session IDs, or raw private filesystem paths.
12. Report endpoint cannot sign, replace, or modify a completed report.

## 13. Completion and next step

Phase 2.7 is complete as a protocol design. It defines challenge request, canonical report schema, detached signature envelope, release/target binding, result taxonomy, freshness, replay prevention, monotonic state, phone-side verification, transport rules, and outage semantics.

Next: Phase 2.8 defines the phone-side verification gate and fail-closed behaviour before sensitive operations. This design does not authorise a native companion implementation, trust-root bootstrap, key generation, verifier deployment, or production activation.
