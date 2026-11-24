# Phase 2.2 — Canonical signed release manifest and inventory design

**Status:** Design artifact complete; owner/security review and implementation gates remain open.  
**Application:** `https://sentryiq.bichet.co.za`  
**Repository:** `Double-IQ/SentryIQ` (ID `1345956206`)  
**Independent verifier:** One specialised HelioHost verifier.  
**Master authority:** Owner's phone; release verification is a separate authority domain.

## 1. Purpose and design decision

The existing format-2 manifest is a useful deterministic inventory of the files inside a release ZIP. It is not a complete description of the deployed application, it is not self-authenticating, and it does not establish owner approval or deployment state.

Adopt a versioned **format-3 canonical release inventory** with two deliberately separate layers:

1. **Canonical inventory manifest** — describes the exact source/build identity, package file set, public browser-delivery assets, private server-runtime code, dependency bundles, and deployment policy. The same canonical manifest bytes are embedded in the ZIP and published as the external `release-manifest.json`.
2. **Detached release-authorisation record** — separately approves the exact manifest digest and ZIP digest, version, source commit, and monotonic release sequence. Its signature is verified independently of GitHub build provenance. It is not embedded in the manifest, avoiding a digest/signature recursion and preventing build provenance from being mistaken for owner approval.

GitHub/Sigstore build provenance remains a third, separate evidence object. The HelioHost verifier report and master-phone acceptance remain separate later trust layers. No key may be reused between release authorisation, GitHub provenance/TUF, HelioHost reports, master-device authority, device identity, or content encryption.

**No cryptographic suite or release-authorisation key custody is approved by this design.** The existing Phase 1 cryptographic profile and key-role separation remain authoritative; Phase 2.3 must settle trust-root distribution and rotation before implementation or key creation.

## 2. Format-3 manifest structure

The manifest is UTF-8 JSON using a closed, versioned schema. The proposed top-level structure is:

```json
{
  "schema": "https://sentryiq.bichet.co.za/security/release-manifest/v3",
  "format": 3,
  "release": {
    "version": "1.3.0",
    "source_ref": "refs/tags/v1.3.0",
    "source_commit": "<40-character Git commit SHA>",
    "repository": "Double-IQ/SentryIQ",
    "repository_id": "1345956206",
    "workflow_path": ".github/workflows/release.yml",
    "workflow_commit": "<40-character workflow definition SHA>"
  },
  "build": {
    "builder_id": "github-actions:Double-IQ/SentryIQ/.github/workflows/release.yml",
    "run_id": "<GitHub Actions run identifier>",
    "run_attempt": 1,
    "event": "push",
    "runner_class": "github-hosted"
  },
  "inventory": {
    "algorithm": "sha256",
    "files": [],
    "http_assets": [],
    "dependency_bundles": [],
    "runtime_policy": {}
  },
  "policy": {
    "deployment_profile": "sentryiq-production-v1",
    "minimum_verifier_policy": "1",
    "required_headers_profile": "sentryiq-web-security-v1"
  }
}
```

Values above are illustrative. The final schema must define exact field types, lengths, enumerations, required/optional fields, closed-object behaviour, and compatibility rules. Identifiers such as run IDs are strings where preserving exact external representation matters. No secrets, private keys, tokens, user data, or host-specific credential values belong in the manifest.

### 2.1 Canonical serialization

Before hashing or signing:
- Encode as UTF-8 without BOM; reject invalid UTF-8 and duplicate JSON member names.
- Use RFC 8785 JSON Canonicalization Scheme (JCS) as the canonical byte representation. Existing Python `json.dumps(sort_keys=True)` output is deterministic for its current inputs but is not declared to be RFC 8785; it must not silently be treated as interchangeable.
- Reject non-finite numbers, floats where integers are required, negative values where prohibited, unknown fields in closed objects, invalid Unicode, and non-canonical path encodings.
- Use lowercase hexadecimal SHA-256 digests and explicit algorithm identifiers.
- Canonicalize first, then compute the manifest SHA-256. Sign the exact canonical bytes or an explicitly domain-separated envelope containing that digest.
- The embedded manifest and external `release-manifest.json` must be byte-identical after canonicalization. CI must compare their exact bytes.

The manifest does not contain its own digest, the ZIP digest, or its own signature. Those values belong in the detached release-authorisation record.

### 2.2 Release identity

The manifest binds:
- Canonical repository name and immutable repository ID.
- Stable release version and exact `refs/tags/vX.Y.Z` source ref.
- Full immutable source commit SHA.
- Reviewed release workflow path and the workflow definition commit authenticated by GitHub/Sigstore provenance.
- Build run ID and attempt, event type, builder identity, and declared runner class.
- A deployment-profile identifier and minimum policy versions.

The verifier must not trust identity fields merely because they appear in JSON. It cross-checks them against the independently verified GitHub/Sigstore attestation and separately signed release authorisation.

### 2.3 File inventory entries

Every file delivered by the release package is listed exactly once. Proposed fields:

| Field | Meaning |
|---|---|
| `path` | Canonical package-relative POSIX path |
| `class` | `public_asset`, `application_code`, `private_runtime`, or `dependency` |
| `size` | Exact byte length as a non-negative integer |
| `sha256` | SHA-256 of exact packaged bytes |
| `deploy_target` | Approved logical destination such as public webroot or private runtime |
| `media_type` | Expected MIME type where relevant |
| `mode` | Expected permission profile, not arbitrary executable permission |
| `required` | Whether absence must fail verification |

Path rules:
- Relative paths only; POSIX separators; no leading slash, drive prefix, backslash, NUL, control character, empty segment, `.`, or `..`.
- Reject symlinks and unsupported special files; reject duplicate paths and case-fold collisions.
- Reject encoded/ambiguous path aliases and percent-encoded separators in HTTP path mappings.
- No file may be silently omitted from the package inventory. The verifier compares the actual package path set with the complete manifest path set.

### 2.4 Public HTTP asset inventory

The format must explicitly identify browser-delivered assets, rather than assuming every non-runtime package file is a public URL.

Each `http_assets` entry binds:
- Exact origin-relative URL path.
- Corresponding package file path/identifier.
- Expected SHA-256 and byte length, matching the file inventory entry.
- Expected content type and allowed content-encoding behaviour.
- Cache policy class (for example, content-addressed immutable asset or revalidated entrypoint).
- Whether the path is required, and whether redirects are forbidden (default: forbidden).
- Whether the asset is security-critical and must be checked before a client accepts the release.

Coverage includes, when present:
- HTML entrypoints and static HTML documents.
- JavaScript modules/bundles and WASM.
- CSS and imported stylesheets.
- PWA web manifest.
- Icons, screenshots, and install metadata.
- Service-worker script and any workbox/precache manifest.
- Fonts and other first-party resources loaded by security-sensitive pages.

The repository audit found no tracked PWA manifest, service-worker entrypoint, or registration in the audited browser scripts. The format must therefore support these fields without claiming they currently exist. Their absence is recorded as a deployment/design gap until the PWA shell is actually implemented and audited.

Dynamic HTML responses need special treatment. If an entrypoint injects per-request nonces, CSRF tokens, session state, or other dynamic values, the verifier must not compare the entire response body with a static file digest. Instead, the manifest inventories the server-side template/code file and declares the route's expected asset references and response-header policy. Static HTML can be measured byte-for-byte. Phase 2.5 defines exact live-response checks.

Security-critical JavaScript/WASM should be self-hosted. Any unavoidable third-party runtime dependency must be explicitly declared with immutable URL/version, expected digest, and policy; an unpinned CDN resource is not acceptable for a key-handling page.

### 2.5 Private server-runtime inventory

The manifest also lists the exact release-managed server-side code that is deployed outside the public webroot, including the current runtime templates moved into `runtime/` by the package builder.

Each private runtime entry binds:
- Logical private path relative to the qualified private data root.
- File digest and byte length.
- Required permission profile and regular-file/no-symlink expectation.
- Runtime class and whether the verifier can inspect it on the qualified host.

The inventory must not include secret values or hash secret-bearing configuration contents. Host-specific configuration, database credentials, API tokens, session secrets, private keys, verifier keys, user data, ciphertext objects, logs, caches, temporary files, and mutable operational state are excluded from release-managed code inventory.

Instead, a separate **runtime configuration policy** describes non-secret properties the host verifier can safely check: required configuration file presence, schema/version, path outside webroot, owner/permission constraints, and required key names without values. The verifier must never return config contents or secret-derived digests that could enable offline guessing.

The target design requires HelioHost to inspect selected private files through a read-only isolated boundary. If host permissions cannot establish genuine independence from the application process, the report must say that private runtime inspection is unavailable; it must not infer private integrity from public HTTP hashes.

### 2.6 Dependency bundles

Private native Sigstore/TUF dependencies and any future runtime dependencies are first-class inventory objects:
- Package name, exact version, upstream source/commit, package digest, lockfile digest, and patch-set digest.
- Provenance or verified source for the dependency bundle.
- Exact installation path outside the webroot.
- Expected autoloader and required file list.
- No mutable floating version or unpinned branch.
- A patch to an upstream dependency is a separately inventoried input with exact upstream commit and patch digest.

The current CI-generated private verifier ZIP is only a short-retention Actions artifact. Format 3 must support a reproducible, independently digest-bound dependency bundle, but it must not imply that production has installed it.

## 3. Detached release authorisation

A separate canonical release-authorisation object is required. Proposed payload:

```json
{
  "schema": "https://sentryiq.bichet.co.za/security/release-authorisation/v1",
  "release_version": "1.3.0",
  "source_commit": "<40-character Git commit SHA>",
  "manifest_sha256": "<64-character SHA-256>",
  "zip_sha256": "<64-character SHA-256>",
  "release_sequence": "3",
  "policy_version": "1",
  "authorisation_key_id": "<immutable public key identifier>",
  "issued_at": "<UTC RFC 3339 timestamp>",
  "expires_at": "<UTC RFC 3339 timestamp>"
}
```

The detached signature is over the exact canonical payload with a domain-separation label such as `SentryIQ/ReleaseAuthorisation/v1`. The signature envelope identifies the algorithm and key ID and carries the signature bytes. The chosen algorithm and key custody must follow the reviewed Phase 1 profile and Phase 2.3 bootstrap/rotation procedure; do not invent a production key or use the master-device, HelioHost, device, or TUF root key.

Required checks:
- Manifest digest, ZIP digest, version, and source commit all match the actual release objects and verified provenance.
- Key ID is trusted through a separately bootstrapped release-authorisation trust root.
- Signature, policy version, validity interval, release sequence, and revocation state validate.
- Duplicate authorisations, stale policy, sequence rollback, and mismatched subject bindings fail closed.
- Re-authorising a different ZIP or manifest for the same version requires an explicit new sequence and audit trail; a mutable GitHub Release asset cannot silently inherit the old approval.
- Emergency rollback is a separate signed owner action naming the exact prior version and digests. It does not lower the general monotonic sequence.

The application host must not be able to mint this authorisation. The exact human approval workflow and key custody are Phase 2.3 decisions.

## 4. Independent evidence objects — never conflate them

| Evidence object | What it proves | What it does not prove |
|---|---|---|
| GitHub/Sigstore build attestation | Repository, workflow, source/build identity and artifact subject digest under GitHub/Sigstore policy | Owner approval, benign source, deployed bytes, browser execution |
| Format-3 canonical inventory | Declared package files, public URL mappings, private runtime code and dependency identities | Authenticity until its digest is authorised; actual deployed state |
| Detached release authorisation | A separately trusted authority approved exact manifest/ZIP digests and release sequence | That the host deployed those bytes or that code is benign |
| HelioHost signed verifier report | Independently measured bytes/policy at a particular time and challenge | Browser/OS integrity, benign code, owner acceptance |
| Master-phone acceptance state | Owner's device accepted exact release and verifier evidence under pinned trust roots | Safety against a compromised phone/OS or malicious approved code |

No evidence object may substitute for another. A sidecar checksum is transfer-integrity metadata only.

## 5. Deployment and measurement contract

The package inventory and the live deployment inventory are related but distinct:
- The package inventory describes exact release inputs.
- The deployment profile maps each package path to its expected public or private target.
- The verifier measures actual public HTTP response bytes and qualified private runtime files.
- The verifier also enumerates the allowed deployment surface and reports unexpected files or routes according to a reviewed allowlist policy.
- Missing required assets, unexpected executable files, ambiguous URL aliases, digest/length mismatch, disallowed redirects, wrong MIME types, unsafe cache headers, or policy-header mismatch fail the relevant measurement.
- Public HTTP measurement cannot enumerate arbitrary private webroot contents or prove private PHP/config integrity.
- A release cannot be declared fully measured if the host cannot expose a safe, independent private-file inspection path; report a scoped result with that limitation and fail any policy that requires the missing evidence.

The manifest does not declare every live header value as a file digest. It references a versioned response-header policy profile, whose exact requirements are defined and tested in Phase 2.5.

## 6. Versioning and migration

- Format 2 remains a legacy accepted format only for historical releases and compatibility tests.
- New releases after implementation must use format 3; no silent format downgrade.
- Verifiers reject unknown major formats, unknown required fields, unsupported algorithms, and weaker policy profiles.
- Format-3 schema changes require a new schema version or explicitly compatible minor revision with tests.
- The ZIP embeds the canonical format-3 manifest. The external manifest is byte-identical. Both are independently attested as GitHub provenance subjects.
- The detached authorisation record binds the exact external manifest and ZIP digests. Its signature does not appear inside either subject.
- The updater verifies provenance, release authorisation, package inventory, dependency bundle, and anti-rollback before any extraction or replacement.
- HelioHost obtains the authorisation and manifest from a trust source not controlled solely by the application host, then measures the deployment.
- The phone verifies all signatures and evidence bindings against pinned trust roots and current policy.

## 7. Required tests before implementation acceptance

1. Canonicalization is stable across supported PHP/Python/phone implementations and produces byte-identical manifest output.
2. Duplicate JSON keys, invalid UTF-8, unknown critical fields, invalid types, float coercion, and non-canonical encoding are rejected.
3. Path traversal, encoded traversal, case collisions, duplicate paths, symlinks, special files, and unlisted extra package files are rejected.
4. Every file digest/size and every HTTP mapping must match the corresponding inventory entry.
5. Dynamic entrypoint templates are distinguished from static response assets; nonce/CSRF/session values are not mistaken for static hashes.
6. A missing or unexpected JS/CSS/WASM/PWA/service-worker/icon asset fails the configured release policy.
7. External manifest and ZIP-embedded manifest must be byte-identical.
8. Build provenance with wrong repository, repo ID, workflow path/commit, ref, event, source commit, or subject digest is rejected.
9. Release authorisation with wrong key, signature, manifest digest, ZIP digest, version, sequence, validity, or policy version is rejected.
10. A valid GitHub attestation without release authorisation is rejected.
11. A valid manifest/authorisation without a fresh HelioHost report is rejected by the later phone gate.
12. Mutable replacement of a GitHub Release asset after authorisation is detected by digest mismatch.
13. An approved rollback is accepted only with the separate exact-digest owner rollback statement.
14. Runtime secret/config files are excluded without leaking values or derived hashes; private code files remain covered.
15. Dependency bundle and patch digests are pinned; missing, changed, or untrusted private dependencies fail closed.

## 8. Phase 2.2 completion and remaining decisions

This artifact completes Phase 2.2 as a design proposal. It does not authorise code changes, schema rollout, release publication, key generation, trust-root bootstrap, or production deployment.

Required owner/security review before implementation:
- Confirm the proposed format-3 schema and canonicalization profile.
- Confirm which exact public browser assets and routes are release-critical.
- Confirm the host-side private runtime inspection boundary and exclusions.
- Resolve release-authorisation key custody, human approval ceremony, bootstrap, rotation, revocation, and emergency rollback in Phase 2.3.
- Confirm the minimum supported verifier policy and migration window for historical format-2 releases.

**Next planned item: Phase 2.3 — design independent trust-root distribution, release-authorisation key custody, bootstrap, rotation, emergency revocation, and phone-side pinning.** No key generation is part of that design task.
