# Phase 1.0 — Repository Dependency Map

**Status:** In progress; initial architecture and high-risk dependency map recorded.  
**Branch:** `docs/device-rooted-security-baseline`  
**Scope:** Repository source, tests, workflows, and configuration only. The owner confirmed no independent nodes were ever provisioned.

## 1. Runtime entrypoint boundary

### Normal application path
- `index.php` loads `security_bootstrap.php`, private vault engine/email template, `auth_flow.php`, and dashboard modules.
- `security_bootstrap.php` loads `app/Security/SecurityBootstrap.php`.
- `app/Security/SecurityBootstrap.php` handles HTTPS/session/security headers, CSRF/authentication, private config loading, vault runtime, and Gallery storage signer loading.
- The inspected normal app entrypoint and security bootstrap do not directly construct or load the legacy A/B/C verifier, Node 4 event runner, or private-host attestation gate.
- This is a source-level finding for the inspected entrypoints, not a claim that every dynamic include path in the repository has been exhaustively traced.

### Legacy verifier execution path
- `bin/integrity-node-run.php` explicitly preloads the A/B/C verifier classes, scheduled runner, Node 4 event runner/client, release-state/evidence stores, Sigstore/release verification classes, and old private-host client/verifier/gate classes. Its private runtime config must return an `IntegrityNodeScheduledRunner`.
- `bin/integrity-node-baseline.php` and `bin/integrity-node-keygen.php` are separate baseline/key-management CLIs. They are repository code only; no baseline or production key was initialised.
- `integrity_event.php` is a separate POST endpoint. It loads Node 4 runtime config, event request decoder, file event store, and two-node event-report verifier. No live external caller exists under the confirmed no-node-provisioned architecture.
- These paths must be redesigned or retired only after replacement contracts and tests exist. Do not infer an active deployment from their presence.

## 2. High-risk legacy dependency clusters

| Cluster | Repository coupling | Disposition for target architecture |
|---|---|---|
| A/B/C verifier classes | `IntegrityNodeA`, `IntegrityNodeB`, `IntegrityNodeC`; A/B require Node 4 event exchange; C has hard-coded `integrity-c` assumptions | Keep as historical/tested code until the single HelioHost verifier replacement is tested; do not deploy unchanged |
| Scheduled runner/binding | Runner accepts A/B/C and optional Node 4 event runner; binding union is A/B/C only | Replace with a single verifier identity/binding after tests; preserve useful lock/anti-rollback behaviour |
| Report signer/evidence | Signer and evidence store include node-specific identity/schema/marker assumptions; evidence store is tied to `integrity-c` | Reuse cryptographic primitives and bounded evidence patterns only after schema and identity redesign |
| Phone/report verifier | `IntegrityReportVerifier` requires exactly two trusted node keys and two approvals | Not reusable as-is for a single verifier; design a new phone-side verifier policy |
| Node key generator | Allows only `integrity-a`, `integrity-b`, `integrity-c`; writes Ed25519 key pair outside webroot | Review safe filesystem/key-publication logic; redesign identity allowlist; never run for production during design |
| Node 4/event plane | Event runner/client, monitor, request decoder, event store, incident correlator, endpoint and report verifier | Not part of the target architecture by default; trace all test/workflow consumers before removal |
| Private-host A/B gate | CLI preloads old client/verifier/gate; collector and request handler are A/B-specific | Do not treat as proof of HelioHost private filesystem inspection; replace only if a qualified host-side read-only mechanism is designed |

## 3. Existing authentication and device-management boundary

- `app/Auth/PasskeyAuth.php` implements WebAuthn registration/authentication and stores passkey credential records in private data storage.
- It wraps the existing 32-byte vault master key using an HKDF-SHA256 key derived from the WebAuthn PRF output and AES-256-GCM. This is a vault-unlock mechanism, not a SentryIQ master-device signing authority.
- The passkey store currently records credential ID, public key, username, wrapped vault key, signature counter, and creation time. The inspected registration path does not issue a master-signed device certificate, global device-registry epoch, scoped device permissions, or master-authorised enrolment/revocation protocol.
- `app/Auth/Passkeys.php` describes adding another passkey/device and retaining at least one credential. That UI is not a master-phone authority ceremony.
- Gallery device management and Gallery recovery are separate scoped mechanisms. Tests explicitly distinguish Gallery device removal from global SentryIQ passkey deletion; Gallery recovery retrieves encrypted envelopes and performs decryption locally. Neither establishes offline authority to replace a lost SentryIQ master phone.
- Reuse candidates: WebAuthn challenge validation, COSE parsing, passkey PRF key wrapping, fresh-auth checks, secure passkey-store locking. Reuse only after threat-model review and separation of vault-unlock from device-authority roles.

## 4. Release and cryptographic building blocks

- Release pipeline and release-manifest tests are generic candidates for reuse; release provenance and trust policy must be checked against the final trust-root design.
- `IntegrityReportSigner` uses Ed25519 detached signatures, but its payload and required evidence markers are coupled to legacy node identity and the old event plane.
- `IntegrityReportVerifier` has a fixed two-node approval policy and must not be mistaken for a generic one-verifier client verifier.
- Existing TUF, Sigstore, release artifact, manifest, and anti-rollback components remain candidate building blocks. Their exact trust roots, workflow identity, expiry, rollback, and update semantics require a separate focused review in Phase 1/2.
- The scheduled runner's exclusive lock, staged-artifact digest recheck, monotonic release state, and evidence retention are promising patterns, but not accepted wholesale.

## 5. Tests and CI coupling

The tracked tree includes dedicated tests for A/B/C, Node 4, private-host attestation, node key generation, scheduled runner, report signing/verification, release provenance, TUF, passkeys, Gallery device management, and Gallery recovery.

The legacy workflow `.github/workflows/integrity-node-tests.yml` and `.github/workflows/native-sigstore-integrity-node.yml` must be migrated to the new verifier contract before legacy tests/classes are removed. `.github/workflows/validate-v012-attestation.yml` and its v0.1.2 fixture retain historical dual-node assumptions and require explicit classification. Generic PHP lint, release manifest tests, release packaging/provenance, TUF patch/root-store, and Gallery security workflows are separate candidates to preserve.

## 6. Confirmed repository findings to carry into design

1. No tracked Composer root manifest was found in the inspected repository tree; native Sigstore/TUF runtime dependency provisioning therefore needs a pinned, reproducible private bundle or a reviewed self-contained alternative.
2. No tracked PWA manifest or service-worker entrypoint was found in the tracked tree inventory. The implementation plan must not assume an existing installable PWA shell.
3. `.htaccess` and PHP currently specify different Referrer-Policy values. Resolve at source/config level and add tests; no live-host probe is applicable.
4. The public HTTP asset strategy cannot by itself prove private PHP/config integrity or detect every unexpected file in a deployed webroot. The target design needs a defensible protected inventory and a qualified read-only inspection boundary.
5. The target HelioHost verifier must not receive master keys, recovery material, DEKs, vault plaintext, device-approval authority, or application write authority.

## 7. Remaining work before Phase 1.0 can be marked complete

- Finish the tracked PHP include/require and dynamic-dispatch sweep across every non-test PHP file, including endpoint, diagnostics, cloud storage, updater, and private-data modules.
- Trace all references to alert/event stores and their consumers outside the legacy CLI/endpoint.
- Inspect every private runtime config template and workflow path filter, including release and historical attestation workflows.
- Record a complete symbol-to-caller/test/workflow matrix for all legacy classes and identify dead/unreferenced files versus test-only references.
- Reconcile this map against the complete repository tree and test results.

No source files have been deleted or changed as part of this map. No production keys, baselines, releases, or deployments have been created.
