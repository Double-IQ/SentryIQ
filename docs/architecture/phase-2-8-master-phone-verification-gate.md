# Phase 2.8 — Master-phone verification gate and fail-closed operation policy

**Status:** Design artifact complete; owner decision on native companion and implementation remain pending.  
**Master authority:** Owner's phone.  
**Application:** https://sentryiq.bichet.co.za  
**Independent verifier:** One specialised HelioHost verifier.  
**Safety:** No phone application, key, trust root, production gate, or deployment was created or changed.

## 1. Purpose and central decision

The master phone must independently verify release authorisation and a fresh HelioHost report before allowing operations that depend on the integrity of the SentryIQ application or its security state.

A PHP response, PWA boolean, database row, cached badge, or message supplied only by the application host is not proof. The phone verifies signatures and policy locally using trust roots pinned during the deliberate bootstrap ceremony.

**High-assurance master operations require a trusted native companion or an equivalently isolated phone-side component.** A PWA-only page cannot claim hardware-backed master-key custody or reliably protect its own verification UI from malicious same-origin JavaScript. The Phase 1.10 owner decision on adopting a native companion remains open; this design records the gate requirement but does not silently make that product decision.

A release/verifier pass is necessary but not sufficient to prove that browser code is benign or that the phone/OS is uncompromised. The native component must protect master authority and independently validate the exact operation it authorises.

## 2. Sensitive-operation classes

The phone policy classifies operations by impact. The active policy must be versioned and pinned; the PWA cannot downgrade an operation's class.

| Class | Examples | Gate requirement |
|---|---|---|
| Public/non-sensitive | Public landing pages, public documentation, sign-in UI before protected data is unlocked | No release/verifier pass required; no secrets or protected plaintext exposed |
| Protected content access | Unlock/use Vault, Documents, Gallery; decrypt or unwrap a content root/DEK; display protected records | Fresh release and verifier pass plus approved device/session state; high assurance additionally requires the trusted native key-use boundary described below |
| Data movement | Export, download, share, copy, print, backup/restore, generate object access URLs | Fresh pass, explicit operation scope, fresh user verification where policy requires, and operation-specific authorisation |
| Device authority | Enrol/approve a device, change scopes, revoke a device, change master identity or device registry | Master phone only; native companion independently displays candidate identity, key fingerprints, requested scopes, expiry and operation; fresh user verification and fresh gate evidence |
| Trust administration | Pin/rotate/revoke release-authorisation or verifier keys, change minimum policy, approve a release rollback | Owner-only trusted native ceremony; fresh gate evidence or the separately defined emergency root-recovery ceremony |
| Recovery | Lost-master replacement, offline recovery material use, trust-state recovery after phone loss | Separate Phase 1.8 offline recovery ceremony; no server-only reset; verifier outage cannot turn recovery into a routine bypass |
| Operational administration | Change security configuration, rotate application service credentials, modify release/deployment state | Separate operator authority and audit policy; never delegated to HelioHost or an additional device |

A normal successful login or authenticated PHP session does not satisfy the security gate.

## 3. Gate architecture

The trusted phone-side component holds or protects:
- Pinned release-authorisation trust root and active key IDs.
- Pinned HelioHost verifier public key and active key IDs.
- Current Sigstore/TUF trust policy/root state needed for independent provenance verification.
- Current trust-store sequence/digest and policy versions.
- Highest accepted release sequence and exact accepted release digests.
- Highest accepted verifier report sequence and consumed challenge IDs.
- Current master identity and authority epoch.
- Per-device certificate/registry state required for the requested operation.
- Fresh local user-verification state for sensitive approvals.

The application host may transport public evidence and display a status summary. It cannot change phone-held pins, high-water marks, revocation state, operation scope, or the final decision.

The trusted component must not expose a general-purpose API that signs arbitrary bytes supplied by the PWA. It constructs and validates the canonical operation request itself and displays the exact action in trusted UI.

## 4. Verification sequence

For each operation requiring a current gate:

1. **Classify the operation.** Determine its security class from trusted native policy, not a PWA-supplied label.
2. **Check local trust state.** Confirm the trust store is initialised, current, not rolled back, and contains active release/verifier keys.
3. **Resolve release evidence.** Obtain the canonical manifest, detached release-authorisation record, ZIP digest, and GitHub/Sigstore provenance from the approved trust sources.
4. **Verify build provenance.** Validate repository ID/name, workflow identity/path/commit, tag/ref, source commit, event, subject digest, and current Sigstore/TUF trust.
5. **Verify release authorisation.** Validate its detached signature, key ID, exact manifest/ZIP digests, release sequence, policy version, validity, and revocation status.
6. **Create a fresh challenge.** Generate a new random nonce and challenge ID on the phone. Sign the request with the current master device key if the selected challenge-authentication mode requires it.
7. **Obtain verifier evidence.** Submit the challenge to the fixed HelioHost verifier origin and retrieve the signed report for that exact challenge.
8. **Verify the report.** Apply every Phase 2.7 check: report signature/key ID, challenge/nonce, target origin, deployment profile, release identity/digests, policy version, freshness/expiry, result taxonomy, evidence scope, and report sequence.
9. **Apply assurance policy.** Confirm the public and private measurement levels satisfy the operation's minimum evidence requirements. An HTTP-only report cannot satisfy a policy that requires private runtime inspection.
10. **Check device authority.** Confirm current master/device registry epoch, certificate scope, expiry, revocation, and proof-of-possession as applicable.
11. **Display trusted operation details.** For authority-changing or data-export operations, show the exact candidate device, scopes, target, record/object, or action in native UI. Require fresh local user verification.
12. **Persist acceptance.** Atomically persist accepted release/report high-water marks, challenge consumption, and operation decision before proceeding.
13. **Perform only the approved operation.** The native component performs the sensitive key/authority operation itself or issues a single-use operation-bound permit under the rules below. It never returns a generic reusable "verified" bearer token.

If any step fails, the operation is denied. No fallback to an application-host status flag is permitted.

## 5. Operation-bound authorisation

A generic five-minute "device verified" token would allow a compromised PWA to reuse one approval for unrelated operations. Avoid that design.

Preferred:
- The native companion performs master signing, trust-root acceptance, recovery, and high-assurance key operations internally.
- The PWA may request an operation, but the companion independently parses and validates its schema, displays the human-readable details, and constructs the signed statement itself.
- Each approval is bound to one operation type, canonical request digest, target device/object, requested scopes, current release sequence, current authority epoch, and a one-use challenge.
- The companion consumes the permit atomically and rejects replay, altered parameters, scope widening, or use after expiry.
- No general bearer capability or master private key is returned to the PWA.

If a narrow native-to-PWA permit is unavoidable for a specific integration, it must be one-use, short-lived, bound to an exact canonical request digest and operation, and validated/consumed by the native component at execution time. The permit must not itself grant access to a general signing or decryption API.

## 6. PWA and content-key boundary

The native companion protects the master authority key and the integrity of trusted approval UI. It does not automatically protect plaintext or DEKs that remain in browser JavaScript.

The Phase 1 threat model establishes that malicious same-origin JavaScript can:
- Read plaintext displayed in the page or held in JavaScript memory.
- Observe WebAuthn PRF output returned to JavaScript.
- Invoke page-accessible WebCrypto keys, even when marked non-extractable.
- Change PWA UI/request details before a user confirms them.
- Exfiltrate content used during a compromised session.

Therefore:
- Do not claim that a successful release/verifier report makes the browser runtime trustworthy.
- Do not send master private keys, recovery material, or usable content roots to the PWA.
- Device approval and trust-root operations must be performed and displayed by the native companion, not by a PWA modal.
- High-assurance content decryption requires a separately reviewed native key-use boundary or another design that keeps the relevant plaintext/key operation outside attacker-controlled same-origin JavaScript.
- If content decryption remains in the PWA, record it as a lower-assurance tier with explicit residual risk; the release gate reduces supply-chain exposure but does not eliminate same-origin compromise.
- A service worker, when introduced, is part of the application-origin attack surface and must be covered by the release manifest and Phase 2.5 measurement.

The owner must decide whether a native companion is adopted and which operations it performs before implementation begins.

## 7. Freshness and continuous validity

A pass report is not a permanent session property.

Proposed defaults, subject to owner/security review:
- Each high-risk operation obtains its own challenge/report or an explicitly scoped native authorization derived from a fresh report.
- Report lifetime is no more than the Phase 2.7 policy maximum.
- A report cannot be reused after challenge consumption or across a different operation, release sequence, origin, deployment profile, or device authority epoch.
- Long-running operations revalidate before commit if the report expires or trust state changes.
- On app resume, browser tab restore, device unlock after idle, or detected release change, the native component re-evaluates freshness before protected operations.
- Trust-root revocation, verifier key revocation, release rollback, device revocation, master epoch change, or policy downgrade immediately invalidates dependent permits.
- Network outage does not extend expiry.

The phone may support a limited offline policy for low-risk read-only access only if owner-approved and explicitly scoped. High-risk authority changes, exports, recovery, trust changes, and operations requiring current deployment evidence fail closed without fresh evidence.

## 8. Fail-closed state machine

The trusted gate uses explicit states:

| State | Meaning | Permitted actions |
|---|---|---|
| UNINITIALISED | No trusted bootstrap or required roots are pinned | Public/non-sensitive only; trusted initialisation ceremony |
| CHECKING | Fresh release/verifier evidence is being obtained and verified | No protected operation |
| VERIFIED | Current evidence and policy pass for the exact release/target | Only operations whose policy and scopes are satisfied |
| EXPIRED | Previously accepted evidence is outside freshness window | Public/non-sensitive only; re-check required |
| REJECTED | Signature, digest, policy, release, device, or measurement failed | Deny protected operations; show failure |
| INSUFFICIENT | Required evidence is unavailable or below assurance level | Deny operations requiring that evidence |
| REVOKED | Relevant trust key, device, master epoch, or policy has been revoked | Deny dependent operations; trusted recovery/rotation only |
| RECOVERY | Explicit offline recovery ceremony is active | Only the narrowly defined recovery operations |

A visual green state is shown only when the trusted component is in VERIFIED for the current release, policy, target, and operation scope. The PWA cannot set the state or persist it as authority.

## 9. Mandatory denial conditions

The gate denies the operation when any of the following occurs:
- Trust store is uninitialised, rolled back, corrupt, expired, or has an unknown policy.
- Release-authorisation key is unknown/revoked or signature/digest/sequence is invalid.
- GitHub/Sigstore provenance has wrong repository, workflow, ref, commit, event, subject digest, or untrusted TUF root.
- Release version/digest is lower than the phone-held high-water mark without an exact owner-signed rollback.
- Verifier key is unknown, expired, revoked, or signature invalid.
- Report challenge, nonce, target origin, release binding, policy, or expiry does not match.
- Report is replayed, challenge was already consumed, or report sequence is stale.
- Result is fail, insufficient_evidence, or unavailable.
- Required public assets, headers, private runtime files, or directory inventories are missing or below required assurance.
- A required private inspection channel is unavailable.
- Device certificate is expired/revoked, scope is insufficient, proof-of-possession fails, or registry/master epoch is stale.
- Operation request digest differs from the native-confirmed request.
- Local clock or protected high-water state cannot be trusted within policy tolerance.
- App host attempts to substitute a status, key, manifest, verifier endpoint, or policy value.

There is no "warn and continue" mode for mandatory evidence. Emergency recovery is a separate ceremony, not a general override.

## 10. Emergency recovery and availability

A lost verifier, expired report, network outage, or application outage does not permit the app host to bypass the gate.

Master-phone loss follows Phase 1.8:
- Use separate offline master-replacement authority.
- Create a new master identity and advance the authority epoch.
- Re-establish release/verifier pins from the trusted recovery record and independent transition evidence.
- Revoke the old master and prior grants/sessions.
- Re-enrol additional devices through the new master.
- Keep data recovery distinct from master replacement.

If the HelioHost verifier key is compromised or unavailable, sensitive operations remain denied until a replacement verifier is qualified and independently pinned. A cached old report cannot be treated as fresh.

The offline recovery ceremony may replace the master even when online verifier service is unavailable, but it does not authorise ordinary application use, release acceptance, or device enrolment through the untrusted application host until trust is restored.

## 11. Audit record

For each gate decision, retain a minimal local audit record:
- Operation class and canonical request digest.
- Release version, release sequence, manifest/ZIP digests.
- Verifier ID/key ID, report digest, report sequence, challenge ID.
- Trust-store/policy version and master authority epoch.
- Decision and stable reason code.
- Local confirmation time and whether fresh user verification occurred.

Do not log private keys, recovery material, content keys, PRF output, plaintext, user record values, or raw bearer capabilities. The audit record is not a substitute for cryptographic evidence and must be protected against local rollback/tampering.

## 12. Acceptance tests

1. PWA cannot set VERIFIED state or bypass native policy.
2. Missing, stale, invalid, replayed, or wrong-release report blocks every gated operation.
3. Valid report for one challenge cannot authorise a different operation or request digest.
4. PWA alteration of device ID, fingerprint, scope, origin, or action after display is detected by native confirmation.
5. Additional device cannot invoke master operations or change trust roots.
6. Revoked device, stale master epoch, stale registry, and expired certificate are rejected.
7. Release rollback or mutable replacement asset under the same tag is rejected.
8. Private-runtime assurance below policy minimum is insufficient, not pass.
9. Verifier outage, app outage, clock uncertainty, or expired evidence denies high-risk operations.
10. A native companion does not expose a general signing/decryption oracle to same-origin JavaScript.
11. If content keys remain browser-accessible, tests and UI explicitly record the lower assurance and residual XSS risk.
12. Offline master recovery works without an application-host reset and does not enable ordinary use before trust restoration.
13. Gate high-water marks cannot be lowered by app-host responses or stale device backups without explicit recovery.
14. Logs contain no secrets, keys, PRF output, or plaintext.

## 13. Owner decisions and completion

Phase 2.8 is complete as a gate design. The following decisions remain owner/security review gates before implementation:
- Approve or reject a native master companion and minimum supported phone/OS versions.
- Decide which content-key operations must move into the native boundary versus remain explicitly lower-assurance PWA operations.
- Confirm the exact sensitive-operation policy and any limited offline read-only behaviour.
- Confirm challenge/report freshness defaults and trusted-time requirements.
- Confirm which private-runtime assurance level is mandatory before protected operations.

This phase does not authorise native app development, key generation, trust-root bootstrap, production gate activation, or deployment.

**Next planned item:** Phase 2.9 — add tamper, injection, stale report, forged signature, replay, missing/unexpected asset, private-file mismatch, and verifier-outage tests. This is a test design/implementation task and must not introduce production keys or deployment.
