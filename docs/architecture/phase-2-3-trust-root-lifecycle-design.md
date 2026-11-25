# Phase 2.3 — Independent trust-root distribution, bootstrap, and rotation design

**Status:** Design artifact complete; owner/security review and custody decisions remain open.  
**Application:** `https://sentryiq.bichet.co.za`  
**Master authority:** Owner's phone.  
**Independent verifier:** One specialised HelioHost verifier.  
**Safety:** No trust keys are generated, provisioned, rotated, or pinned by this design.

## 1. Purpose and authority model

Phase 2.2 defined a canonical manifest and a detached release-authorisation record. Those objects are not trustworthy until a relying client knows which public keys are authorised to sign them. The target architecture also requires the phone to verify a separate HelioHost report key.

The trust model therefore maintains distinct trust domains:

1. **GitHub/Sigstore/TUF roots** authenticate build-provenance evidence under the maintained Sigstore/TUF policy.
2. **Release-authorisation root** identifies which separately controlled key may approve an exact release version, source commit, manifest digest, ZIP digest, and release sequence.
3. **HelioHost verifier root** identifies which dedicated verifier key may sign independent deployment-measurement reports.
4. **Master-device authority root** identifies the owner's current master phone and authorises device lifecycle and security-policy transitions.
5. **Offline recovery authority** authorises replacement of a lost master through the separate recovery ceremony.

These roles are not interchangeable. In particular:
- GitHub OIDC/Sigstore identity is not owner release approval.
- TUF root keys are not release-authorisation keys.
- Release-authorisation keys are not HelioHost report keys.
- The HelioHost report key cannot approve releases, devices, trust-root changes, or user-data operations.
- The master-device key can accept a trust transition under the owner's policy but must not become the release signer or verifier report signer.
- Offline recovery authority is not a routine second master and is not a report/release signing key.

The owner's phone is the relying authority that pins release-authorisation and verifier public keys. The application host may relay trust metadata but cannot create, replace, or approve it.

## 2. Root and key-role register

| Trust domain | Private-key custody | Phone-side trust anchor | Allowed operation | Explicitly forbidden |
|---|---|---|---|---|
| GitHub/Sigstore/TUF | Maintained upstream Sigstore/TUF trust process and its threshold-controlled roots | Maintained, reviewed Sigstore trust policy/root bootstrap; monotonic TUF root updates | Authenticate GitHub/SLSA build provenance | Owner approval, verifier reports, device authority |
| Release authorisation | Separate release-authorisation custody boundary, not GitHub runner, app host, or HelioHost | Release-authorisation public root/key IDs pinned by deliberate phone bootstrap | Approve exact release manifest/ZIP digests and monotonic release sequence | Build attestation substitution, device approval, verifier reports, data encryption |
| HelioHost verifier | Dedicated verifier-only key in qualified HelioHost isolation boundary | Pinned verifier public key and policy on the master phone | Sign bounded measurement reports only | Release approval, device authority, app write, user data |
| Master device | Owner's current phone; hardware-backed/non-exportable where platform permits | Current master identity/public key and authority epoch | Approve devices and owner security-policy transitions, including trust-root acceptance | Release signing or HelioHost report signing |
| Additional device | Individual device-protected key | Master-signed certificate and current registry state | Device proof-of-possession and permitted scoped operations | Trust-root administration or master promotion |
| Offline recovery | Owner-held offline recovery material, separate from online services | Recovery authority public commitment/verification material pinned during trusted initialisation | One-time lost-master replacement under ceremony | Routine signing, release approval, verifier reports, server-only reset |

**Candidate signature profile:** The Phase 1 cryptographic profile identifies Ed25519 as the proposed detached-signature profile for verifier reports and device signatures. Ed25519 is a candidate for release-authorisation and trust-transition statements only after the owner/security review confirms the supported phone/native platform and key custody. Do not infer that any production key exists or generate one during design.

Each public key has a role-bound immutable key ID derived from a canonical encoding of its public key and role. A key ID is never reassigned, even after revocation. Metadata includes algorithm, role, key ID, status, creation/activation/retirement times, allowed purpose, and transition evidence. Private key bytes never appear in the trust bundle.

## 3. Trusted first bootstrap

### 3.1 Bootstrap must not depend on the application host

The first trust-store state cannot be accepted from:
- A JSON endpoint served only by `sentryiq.bichet.co.za`.
- A QR code displayed only by the application origin.
- A database record or PHP configuration controlled by the application host.
- A HelioHost report that is not yet trusted.
- A GitHub release asset whose authorisation key is not already trusted.

The phone must begin from a deliberate, owner-supervised ceremony. The ceremony verifies the public fingerprints of the release-authorisation root and the qualified HelioHost verifier root through an independently authenticated channel or physical/out-of-band fingerprint record controlled by the owner. The exact channel, human confirmation steps, and supported native/PWA interface are owner decisions; the current PWA cannot be assumed to provide a secure hardware-backed approval surface.

### 3.2 Bootstrap sequence

1. Confirm the master phone's platform, secure key storage capability, OS/browser integrity assumptions, and owner-verification method.
2. Obtain the release-authorisation public root fingerprint from the independently controlled release-authority custody process.
3. Obtain the HelioHost verifier public key fingerprint only after Phase 2.4/Phase 4 host qualification and isolation evidence exist.
4. Obtain the current Sigstore/TUF bootstrap trust material through the maintained Sigstore trust distribution process; verify its initial root under the documented upstream bootstrap procedure.
5. Display role, key ID, algorithm, fingerprint, purpose, and trust boundary separately on the trusted owner interface. Do not show a generic "SentryIQ trusted" status that conceals which root was pinned.
6. Owner confirms each root independently after comparing the fingerprints through the approved out-of-band process and fresh local user verification.
7. Phone stores the accepted root set, trust-store version, policy version, and high-water marks in protected local storage bound to the current master identity.
8. Phone records a signed bootstrap receipt containing the accepted key IDs/fingerprints, ceremony version, time, and initial trust-store digest. The receipt contains no private key or recovery secret.

No root is considered pinned merely because it was downloaded successfully. A failed, ambiguous, or interrupted ceremony leaves the trust store uninitialised and high-risk operations disabled.

### 3.3 Application-host and verifier independence

The application host may cache and relay public trust metadata. The phone must verify signatures and monotonic versions itself and must reject any root/key introduced only by the app host.

HelioHost may publish its public key and signed verifier metadata, but it cannot sign a transition that makes its own new key trusted. The owner phone must accept the transition under an already trusted owner-controlled root or the offline recovery process.

## 4. Trust-store object and signed transition

A versioned trust-store object should contain:
- Schema and policy version.
- Monotonic trust-store sequence/epoch.
- Previous accepted trust-store digest.
- Issued-at and expiry timestamps.
- Role-specific root/key records, allowed purposes, activation and retirement windows.
- Revocation records and effective times.
- Minimum accepted release sequence and minimum verifier policy version.
- Key-transition statements and proof-of-possession evidence.
- Required signature threshold and signer key IDs.

The object is canonicalised using the same strict JSON/JCS rules defined in Phase 2.2. The signed transition includes a domain-separation label such as `SentryIQ/TrustStoreTransition/v1`. Exact signature envelope and threshold policy are implementation details for reviewed cryptographic libraries; do not hand-roll signature or canonicalisation primitives.

A transition is accepted only if:
1. The schema and policy are supported and not downgraded.
2. The new sequence is strictly greater than the phone's persisted high-water mark.
3. The previous digest matches the phone's current trust-store digest.
4. The required currently trusted authority signatures validate.
5. The new key material and purpose are valid for the role being changed.
6. The new key proves possession where the protocol requires it.
7. No revoked key is reactivated and no key ID is reused.
8. The owner phone explicitly accepts the change with fresh user verification.
9. The phone atomically persists the new state before treating it as active.

The phone's locally pinned state is authoritative. A server-provided "current trust-store version" is only a hint and cannot lower the local version.

## 5. Normal key rotation

### 5.1 Planned release-authorisation key rotation

1. Create the replacement key only in the separately qualified release-authority custody boundary after explicit owner approval.
2. Publish a transition naming the old and new key IDs, roles, algorithms, activation time, retirement time, and trust-store sequence.
3. The transition is signed by the currently trusted release-authorisation root or designated offline root threshold; the replacement key signs a proof-of-possession challenge.
4. The master phone validates the transition, displays both fingerprints and the change, requires fresh owner verification, and persists the new pin.
5. During a bounded overlap, accept both keys only for the explicitly stated time and purpose. New releases use the new key after activation.
6. Retire the old key at the stated deadline and reject all later signatures from it.
7. Retain public transition evidence for audit; destroy or offline-retain old private material according to the reviewed custody procedure.

### 5.2 Planned HelioHost verifier-key rotation

1. Replacement is permitted only after host qualification confirms the new private-key boundary is independent of the application host.
2. New key ID and public fingerprint are published with a signed transition under the current trusted verifier transition authority and accepted by the phone.
3. The new key proves possession by signing a phone-generated challenge or a defined transition nonce.
4. The phone accepts a bounded overlap window only when both key IDs and exact activation/retirement times are present.
5. The verifier's report must identify the key ID, policy version, and report schema. The phone rejects an unknown or retired key.
6. The verifier cannot authorise its own new key. The phone's owner-approved trust transition is mandatory.

### 5.3 Sigstore/TUF root rotation

Continue using the maintained TUF root-rotation process and threshold rules. Each successive root must be authenticated under the required old/new root thresholds and version progression as defined by TUF. Do not replace TUF roots because a release manifest, application host, or HelioHost report supplies new root bytes.

The existing PHP `TufRootStore` is a local persistence primitive for the application updater; it is not the master phone's independent trust store and is not the HelioHost verifier's root store. Its successful tests do not establish production persistence or phone-side root pinning.

## 6. Emergency compromise and revocation

Treat compromise according to the affected role. The response must not rely on the compromised key to authorise its own replacement.

### Release-authorisation key compromise
- Phone immediately marks the key revoked and rejects all new authorisations from it.
- Freeze acceptance of new releases until a replacement key is pinned through the offline/owner-controlled root transition.
- Review the exact release sequences/digests accepted during the compromise interval.
- Issue a new release-authorisation key and trust transition using an uncompromised offline root/owner ceremony.
- Re-approve the last known-good release digest if necessary; do not trust a replacement asset merely because it uses the same GitHub tag.

### HelioHost verifier key compromise
- Phone rejects the compromised verifier key ID and all reports signed by it after the defined compromise boundary.
- Sensitive operations requiring fresh verifier evidence remain denied until a replacement verifier is qualified and independently pinned.
- Rebuild/rotate the verifier host boundary and credentials; prove the new key is not readable or writable by the application host.
- Pin the replacement through an owner-approved transition. The verifier cannot self-repin.
- Review reports accepted during the exposure window and repeat measurement where trustworthy evidence exists.

### Master phone loss or compromise
- Invoke the Phase 1.8 offline master-replacement ceremony using the separate master-replacement authority.
- Create a new master identity, increment the authority epoch, revoke the old master, invalidate prior grants/sessions, and re-enrol devices.
- Restore or re-establish release/verifier trust pins only from the trusted recovery record and independently authenticated current transitions.
- Data recovery and master replacement remain distinct; possession of one recovery material must not silently confer the other authority.

### Root-store corruption or rollback
- Reject a trust store with a lower sequence, wrong previous digest, invalid signature, or unknown policy.
- Do not silently reset the high-water mark or fetch a replacement from the application host.
- Recover through a separately authenticated owner/recovery ceremony, recording the last known trusted digest and reason for recovery.

## 7. Phone-side persistence and anti-rollback

The master phone maintains:
- Current trust-store sequence and digest.
- Pinned release-authorisation key IDs and status.
- Pinned verifier key IDs and status.
- Current Sigstore/TUF trust policy and last accepted root versions where the phone itself verifies that chain.
- Highest accepted release sequence and exact release digest.
- Highest accepted verifier policy version and freshness requirements.
- Revocation list and transition history.

The store is bound to the current master identity and protected by the strongest available platform storage. Where a hardware-backed monotonic counter is unavailable, do not claim rollback-proof storage. Use signed checkpoints, protected local state, and an explicit revalidation/recovery procedure after backup restore, app reinstall, device migration, or suspected local-state rollback.

The application host cannot lower or reset any phone-held high-water mark. A network outage or inability to refresh required trust metadata causes a fail-closed result for operations whose policy requires fresh evidence; previously accepted state may be used only within an explicitly defined, bounded offline policy.

## 8. Expiry, freshness, and outage rules

- Release authorisation validity is bounded and tied to exact manifest/ZIP digests and release sequence.
- Verifier public-key validity and verifier policy version are distinct from the freshness of an individual report.
- A report signed by a trusted key can still be stale, replayed, wrong-origin, wrong-release, or wrong-challenge; the phone must validate those report fields in Phase 2.7.
- A key's retirement date does not make old reports fresh or permit a revoked key to sign new reports.
- Clock uncertainty must not silently extend trust. Define trusted-time and challenge freshness policy with the native companion/platform review.
- If the release-authorisation service, Sigstore/TUF metadata, verifier, or trust metadata source is unavailable, do not weaken signature, freshness, or anti-rollback checks to preserve availability.
- Emergency override must be a separate owner-visible and auditable recovery ceremony, not a hidden server flag.

## 9. Trust transition test requirements

1. Unknown release-authorisation key is rejected even when GitHub/Sigstore provenance is valid.
2. Unknown HelioHost key is rejected even when report contents claim success.
3. Application-host-supplied replacement roots are rejected without independent owner approval.
4. Old-key-signed, new-key-signed, and required-threshold transition signatures are checked exactly.
5. Wrong role, wrong purpose, wrong key ID, algorithm downgrade, duplicate key ID, and key-ID reuse are rejected.
6. Lower trust-store sequence, same sequence with changed bytes, wrong previous digest, expired transition, and invalid policy version are rejected.
7. Replacement key proof-of-possession must match the new public key and transition challenge.
8. Planned overlap expires at the exact boundary; retired keys cannot sign new objects.
9. Compromised/revoked keys cannot be reactivated by an ordinary transition.
10. Release sequence rollback, changed ZIP under same tag, changed manifest under same version, and unauthorised rollback are rejected.
11. Phone reinstall/backup restore/local state corruption cannot silently lower trust high-water marks.
12. Loss of verifier or trust metadata service denies operations requiring fresh evidence.
13. Lost-master recovery requires the distinct MRAK ceremony and does not let the application host reset the trust store.
14. No key material or recovery secret is present in logs, app-host responses, manifests, or public trust metadata.

## 10. Decisions and gates

Owner/security review must settle:
- Native companion and minimum supported phone/OS versions for secure bootstrap and high-risk trust acceptance.
- Release-authorisation key custody model (offline owner-controlled key, hardware-backed signing device, or another independently controlled boundary).
- Whether a separate offline trust-transition root/threshold is required in addition to the master's owner approval.
- Verifier key generation and custody only after HelioHost qualification.
- Trust-store validity periods, overlap durations, emergency revocation timing, and offline acceptance policy.
- How recovery material restores trust state after a lost master without conflating DRS and MRAK.
- Exact algorithms and serialization profile after cross-platform interoperability testing.

This phase defines no operational key ceremony and generates no key. The next item, Phase 2.4, designs the HelioHost verifier as a read-only isolated service with a dedicated signing key and no application-write authority. Host qualification remains a prerequisite before any verifier key generation or deployment.
