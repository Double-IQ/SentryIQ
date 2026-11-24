# SentryIQ Device-Rooted Security Architecture

**Status:** Proposed target architecture — design baseline, not yet implemented or deployment-approved.  
**Canonical application origin:** `https://sentryiq.bichet.co.za`  
**Application hosting:** Existing SentryIQ application host (the host serving the canonical origin).  
**Independent security node:** HelioHost.  
**Master device:** Owner's phone.

## 1. Architecture decision

SentryIQ remains the application installed and served at `https://sentryiq.bichet.co.za`. HelioHost is assigned the role of one independent, specialised security node. It is not a second SentryIQ application installation. The owner's phone is the master device and root of device-authorisation authority.

Cloudflare Workers/R2/Durable Objects, Val Town, and the previous multi-node A/B/C deployment topology are not part of this target architecture. The existing Cloudflare Node A implementation is legacy research/code pending disposition; it is not an active deployment target.

This decision does not assert that the new design is already implemented, that HelioHost capabilities have been proven, or that the current PWA can securely enforce all of these properties. Those are explicit design and acceptance tasks.

## 2. Components and trust boundaries

### 2.1 SentryIQ application — sentryiq.bichet.co.za
- Continues to host and serve the SentryIQ application/PWA.
- Stores ciphertext and non-secret public device/release metadata only where the end-to-end encryption design permits.
- Must not possess the master-device private key, offline recovery secret, or plaintext data-encryption keys.
- Is treated as potentially compromised by the threat model; server responses are not self-authenticating evidence of integrity.

### 2.2 HelioHost security node
- Runs a small, specialised verifier service, not a second SentryIQ application.
- Independently retrieves the deployed public PWA assets and checks them against an independently approved, cryptographically signed release manifest.
- Where provider permissions permit, independently inspects selected server-side files/configuration through a read-only, isolated mechanism. Public HTTP asset checks alone cannot prove integrity of private PHP code or host configuration.
- Produces a signed, freshness-bounded verification result containing the release identity, measured digests, policy version, timestamp/expiry, nonce or challenge binding, and pass/fail decision.
- Has its own signing key and credentials, separate from application, release-signing, master-device, and recovery keys.
- Has no authority to approve devices, decrypt user data, change release policy, or modify the application host.
- Fails closed on missing, stale, inconsistent, unreachable, or invalid evidence.

### 2.3 Master phone
- Is the sole normal authority for enrolling, approving, changing permissions for, and revoking trusted devices.
- Holds the master device identity/private key locally, protected by platform hardware security where available.
- Verifies the security node's signed result using a public key pinned during a deliberate trusted bootstrap.
- Does not trust a status message or key supplied only by the application server.
- Requires fresh user verification for sensitive actions and device approvals.
- Never exports or uploads its master private key.

### 2.4 Additional devices
- Generate their own device key pairs locally.
- Are enrolled only after a fresh, explicit approval signed by the current master device.
- Receive device-specific credentials and narrowly scoped permissions; never receive the master private key.
- Cannot approve, promote, or enrol another device.
- Can be individually revoked. Revocation blocks future authorisation; previously copied plaintext or keys cannot be retroactively recalled.

### 2.5 Offline recovery authority
- Is generated separately during trusted initialisation and stored offline by the owner.
- Is not stored on either server and is not an ordinary login password.
- Can authorise replacement of a lost master device only through a deliberate recovery ceremony.
- Is protected independently from the master phone and is not recoverable by HelioHost or the application host alone.

## 3. Cryptographic roles — keys must not be interchangeable

1. **Release-signing key:** signs approved release manifests/provenance. Its private key is held in the release process, not on either production host or the PWA.
2. **Security-node signing key:** signs independent verification reports. Held only by the isolated HelioHost verifier.
3. **Master-device key:** authorises devices and security-policy-sensitive actions. Held on the master phone, preferably hardware-backed/non-exportable.
4. **Per-device key:** identifies one enrolled device and signs its own protocol messages.
5. **Data-encryption keys (DEKs):** encrypt user data. Use envelope encryption and per-vault/per-purpose separation; DEKs are wrapped for authorised devices or derived through a reviewed key hierarchy. The server stores ciphertext and wrapped key material only.
6. **Recovery key/material:** separately generated, offline, and sufficient only for the documented recovery process.
7. **Transport/session credentials:** short-lived and revocable; never substitute for any of the keys above.

No private key or recovery secret is shared between these roles. Public keys and key identifiers may be distributed as required.

## 4. Independent release verification protocol

1. A release pipeline creates a canonical manifest covering the exact release version, immutable source commit, build identity, and hashes/lengths of all security-relevant deployed assets, including HTML entry points, JavaScript, CSS, manifest, icons, and service worker.
2. The release is signed using the approved release-signing/provenance policy. The application host cannot create an accepted release merely by changing its own files or manifest.
3. HelioHost retrieves the approved release metadata from a trust source independent of the application host, then independently fetches the live assets from `https://sentryiq.bichet.co.za` and hashes the actual response bytes. It checks redirects, content types, duplicate/ambiguous paths, unexpected assets, cache variants, and policy-required headers.
4. Where technically and contractually supported, the security node separately inspects private server-side files through a read-only isolated collector. It must not place a signing key in the public PHP request path or under an identity writable by the application.
5. HelioHost signs a bounded, challenge-bound verification report. The report is not accepted merely because it is hosted at HelioHost; the phone verifies its signature, expected verifier identity, challenge, policy version, release identity, and freshness.
6. The master phone independently verifies release-signing evidence and the security-node report before enabling sensitive operations. A missing, stale, invalid, or failed report is a denial, not a warning-only success.

**Important PWA limitation:** A service worker or JavaScript bundle cannot safely attest to its own runtime. If the application origin or browser execution context is compromised, malicious JavaScript may execute before or during client-side checks and may invoke application-accessible decryption operations. The design must therefore minimise plaintext/key exposure, use strict CSP and dependency controls, verify before activation where feasible, and evaluate a native companion or separately trusted verifier for high-assurance key-use gates. A successful server-side hash check is evidence about measured delivery, not proof that the phone's browser/OS is uncompromised.

## 5. Device enrolment and revocation

- A candidate device creates its key pair locally and presents a short-lived pairing challenge (for example, a QR code containing a nonce, device public-key fingerprint, and protocol version).
- The master phone scans and validates the pairing request, displays a human-readable device identity and requested permissions, and requires fresh user verification.
- The master signs a narrowly scoped enrolment certificate bound to the candidate public key, device ID, permissions, expiry/renewal policy, and current device-registry epoch.
- The server may relay/store the certificate but cannot mint or broaden it.
- Revocation is signed by the master and propagated to all relying components. Short-lived device authorisations limit exposure while offline.
- A device cannot approve another device, alter the master identity, change the release trust root, or weaken verification policy.

## 6. Lost-phone recovery

Recovery must be designed before first initialisation.

1. The owner obtains a replacement phone and creates a new device identity.
2. The owner supplies the offline recovery material through a locally verified recovery flow.
3. Recovery requires a fresh key on the replacement device and proof of possession of the offline recovery authority; server-only recovery is prohibited.
4. The recovery ceremony revokes the old master identity, increments the master/device-registry epoch, invalidates old sessions and enrolment grants, and records a signed recovery event.
5. New device credentials and wrapped data keys are issued. Affected DEKs are rotated/re-wrapped where feasible.
6. The owner verifies recovery completion and stores a newly generated offline recovery copy.

Recovery material must not be a static password, emailed code, support override, or secret stored alongside the encrypted data. The precise threshold/backup format and the risk of loss of both phone and recovery material must be specified before implementation.

## 7. Threat model and limits

The design aims to resist:
- Database, backup, and application-host compromise without access to client-held keys.
- Unapproved device enrolment and device impersonation.
- Forged or altered release manifests and security-node reports.
- Replay of pairing, verification, and recovery messages.
- Silent changes to deployed public PWA assets detectable by independent measurement.
- A compromised application host attempting to self-approve its code or issue device credentials.

The design cannot, by cryptography alone, guarantee safety against:
- A fully compromised master phone, its OS, browser, or trusted execution environment.
- Malicious JavaScript executing in the same origin/context with access to plaintext or permitted key operations.
- A compromised release-signing authority or security-node signing key.
- Coercion, theft of offline recovery material, or owner-approved malicious software.
- Plaintext already copied from a device before revocation.

Controls must be proportionate and claims must reflect these limits.

## 8. Deployment and privacy rules

- Do not expose a public endpoint that returns file contents, private configuration, secrets, or arbitrary filesystem paths.
- The security node receives no master private key, DEK, recovery secret, vault plaintext, or general application credentials.
- Use dedicated credentials, least privilege, TLS with strict validation, bounded requests/responses, nonce/challenge replay protection, rate limits, and audit logs.
- Keep verifier policy and release trust roots independently administered from the application host.
- IP allowlisting may be an additional access control, not a substitute for cryptographic identity, authentication, or end-to-end encryption.
- Do not assume a PWA provides hardware-backed key storage. Record platform/browser capabilities and use a native security component if required by the accepted assurance level.

## 9. Acceptance criteria

The design is not production-ready until tests and deployment evidence demonstrate:
- A clean release passes signature, provenance, asset digest, and freshness checks.
- Modified, injected, missing, unexpected, redirected, stale, or replayed assets/evidence fail closed.
- The application host cannot forge a security-node report or release signature.
- The security node cannot approve devices or decrypt data.
- No server-side backup or database contains a usable master private key, plaintext DEK, or recovery secret.
- Unapproved devices cannot enrol; approved devices cannot enrol others.
- Revocation and recovery invalidate old authority and are auditable.
- Lost-phone recovery restores authorised access without a server support bypass.
- Browser/PWA compromise scenarios are tested, and any residual same-origin/runtime risk is documented.
- Backup restoration, key rotation, verifier outage, application outage, and rollback are rehearsed.

## 10. Status

This document defines the target design only. The existing Cloudflare Worker, R2, Durable Object, Node A/B, and older private-host attestation code have not been proven to implement this architecture. They must be mapped, adapted, retained as reusable components, or retired through a reviewed repository cleanup. No production mutation, key generation, baseline initialisation, or release publication is authorised by this document.
