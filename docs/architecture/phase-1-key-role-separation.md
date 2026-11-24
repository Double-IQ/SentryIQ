# Phase 1.4 — Cryptographic key-role separation, ownership, custody, and authority

**Status:** Proposed role-separation design; owner/security review required.  
**Baseline:** `main` after Phase 1.3 merge.  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Master authority:** Owner's phone; sole normal device-enrolment authority.  
**Independent security node:** One specialised HelioHost verifier.  
**Scope:** Define distinct cryptographic roles, ownership, custody boundaries, permitted operations, and compromise separation. Exact certificate and envelope schemas remain in Phases 1.6–1.8. No key generation, provisioning, migration, or production activation is authorised.

## 1. Core separation rules

1. **One purpose, one key role.** A key created for one purpose must not be reused for another purpose, even if the algorithm and key size are identical.
2. **Signing is not encryption.** A signing private key must never encrypt data or wrap DEKs; an encryption/key-agreement key must never sign authority or release statements.
3. **Authority is not data access.** The master device's authority to approve devices does not imply that its signing key is a Vault DEK or Gallery content key.
4. **Recovery is not routine authority.** Offline recovery can authorise one emergency master replacement. It is not a second everyday master and cannot be held by either server.
5. **The application host is not a key custodian for user content.** It may hold public keys, signed certificates, ciphertext, wrapped DEKs, and service credentials strictly required for its narrow storage/relay functions. It must not hold usable VMK, Gallery root key, private device keys, plaintext DEKs, or recovery secrets.
6. **The verifier is not an application authority.** HelioHost signs measurement reports only. It cannot approve devices, decrypt data, issue releases, or alter application state.
7. **The release pipeline is not a device authority.** Release provenance keys attest to build identity and artifacts; they cannot sign device certificates or verifier reports.
8. **Session credentials are not cryptographic identities.** A session cookie authenticates a web session; it cannot approve devices, replace a master, change trust roots, or unwrap user data.
9. **Independent compromise domains.** Compromise of one key role must not automatically reveal or grant the capabilities of another role.
10. **No key material in source control, issue trackers, chat, logs, public assets, or ordinary backup archives.** Public keys and public certificates may be published where the protocol requires them.

## 2. Key-role inventory and custody

| Role | Owner / controller | Private material custody | Permitted operations | Explicitly forbidden |
|---|---|---|---|---|
| **Release provenance identity** | SentryIQ release process under approved repository/workflow policy | Prefer short-lived GitHub OIDC/Sigstore signing identity; any TUF root private keys remain separately offline under threshold custody | Attest the source/workflow/artifact relationship; authorise trust-root metadata only under its own TUF policy | Device enrolment, verifier reports, user-data decryption, master recovery, application-host runtime access |
| **HelioHost verifier report key** | Independent verifier operator, with public trust pinned by the owner's master phone | Dedicated Ed25519 private key in a verifier-only protected filesystem/service boundary, outside app-host access; separate OS identity and permissions | Sign bounded, challenge-bound release/deployment measurement reports | Sign releases, approve devices, decrypt user data, access VMK/DEKs/recovery material, write to application host |
| **Master-phone signing key** | Owner | Device/platform-protected private key; hardware-backed/non-exportable where available | Sign device enrolments, scope changes, revocations, registry transitions, and master-authority statements | Encrypt user content, act as verifier/release signer, be stored on application host, be exported into page JavaScript |
| **Master-phone key-agreement key** | Owner | Separate device/platform-protected X25519 key from the signing key | Receive or establish encrypted key envelopes for the master device | Sign certificates/reports, replace the signing key, be reused as a content DEK |
| **Additional-device signing key** | Individual enrolled device; certified by master | Device/platform-protected private key, unique per device | Sign proof-of-possession and permitted scoped protocol messages | Enrol/promote other devices, change trust roots, revoke the master, replace recovery authority, sign on behalf of another device |
| **Additional-device key-agreement key** | Individual enrolled device | Separate per-device X25519 key | Receive only the encrypted key material allowed by its certificate scope | Sign authority, act as master key, be shared with another device |
| **Vault content root / VMK** | Owner's authorised device set under the later envelope design | Generated and used on authorised devices; wrapped separately for authorised devices/credentials and offline data recovery | Derive or unlock Vault content-encryption keys according to Phase 1.6 | Be stored plaintext in PHP sessions/configuration, sent to HelioHost, or used as a signing key |
| **Per-object DEK** | Owner's authorised device set | Generated on the encrypting device; plaintext exists only while encrypting/decrypting the specific object | Encrypt/decrypt one object or one explicitly defined object unit | Reuse across unrelated objects, signing, long-term server storage, exposure to PHP or verifier |
| **Gallery root key** | Owner's authorised device set, Gallery scope only | Browser/device protected wrapping under Gallery passkey/recovery envelopes | Protect Gallery private wrapping-key material and Gallery-specific key hierarchy | Reuse as Vault root, master signing key, session secret, or verifier key |
| **Gallery wrapping key pair** | Owner's Gallery identity | Private key encrypted under Gallery root key and unlocked on authorised device; public key may be stored server-side | Wrap/unwrap Gallery DEKs and perform approved DEK rewrap migration | Sign master certificates, sign releases/reports, encrypt non-Gallery data by default |
| **Password-derived KEK** | User, derived on authorised device | Transient device memory only; never persisted | Unlock/wrap the relevant content root key | Act as a long-lived signing key, be stored server-side, be reused for another purpose without a distinct KDF domain |
| **WebAuthn PRF-derived KEK** | Individual passkey/credential | Derived and used client-side; PRF output remains on client | Wrap/unwrap only the key envelope explicitly assigned to that credential and purpose | Be sent to PHP, reused across Vault/Gallery/master roles, be logged or persisted |
| **Data-recovery wrapping key** | Owner, offline recovery custody | Separate offline recovery medium; used only in a local recovery ceremony | Unlock the data-root envelope needed for owner recovery | Routine login, device enrolment, server-side decryption, or verifier operation |
| **Master-replacement recovery authority** | Owner, offline emergency custody | Distinct offline authority material; not the data-recovery wrapping key | Authorise a one-time master replacement and registry-epoch transition | Routine device approval, daily login, data encryption, or server-only reset |
| **Session credential** | Authenticated user/device session | Random bearer token in secure HttpOnly cookie; server-side session state in protected runtime | Identify a short-lived authenticated web session and bind requests to CSRF/session state | Sign authority statements, hold user-data keys, grant new device scopes, recover master |
| **Application service credential** | SentryIQ application operator | Private runtime configuration; least-privilege service identity (e.g. B2 object signing) | Perform the minimum service operation required, such as signing scoped object URLs | Decrypt user content, sign device certificates/reports/releases, be sent to browser or verifier |
| **Audit/log-integrity key (if introduced)** | Application/security operations | Separate protected logging boundary | Authenticate log checkpoints or integrity records only | Encrypt user data, sign device authority, or replace release/verifier trust |

A public key is not a secret, but it remains security-critical: an attacker who substitutes a public key may redirect encrypted data or change who can verify signatures. Public-key authenticity must be anchored in the relevant authority, not inferred from its location on the application host.

## 3. Authority matrix

| Operation | Master phone | Additional device | Application host | HelioHost verifier | Release pipeline | Offline recovery |
|---|---:|---:|---:|---:|---:|---:|
| Enrol a new device | **Approve/sign** | Request only | Relay/store signed result | No | No | Emergency master replacement only |
| Change device scopes | **Approve/sign** | No | Relay/store signed result | No | No | No |
| Revoke an additional device | **Approve/sign** | No | Relay/store signed result | No | No | No |
| Replace lost master | Accepts recovery-authorised replacement | No | Relay signed transition only | No | No | **Authorise once** |
| Sign a release attestation | No | No | No | No | **Yes, under release policy** | No |
| Sign a verifier report | No | No | No | **Yes, measurement only** | No | No |
| Decrypt Vault/Document/Gallery content | Locally, if authorised | Locally, within scope | **Never** | **Never** | Never | Only local recovery access to the relevant recovery envelope; no server decrypt |
| Store/relay ciphertext and public metadata | May submit/consume | May submit/consume | **Yes** | No user-data access | No | No |
| Issue short-lived object-storage authorisation | No | No | **Yes, scoped service operation** | No | No | No |
| Change release/verifier trust roots | Verify/accept trusted transition | No | Cannot decide | Cannot decide own trust | Only via separately approved trust process | Emergency recovery only if policy explicitly defines it |

The application host may transport signed objects and public certificates. Every relying device verifies the relevant signature, scope, expiry, epoch, and object binding itself. A database row or server response is never authority merely because it came from the application host.

## 4. Key hierarchy and separation boundaries

### 4.1 User-content hierarchy

- A Vault content root is distinct from the master-device signing key and from the Gallery root.
- Per-object DEKs are generated independently for each protected object. A Vault root may wrap or derive a set of scoped object keys only through a separately specified Phase 1.6 design.
- A password-derived KEK and each credential-specific PRF-derived KEK wrap the relevant root-key envelope; they are not the root key and are not signing identities.
- The Gallery root remains Gallery-only. Gallery private wrapping keys are encrypted under it, and per-photo DEKs are wrapped to the Gallery public key. The server stores only public keys, encrypted private-key envelopes, wrapped DEKs, and operational metadata.
- A DEK compromise is scoped to the object(s) encrypted under that DEK. A root-key compromise has a larger blast radius and triggers root rotation/re-encryption planning.

### 4.2 Device authority hierarchy

- The master phone owns an independent signing key pair and key-agreement pair.
- Each additional device generates its own signing and key-agreement pairs. The master signs a certificate/grant that binds the device public keys, device identity, explicit scopes, expiry, protocol version, and current registry epoch.
- A device's key-agreement key receives only the key envelopes required by its approved scope. The device signing key proves possession; it does not confer master authority.
- The application host stores public keys and signed grants and may relay them. It cannot mint a master signature, alter scopes without invalidating the signature, or make a revoked/stale epoch valid.
- The registry epoch is monotonic. Recovery or a global authority reset advances it, invalidating prior-epoch device grants and sessions according to the protocol.

### 4.3 Recovery separation

Two separate recovery concerns must not be collapsed into one secret:

1. **Data recovery:** unlocks or unwraps the content-root material needed to recover encrypted user data. It must be owner-held and offline; the server stores only an encrypted recovery envelope.
2. **Master replacement authority:** authorises creation of a replacement master identity, increments the registry epoch, and revokes the lost master. It is an emergency authority proof, not a data key and not a routine login credential.

The same physical recovery kit may contain separately labelled and independently protected components, but the cryptographic material and protocol domains must remain distinct. A compromised data-recovery key must not silently become a master signing key; possession of a master-replacement proof must not automatically decrypt content unless the separate data-recovery policy is also satisfied.

## 5. Custody requirements

### 5.1 Master phone and additional devices

- Prefer hardware-backed, non-exportable platform key storage for signing and key-agreement private keys where the operating system supports it.
- Where the browser must hold a key, use a non-extractable WebCrypto key where possible and document that this does not prevent malicious same-origin JavaScript from invoking key operations.
- Do not serialize private signing keys, root keys, DEKs, PRF outputs, or recovery secrets to localStorage, IndexedDB, Cache Storage, service-worker caches, URLs, or application logs.
- A browser-only implementation must state its limits for browser profile sync, extensions, debugging interfaces, OS compromise, backups, and same-origin script compromise. Evaluate a native companion if the required assurance cannot be met.
- Device lock, user verification, session timeout, and explicit reauthentication are controls around key use, not replacements for key separation.

### 5.2 Application host

- May store public device/verifier trust material, signed device grants, encrypted content, wrapped key envelopes, opaque IDs, limited protocol state, and least-privilege service credentials.
- Must not store plaintext user-data keys, private device keys, master private key, verifier private key, release signing key, recovery secret, or PRF output.
- PHP session state contains authentication/session metadata and short-lived challenges only. It must not contain VMK, DEKs, Gallery root/private keys, PRF output, or recovery material.
- Service credentials remain outside the web root with restrictive permissions and narrowly scoped access. B2 signing capability must not be mistaken for a content-decryption capability.
- The app host cannot be trusted to enforce key-role boundaries by configuration alone; client cryptographic verification and independent trust anchors are required.

### 5.3 HelioHost verifier

- Keep the Ed25519 verifier private key and verifier policy outside the application host's filesystem and credentials.
- Use a dedicated service identity and read-only inputs. The verifier has no application database write credentials, B2 write credentials, user-data keys, session cookies, or device-authority keys.
- Its signing key signs only a bounded report containing verifier identity, schema/policy version, challenge, release identity, measured digests, timestamps, expiry, and decision.
- The master phone pins/authenticates the verifier public key and verifies every report signature and binding. The verifier must not be able to install a replacement trust root by signing its own key transition.
- Key rotation and emergency revocation are controlled by an independently authenticated phone-side trust transition.

### 5.4 Release and TUF trust

- Prefer ephemeral OIDC/Sigstore workflow identity for release provenance rather than a long-lived private key on the application host.
- Any TUF root private keys are separate from Sigstore, verifier, master-device, and content keys. Root metadata rotation follows TUF's own threshold and version rules.
- Release artifacts and manifests may contain public keys and signatures, but never private signing material or user data.
- A valid release attestation proves provenance under the accepted workflow identity; it does not approve a device or grant access to user content.

### 5.5 Session and service credentials

- Session IDs are random, high-entropy bearer credentials. Store only the minimum server-side session state, enforce idle/absolute expiry, rotate on authentication/privilege transitions, and invalidate on device revocation or registry-epoch change.
- Secure, HttpOnly, SameSite cookie flags are required. Session identifiers must not appear in URLs, logs, analytics, referrers, or backups in plaintext.
- Session credentials cannot sign or encrypt long-lived user content and cannot substitute for a device certificate.
- Service credentials are independent from user-data keys and limited to the API operations needed. Rotate/revoke them separately and audit use.

## 6. Key identifiers and metadata

- Each key role has its own immutable random key ID. Use distinct namespaces/prefixes (for example, `master-sign-`, `device-sign-`, `device-kex-`, `verifier-sign-`, `vault-root-`, `gallery-root-`, `gallery-wrap-`, `dek-`, `release-root-`) while keeping at least 128 bits of random uniqueness.
- IDs are public references, not secrets or proofs of ownership. A certificate or authenticated envelope must bind the key ID to its public key, role, owner, and epoch.
- Never infer authority from a prefix or an ID supplied by the application host. Validate the signed binding.
- Key metadata includes role, algorithm suite, key ID, creation time, activation time, status, owner, version, and revocation/retirement evidence. Do not store private bytes in the metadata record.
- Avoid placing raw private key bytes, PRF output, recovery secret, or DEK in any JSON object that may be logged, serialised into a session, or returned from an endpoint.

## 7. Rotation, revocation, and compromise boundaries

| Role | Rotation trigger | Who authorises rotation | Revocation effect |
|---|---|---|---|
| Release provenance | Workflow identity or signing trust compromise, policy change | Release trust-root policy owners | Reject new/affected attestations; verify last-known-good release independently |
| TUF root | Root-key change or compromise | Existing TUF threshold process and trusted root update | Reject old root after authenticated monotonic transition |
| Verifier signing | Suspected key exposure, host migration, policy change | Owner's independently pinned phone-side trust procedure | Reject reports from revoked key; re-pin only through trusted transition |
| Master signing | Lost/stolen/compromised master phone | Offline master-replacement ceremony | Increment registry epoch; invalidate old master and prior grants/sessions |
| Additional device signing/key agreement | Device loss, theft, compromise, user removal | Master phone | Revoke device ID/key IDs and reject its future proofs/grants |
| Vault/DEK | Exposure, algorithm migration, planned rotation | Owner-authorised device workflow | Re-encrypt affected content or rewrap affected DEKs; assess copied plaintext |
| Gallery root/wrapping | Root/private-key exposure or planned migration | Owner-authorised Gallery recovery/rotation | Rewrap/re-encrypt under new root; retain old key only while references/rollback remain |
| Data recovery | Use, suspected disclosure, owner-requested renewal | Owner, through recovery ceremony | Replace wrapper and invalidate old recovery secret after new recovery is verified |
| Service credential | Provider alert, suspected leakage, privilege change | Application operator | Revoke provider credential and replace with least-privilege credential |
| Session credential | Logout, timeout, device revocation, epoch change, suspicious activity | Session/device policy | Invalidate session; never rely on key rotation alone to terminate sessions |

Compromise response must be role-scoped. For example, rotating a B2 service credential does not rotate a Gallery root key; rotating a Gallery RSA wrapping key does not revoke the master phone; revoking a device certificate does not erase plaintext already copied from that device.

## 8. Required negative security tests

- A Gallery public key cannot be accepted where a master signing key is expected.
- A device signing key cannot verify as the verifier or release identity.
- A verifier key cannot issue device grants or release attestations.
- A release attestation cannot be interpreted as a master approval.
- A session cookie cannot authorise device enrolment, scope change, recovery, or trust-root replacement.
- A device certificate signed by an old master or stale registry epoch is rejected.
- An additional device cannot promote itself, enrol another device, or widen its own scope.
- The application host cannot decrypt a Vault, Document, or Gallery object using its runtime configuration or storage records.
- The verifier cannot read application session state, user-data stores, B2 credentials, or private user content.
- A recovery-authority proof cannot be used as a content DEK or signing key; a data-recovery key cannot sign a master replacement.
- Cross-role key IDs, wrong-purpose envelopes, wrong AAD, unknown algorithm suites, and malformed public keys fail closed.
- Rotation and revocation tests prove old keys are retained only as long as required and cannot regain authority after a higher epoch is accepted.

## 9. Scope and completion

- This is a proposed design, not a claim that the present repository already implements all roles. Existing Vault passkey/VMK and legacy integrity-node keys remain compatibility code until replacements and tests are complete.
- Exact data-key envelope hierarchy and per-device key distribution are specified in Phase 1.6; device certificate and registry wire formats are specified in Phase 1.7; recovery ceremony and material formats are specified in Phase 1.8.
- Platform-backed key custody, WebCrypto non-extractability limitations, and native companion decision remain Phase 1.5.
- No production keys were generated, no private key was provisioned, no service credential was rotated, and no application code or infrastructure was changed.

- [x] Define distinct cryptographic roles and ownership.
- [x] Define allowed and forbidden operations for each role.
- [x] Separate master authority, per-device identity, content keys, recovery, verifier, release, and session credentials.
- [x] Define custody boundaries for phone, app host, HelioHost, release pipeline, and offline recovery.
- [x] Define role-specific rotation and revocation triggers.
- [ ] Owner/security review of role separation and recovery distinction.
- [ ] Confirm platform key-storage capabilities in Phase 1.5.

**Conclusion:** Phase 1.4 establishes explicit non-sharing and least-authority rules. The next task is Phase 1.5: evaluate supported phone/browser key protection, WebCrypto non-extractability limits, WebAuthn PRF support, and whether a native companion is required.
