# Phase 1.7 — Signed device certificates, registry, scopes, enrolment, and revocation protocol

**Status:** Proposed protocol; owner/security review required.  
**Baseline:** `main` after Phase 1.6 merge.  
**Master authority:** Owner's phone; native companion recommended for hardware-backed master signing.  
**Application host:** Untrusted relay and storage for signed public protocol objects.  
**Scope:** Define signed device certificate and registry semantics, permission scopes, proof of possession, challenge/replay handling, enrolment, renewal, revocation, and master replacement. Exact cryptographic suite selection remains bound to Phase 1.5; recovery ceremony details remain Phase 1.8.

## 1. Protocol invariants

1. Only the current master signing key can approve, renew, change scopes, or revoke an additional device during normal operation.
2. Additional devices can prove possession of their own keys and act within their signed scopes. They cannot issue device certificates, add scopes, revoke the master, or change trust roots.
3. The application host stores and relays signed protocol objects. It cannot create a valid master signature or expand a certificate.
4. Every relying device verifies signatures, key roles, owner, certificate status, scope, authority epoch, registry version, expiry, and challenge binding. A server database row is not authority.
5. Signing and key-agreement public keys are separate fields with separate key IDs and algorithm suites. Private keys are never sent to the server.
6. Master authority, per-device identity, content keys, verifier signing, release provenance, session credentials, and offline recovery remain separate roles.
7. Unknown algorithms, unsupported schema versions, duplicate scopes, wildcards, malformed keys, stale epochs, expired certificates, and replayed challenges fail closed.
8. Offline devices cannot learn about a revocation while disconnected. The protocol bounds stale access but cannot recall plaintext or keys already copied by a device.

## 2. Counters and epochs — keep separate

A single counter must not serve unrelated version domains.

| Counter | Increments when | Purpose |
|---|---|---|
| **authority_epoch** | Master identity is replaced or the master trust root is rotated | Invalidates all certificates and sessions issued under the previous master authority |
| **registry_version** | Any device is enrolled, revoked, renewed, or has scopes changed | Monotonic version of the complete signed device registry |
| **domain_epoch** | VRK, DRK, or GRK is rotated | Selects the current data-root key envelope and object DEK-wrapping generation |
| **release_version** | A new approved application release is published | Release anti-rollback; unrelated to device or content authority |

All counters are canonical unsigned decimal strings in signed JSON to avoid JavaScript Number precision loss. A relying client persists the highest accepted version for each domain and rejects lower values. It also rejects a same-version registry snapshot whose digest differs from the previously accepted snapshot.

**Important:** Adding one device increments `registry_version` but does not invalidate every other device certificate. Certificates are bound to `authority_epoch`; the signed current registry snapshot determines whether each certificate is still active. Master replacement increments `authority_epoch`, which invalidates all prior-epoch certificates and requires explicit re-issuance.

## 3. Signed object format

### 3.1 Canonical representation

- Use a maintained RFC 8785 JSON Canonicalization Scheme (JCS) implementation for the signed JSON payload.
- Parse and reject duplicate JSON member names before canonicalization. Reject invalid UTF-8, non-finite numbers, non-canonical base64url, unexpected critical fields, and type coercion.
- Use compact JWS (RFC 7515) or an equivalent maintained JOSE implementation for detached/embedded signatures. The protected header includes explicit `typ`, `alg`, `kid`, and protocol content type.
- Allowed signature identifiers are an explicit allowlist: `EdDSA` for Ed25519 and `ES256` for P-256 ECDSA/SHA-256. The selected key must be registered for that exact role and algorithm. Reject `none`, HMAC algorithms, unknown `alg`, and algorithm/key-type mismatches.
- The signed payload bytes are the exact canonical JCS bytes. A verifier must not parse and reserialize an unsigned or differently canonicalised object and then accept it.
- The master signature key is resolved only from the locally pinned current master trust root and `kid`, never from a public key supplied by the certificate itself.

### 3.2 Signature-suite binding

The Phase 1.5 platform decision remains open:
- A native iOS master companion seeking Secure Enclave custody is expected to use a Secure Enclave P-256 signing key and ES256 signatures.
- A browser-managed or software-key profile may use Ed25519 if that profile is approved.
- The verifier's Ed25519 report key and release provenance trust remain separate and cannot be used as a master key.
- Each signed object declares its signature suite. The master public-key registry binds `kid` to a specific role, suite, public key, and authority epoch.

No algorithm negotiation is performed from attacker-controlled request fields. A candidate presents supported public-key suites; the master selects one from the policy allowlist and signs that selection into the certificate.

## 4. Device certificate

### 4.1 Logical schema

A master-signed device certificate contains:

| Field | Description |
|---|---|
| `type` | Fixed value `SENTRYIQ-DEVICE-CERT` |
| `schema_version` | Certificate schema version |
| `protocol_version` | Device protocol version |
| `owner_id` | Canonical owner/account identifier |
| `device_id` | Random 128-bit opaque device ID |
| `device_label` | Owner-approved human-readable label; not an authority field |
| `certificate_serial` | Random 128-bit unique serial |
| `signing_key_id` | Immutable key ID for the device signing key |
| `signing_suite_id` | `Ed25519` or `ES256`, as approved |
| `signing_public_key` | Canonical public key bytes |
| `key_agreement_key_id` | Separate immutable key ID for the device HPKE recipient key |
| `key_agreement_suite_id` | Exact HPKE suite ID (P-256 or X25519 profile) |
| `key_agreement_public_key` | Canonical public key bytes |
| `scopes` | Sorted, duplicate-free explicit scope allowlist |
| `authority_epoch` | Master authority epoch at issuance |
| `issued_at` | UTC Unix timestamp |
| `not_before` | UTC Unix timestamp |
| `expires_at` | UTC Unix timestamp |
| `issuer_master_key_id` | Current master signing key ID |
| `certificate_digest_profile` | SHA-256 over canonical certificate payload |

The master signs the canonical payload. The certificate is not valid unless:
- the master signature verifies under the pinned current master key;
- `owner_id` matches the relying account;
- the issuer key is the current master signing role;
- both public keys are well-formed and their suite IDs are allowed;
- signing and key-agreement key IDs are different;
- scopes are valid, sorted, unique, and do not include master-only operations;
- the authority epoch matches the current signed registry;
- the certificate is within its validity interval and is listed as active in the current registry.

### 4.2 Lifetime

Proposed starting limits, subject to device usability and threat review:
- Pairing request: maximum 5 minutes.
- Server challenge for a sensitive request: maximum 2 minutes, single-use.
- Device certificate: maximum 30 days; renewal requires a fresh master approval.
- Signed operation proof: maximum 2 minutes and bound to one server-issued challenge.
- Signed registry snapshot: no more than 24 hours old for online sensitive writes.
- Session: maximum 15 minutes idle and 8 hours absolute, with shorter lifetime for high-risk operations.

A shorter expiry is permitted by policy. A longer expiry requires an explicit, documented risk decision; the client must never extend expiry locally.

## 5. Scope model

Scopes are explicit strings, not free-form permissions or wildcards.

| Scope | Capability |
|---|---|
| `vault.read` | Read/decrypt Vault records in the assigned domain |
| `vault.write` | Create/update/delete signed Vault record revisions |
| `documents.read` | Read/decrypt Documents in the assigned domain |
| `documents.write` | Create/update/delete signed Document revisions |
| `gallery.read` | Read/decrypt Gallery objects and private metadata |
| `gallery.write` | Create/update/delete signed Gallery object revisions |

Master-only operations are not grantable to additional devices:
- `device.enrol`
- `device.scope.change`
- `device.revoke`
- `master.replace`
- `trust.root.rotate`
- `recovery.authorise`

Rules:
- Scope arrays are sorted in a fixed bytewise order; duplicate and unknown values are rejected.
- No `*`, `admin`, `all`, or implied wildcard scopes.
- Read and write are separate. A device lacking `*.write` cannot create a valid signed mutation even if it can decrypt content.
- Domain root envelopes are distributed only for the approved domains. A certificate without a domain scope must not receive that domain root.
- A later collection/folder-level permission model requires separate root keys or explicit object-level grants; it cannot be simulated by a UI hide/show control.

## 6. Pairing and enrolment protocol

### 6.1 Candidate request

1. The candidate generates a random device ID, signing key pair, and separate key-agreement key pair locally.
2. The candidate receives a fresh 32-byte pairing challenge generated by the master phone or transferred through an owner-controlled pairing channel.
3. The candidate creates a canonical pairing request containing owner ID, device ID, label, both public keys and suite IDs, requested scopes, challenge, issued time, and expiry.
4. The candidate signs the request with its new device signing key as proof of possession.
5. The candidate displays a QR/pairing representation with the public-key fingerprints and request expiry. No private key or data root is included.

### 6.2 Master approval

1. The master phone scans/receives the pairing request and verifies candidate proof-of-possession, challenge freshness, owner binding, key formats, and requested scope allowlist.
2. The master displays the device label, signing-key fingerprint, key-agreement-key fingerprint, and each requested permission in human-readable form.
3. The owner explicitly approves or rejects. The master must not silently accept requested scopes or trust a label supplied by the server.
4. The master creates the device certificate, increments `registry_version`, and signs the new registry state.
5. The master creates a Phase 1.6 HPKE root envelope for each approved domain and signs the envelope statement.
6. The application host stores and relays the signed certificate, registry snapshot, and encrypted root envelopes.
7. The candidate verifies the master signature and current registry, decrypts only its approved domain roots, and completes a signed challenge proving successful enrolment.
8. The master marks the device active only after verifying the completion proof.

The application host may transport the pairing request and response, but the master phone's explicit approval and signature are the authority. A server-side “approved=true” field is never sufficient.

## 7. Signed device registry

The master-signed registry snapshot contains:
- registry schema and protocol version;
- owner ID;
- current master signing key ID and authority epoch;
- monotonic registry version;
- active device certificate digests and serials;
- revoked device IDs, signing key IDs, key-agreement key IDs, and certificate serials;
- current domain root key IDs and domain epochs (public identifiers only);
- issued time and expiry;
- previous registry snapshot digest for continuity.

Rules:
- Every enrolment, scope change, revocation, or renewal creates a new signed registry version.
- The master signs the full current state or an authenticated transition plus a verifiable snapshot. Clients must be able to reconstruct and verify the complete current state.
- The server may cache and distribute registry snapshots but cannot change the state or signature.
- Clients reject lower registry versions and same-version/different-digest replacements.
- Online sensitive writes require a registry snapshot no older than the policy freshness window (proposed 24 hours). If freshness cannot be established, the client may permit explicitly approved local offline viewing but must fail closed for online writes, enrolment, revocation, and trust changes.
- A newly enrolled device receives the current signed registry directly from the master-authorised pairing flow, not from an untrusted server response alone.

## 8. Revocation protocol

A master-signed revocation transition contains:
- type `SENTRYIQ-DEVICE-REVOCATION`;
- owner ID and device ID;
- all signing/key-agreement key IDs and certificate serials being revoked;
- reason code from a fixed allowlist (lost, stolen, compromised, owner-removed, replaced);
- effective timestamp;
- new registry version;
- current authority epoch;
- event ID and previous registry digest.

On revocation:
1. Master signs the revocation and new registry state.
2. Application host relays the signed transition and stops issuing new sessions/root envelopes for the revoked device.
3. Relying clients reject the revoked certificate/key IDs and all stale registry versions.
4. Session credentials bound to the device ID/key IDs are invalidated.
5. Phase 1.6 domain-root rotation runs for affected scopes; new root envelopes are sent only to remaining authorised devices.
6. The revocation event is retained as signed audit metadata without secrets or user content.

If the application host withholds the revocation, a connected device may detect stale registry state through its freshness policy and fail closed for sensitive operations. An offline device cannot receive a remote revocation; already copied plaintext and keys cannot be recalled.

## 9. Master key rotation and replacement

### 9.1 Planned master key rotation

- Generate new master signing and key-agreement keys on the owner's phone using the approved platform profile.
- The old master signs a transition binding old/new key IDs, new public keys, new algorithm suite IDs, new authority epoch, and a fresh challenge.
- The new master proves possession of its private signing key.
- The authority epoch increments; all old-epoch device certificates are invalid.
- The new master issues replacement certificates for each still-approved device and publishes a new signed registry.
- The old master key is retired after relying clients have accepted the transition and recovery has been verified.

### 9.2 Lost or compromised master

- If the old master key is available and trusted, use the planned rotation transition.
- If the old master is lost or suspected compromised, use the offline master-replacement authority defined in Phase 1.8. Do not let the application host reset the master or nominate a new public key.
- The recovery-authorised replacement creates a new master identity, increments authority epoch, revokes the old master, and invalidates all prior device certificates and sessions.
- Every additional device must be re-authorised/re-issued by the replacement master. The server cannot silently preserve prior authority.
- Data recovery of VRK/DRK/GRK is a separate operation; master replacement alone does not guarantee content recovery.

## 10. Request proof, replay prevention, and sessions

### 10.1 Sensitive request proof

For sensitive API operations, require a device-signed proof containing:
- protocol/version and operation name;
- owner ID, device ID, signing key ID, certificate serial;
- HTTP method and canonical request path;
- SHA-256 digest of the exact request body;
- server-issued 32-byte challenge and request ID;
- issued time and expiry;
- authority epoch and registry version;
- object ID/revision/domain epoch where relevant.

The server verifies the device signature against the current certificate and scope. Other clients verify signed mutation statements before trusting new object revisions. A stolen session cookie alone must not be enough to authorise a sensitive write.

### 10.2 Challenge store

- Challenges are random 32-byte values, bound to owner, device, operation, and request context.
- Each challenge has a maximum 2-minute lifetime and can be consumed exactly once.
- Store only a protected challenge digest where possible; use atomic consume semantics and reject duplicate request IDs.
- Challenge issuance and consumption are not authority decisions. A compromised host may deny service or issue unusable challenges, but it cannot create a valid master/device signature.
- Reject replay, expired challenge, wrong operation, wrong device, wrong body digest, wrong origin, wrong registry version, and wrong authority epoch.

### 10.3 Session binding

- A session cookie is a short-lived bearer credential for UI continuity, not a device identity or authority key.
- The server-side session stores only authentication state, device ID/key IDs, certificate digest, current authority/registry versions, CSRF state, and short-lived challenges. It must not store VMK, VRK/DRK/GRK, DEKs, private keys, PRF output, recovery material, or plaintext records.
- Session cookies remain Secure, HttpOnly, SameSite=Strict, and never appear in URLs or logs.
- Session renewal requires fresh device proof-of-possession and a current registry snapshot. Logout, timeout, revocation, and authority-epoch change invalidate the session.

## 11. Bootstrap and trust-root pinning

- The initial master public signing key must be pinned by an owner-controlled bootstrap ceremony, not accepted from an application-host API response.
- Recommended bootstrap: the master companion displays a QR containing the master public-key fingerprint and protocol version; the initial authorised client scans it or the owner verifies it through a separate trusted channel.
- The master public key and its role/suite are stored as the local trust anchor. A public key delivered later by the application host is not trusted unless signed by the pinned current master or authenticated by offline recovery.
- Master trust-root rotation uses the planned old-key transition; emergency replacement uses Phase 1.8 recovery authority.
- Verifier and release trust roots remain independent from the master key. A valid release or HelioHost report does not itself enrol a device.

## 12. Security test requirements

- Altering any certificate field, scope, key ID, owner, epoch, expiry, or public key invalidates the master signature.
- Additional-device signing keys cannot issue certificates or registry transitions.
- The application host cannot widen scopes, replace a master key, remove a revocation, or replay an older registry without detection.
- A certificate with a wrong key role, unknown suite, malformed public key, duplicate scope, wildcard scope, or master-only permission is rejected.
- Device proofs fail for wrong HTTP method/path/body digest, wrong challenge, replayed request ID, expired proof, stale authority epoch, stale registry, revoked serial, or insufficient scope.
- A read-only device cannot create an accepted write even if it knows the domain root.
- Master replacement invalidates all old-epoch certificates and sessions.
- Registry version increments on each membership/scope transition; authority epoch changes only on master trust replacement.
- A stale offline device can only perform the explicitly approved local offline actions and cannot silently sync sensitive writes after missing a revocation.
- Pairing QR substitution, key fingerprint mismatch, fake device labels, challenge replay, and malicious server response are tested.
- JWS/JCS canonicalization and ES256/EdDSA signatures pass official test vectors and cross-language tests.

## 13. Scope and completion

- Exact recovery authority format, offline custody, and lost-master ceremony remain Phase 1.8.
- The P-256 Secure Enclave versus Ed25519 software-key master profile remains an owner decision from Phase 1.5. The certificate supports explicit algorithm-suite IDs but implementation must select and pin the approved profile.
- This is a proposed protocol, not an implementation claim. No device certificates, master keys, recovery keys, production sessions, or trust roots were generated.
- No application code, configuration, production state, or infrastructure was changed.

- [x] Define signed device certificate fields and issuer binding.
- [x] Define separate authority epoch, registry version, and domain epoch semantics.
- [x] Define explicit permission scopes and master-only operations.
- [x] Define candidate proof-of-possession and master approval flow.
- [x] Define signed registry, revocation, renewal, and master replacement transitions.
- [x] Define request proof, replay prevention, session binding, and bootstrap pinning.
- [ ] Owner/security review of certificate lifetime, registry freshness, scope granularity, and master signature suite.
- [ ] Cross-platform JWS/JCS and device interoperability tests before implementation.

**Conclusion:** Phase 1.7 specifies a master-signed, independently verifiable device authority protocol. The server can relay and persist it but cannot create or broaden authority. Phase 1.8 must next define the offline recovery authority and data-recovery ceremonies.
