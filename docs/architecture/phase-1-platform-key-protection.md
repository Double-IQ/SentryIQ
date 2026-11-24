# Phase 1.5 — Supported-platform key protection and native-companion assessment

**Status:** Platform capability assessment complete; owner decision required before implementation.  
**Baseline:** `main` after Phase 1.4 merge.  
**Canonical application:** `https://sentryiq.bichet.co.za`  
**Master authority:** Owner's phone.  
**Scope:** Assess browser/PWA, WebAuthn PRF, WebCrypto, iOS Secure Enclave/Keychain, and native-companion options. State which assurances each platform can and cannot provide. No app code, key generation, device enrolment, or native project was created.

## 1. Executive conclusion

**A browser-only PWA cannot provide the same master-key custody guarantee as a native app using iOS Secure Enclave.** WebCrypto can make a key non-extractable through its API, and WebAuthn PRF can derive a credential-bound secret, but page JavaScript still receives PRF output and can invoke operations with page-accessible CryptoKeys. Web content has no direct API that asks the iOS Secure Enclave to sign a SentryIQ-specific master-authority message.

If SentryIQ requires the master phone's authority key to remain hardware-bound and non-exportable, the recommended architecture is:

- Keep the PWA as the application UI and encrypted-data client.
- Add a small native master companion on the owner's phone to create and use the master-authority keys through platform APIs.
- Keep the master signing and key-agreement keys separate.
- On iOS, use Secure Enclave-backed NIST P-256 keys for those operations if the final cross-platform protocol adopts a compatible P-256 profile.
- Let the PWA request a narrowly scoped approval/signature from the companion, then independently verify the returned signed object. The app host must not be able to forge or broaden that approval.
- Do not treat the native companion as a second SentryIQ installation or a second master. It is a protected key-operation surface for the one owner master.

This recommendation creates a **cryptographic-profile compatibility decision**: Phase 1.3 proposed Ed25519/X25519 for device authority, while Apple's documented Secure Enclave key operations are limited to NIST P-256. Ed25519/X25519 can be used by native iOS apps through CryptoKit/Keychain, but that is not the same as Secure Enclave-backed key custody. The master-phone algorithm choice must therefore be resolved before implementation.

## 2. Current repository state

- The repository contains browser-side Gallery encryption in `assets/js/gallery_crypto.js` and `assets/js/gallery_secure.js`. The Gallery obtains WebAuthn PRF output in the browser, derives wrapping keys, and uses WebCrypto for its Gallery key hierarchy.
- The Vault passkey flow in `assets/js/passkey_login.js` and `assets/js/passkey_setup.js` also obtains PRF output, but sends it to the PHP `passkey_auth.php` endpoint. The server currently unwraps the VMK and creates a PHP session containing it. This is a current implementation gap, not an acceptable target pattern.
- The browser code generates Gallery RSA-OAEP keys as extractable during initial creation so it can export the private JWK and encrypt it under the Gallery root key. The resulting wrapped private-key envelope is stored server-side. This protects the private key at rest from a storage-only disclosure, but it does not protect it from malicious same-origin JavaScript while unlocked.
- The Phase 1 repository audit found no tracked PWA manifest, webmanifest, service-worker entrypoint, or service-worker registration in the audited browser scripts. The current repository therefore does not establish a deployed installable PWA or an offline service-worker security boundary.
- The current repository does not contain a native iOS/Android companion target. No native keychain/Secure Enclave integration is implemented.
- No evidence from a live iPhone, Safari/WebAuthn authenticator, Android device, app store package, or actual hardware-backed key is available. This is a repository/platform documentation assessment, not a device lab certification.

## 3. Browser and WebAuthn capabilities

### 3.1 WebAuthn PRF

- WebKit documents WebAuthn PRF extension support in Safari 18.0 on iOS 18, iPadOS 18, visionOS 2, macOS Sequoia, and macOS Sonoma. PRF allows a relying party to obtain a credential-bound symmetric output for use in client-side data encryption.
- Apple's Safari 26.4 release notes additionally describe PRF support mapping to CTAP `hmac-secret`, including credential creation and authentication with security keys. The precise result depends on browser version, authenticator, passkey provider, and credential capabilities.
- PRF is a useful credential-bound key-derivation input. It is **not** a SentryIQ master signing key, a Secure Enclave API for arbitrary SentryIQ operations, or proof that page JavaScript is trustworthy.
- The PRF result is delivered to the web page. Any same-origin script executing during that ceremony may be able to read or misuse it. The target must keep it client-side, derive a purpose-specific KEK, minimise its lifetime, and never send it to PHP, logs, analytics, or the verifier.
- Unsupported PRF must fail closed for a flow that requires it. Do not silently fall back to password-only wrapping or a server-derived substitute.

### 3.2 WebCrypto algorithms

- MDN browser-compatibility data currently records WebCrypto Ed25519 and X25519 support in Safari from version 17, with corresponding iOS Safari support mirrored to Safari. This is API availability, not a hardware-backed custody guarantee.
- AES-GCM, HKDF, ECDSA/ECDH, and RSA-OAEP are established WebCrypto operations. The current Gallery already uses AES-GCM and RSA-OAEP.
- Native WebCrypto HPKE/KEM encapsulation APIs are not broadly available in Safari. MDN compatibility data currently records `SubtleCrypto.encapsulateKey` as unsupported in Safari; Chrome support is newer and Firefox support is preview-only. If HPKE is selected, use a maintained audited implementation or native platform library, not an assumed native Safari API.
- A `CryptoKey` with `extractable: false` prevents export through the WebCrypto export operations. It does not prevent JavaScript running in the same origin from calling permitted `sign`, `decrypt`, `deriveKey`, or other operations with that key. Non-extractability is therefore a useful control, not a defence against malicious same-origin code.
- Persisting a `CryptoKey` through IndexedDB is not a secure-enclave guarantee. It depends on browser implementation, profile persistence, eviction, backup/sync behaviour, and correct structured cloning.

### 3.3 Safari persistence caution

A WebKit bug report filed in April 2026 describes a non-extractable X25519 `CryptoKey` stored in IndexedDB returning `null` on a later read in Safari 26.4 on macOS 15.4. The issue was marked NEW in the report's October 2026 update. This is a specific reported Safari/macOS reproduction, not proof that all iOS Safari versions fail the same way. It is sufficient reason not to make persistent non-extractable X25519 CryptoKey storage a production dependency until tested on the exact supported iOS matrix and the WebKit issue is resolved.
  
**Platform references:**
- [WebKit — Safari 18.0 WebAuthn PRF support](https://webkit.org/blog/15865/webkit-features-in-safari-18-0/) (16 September 2024)
- [Apple — Safari 26.4 release notes, Web Authentication](https://developer.apple.com/documentation/safari-release-notes/safari-26_4-release-notes) (2026)
- [MDN browser-compat-data — WebCrypto SubtleCrypto support](https://github.com/mdn/browser-compat-data/blob/main/api/SubtleCrypto.json) (living compatibility data)
- [WebKit Bug 312279 — non-extractable X25519 CryptoKey IndexedDB persistence](https://bugs.webkit.org/show_bug.cgi?id=312279) (reported 14 April 2026; modified 17 October 2026)

## 4. iOS Secure Enclave and native key custody

Apple documents that Secure Enclave:
- is a hardware-based key manager isolated from the main processor;
- creates and uses private keys internally so the app receives operation results rather than plaintext private key bytes;
- supports only NIST P-256 keys for the documented signing and elliptic-curve key-agreement operations;
- cannot import pre-existing private key bytes into the Secure Enclave; the key must be created there.

Apple CryptoKit exposes `SecureEnclave.P256.Signing.PrivateKey` and `SecureEnclave.P256.KeyAgreement.PrivateKey`. These can provide a strong native master-key custody boundary for a native iOS app, with user-presence/biometric access controls configured through Keychain/Security APIs.

Important compatibility distinction:
- CryptoKit's general `Curve25519.Signing` and `Curve25519.KeyAgreement` keys can be stored in the Keychain as generic-password items, but Apple's Keychain sample distinguishes those from NIST key types backed by `SecKey` and Secure Enclave.
- Secure Enclave-backed key generation cannot import an Ed25519/X25519 private key created earlier in a PWA. A migration must create a new P-256 key inside the enclave and issue a new signed master-authority transition.
- Secure Enclave P-256 signing and P-256 key agreement must use separate key pairs, even though both use the same curve.
- A native app can call CryptoKit/Security APIs; ordinary Safari page JavaScript cannot directly obtain a Secure Enclave key reference or request arbitrary signing operations from it.

**Apple references:**
- [Apple — Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave)
- [Apple — SecureEnclave.P256.Signing](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing)
- [Apple — SecureEnclave.P256.KeyAgreement](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement)
- [Apple — Storing CryptoKit keys in the Keychain](https://developer.apple.com/documentation/cryptokit/storing-cryptokit-keys-in-the-keychain)

## 5. Platform options

| Option | Key custody | Advantages | Limitations / residual risk | Assessment |
|---|---|---|---|---|
| **PWA only — WebCrypto + WebAuthn PRF** | Browser-managed CryptoKey and authenticator-held passkey; PRF output visible to page code | One codebase; no app-store release; existing Gallery path already uses PRF/WebCrypto | No direct Secure Enclave API; same-origin script can invoke keys/read PRF output; persistent CryptoKey behaviour varies; no guarantee of hardware-backed master authority | Suitable for encrypted data client and ordinary additional devices with documented browser threat model; not sufficient to claim hardware-bound master authority |
| **PWA + wrapped private key in IndexedDB** | Private key encrypted/wrapped at rest; unwrapped while app is active | Supports continuity across browser sessions; existing Gallery uses encrypted private-key envelopes | IndexedDB is not Secure Enclave; browser profile compromise/backup/eviction; key becomes available to page JS when unlocked; Safari X25519 persistence bug is a compatibility warning | Acceptable only as explicitly lower-assurance web-device custody; not master-key hardware assurance |
| **Native iOS master companion — Secure Enclave P-256** | Signing and key-agreement private keys created and used in Secure Enclave; access controlled by native app/Keychain | Strongest documented iOS custody; private key need not enter JavaScript or PHP; can enforce local user presence | Requires native app, platform-specific release/maintenance, P-256 protocol compatibility, and a carefully authenticated PWA↔companion request/response protocol | **Recommended for the master phone if hardware-backed authority is a requirement** |
| **Native iOS companion — Ed25519/X25519 in Keychain** | Native app stores Curve25519 key material in Keychain; not Secure Enclave-backed under Apple's documented constraints | Preserves Phase 1.3 curve choice and native app boundary | Private key is not held by Secure Enclave; it is protected at rest by Keychain but may be loaded into app memory for operations | Viable only if owner accepts non-enclave Curve25519 custody; do not describe it as hardware-backed Secure Enclave |
| **Native Android companion — Android Keystore/StrongBox** | Hardware-backed where device hardware and API report it; otherwise software-backed Keystore | Can keep private keys out of app process for supported algorithms; StrongBox may provide stronger isolation | Algorithm/hardware support varies by OEM, Android version, and key purpose; must check actual security level and fallback behaviour | Candidate companion path; requires device matrix and hardware-backed attestation tests |
| **Hybrid PWA + native master companion** | Master authority keys in native secure storage; PWA handles UI and client-side encrypted content | Retains web delivery while moving the highest authority to protected native custody | Deep-link/Universal Link/app handoff must authenticate requests and responses; native app and PWA version skew; user experience and recovery complexity | Best fit with one master phone plus web clients, subject to protocol design and owner acceptance |

## 6. Recommended master-phone model

1. The master phone's normal authority is exercised by a native companion, not by a private key stored in the PWA's JavaScript heap or IndexedDB.
2. The companion creates its master signing and key-agreement keys locally. On iOS, the preferred custody candidate is two separate Secure Enclave P-256 keys protected by local user verification.
3. The public keys and signed master identity are registered with the SentryIQ application as public metadata. The private keys never leave the companion's protected key store.
4. The PWA prepares a canonical, human-readable approval request containing candidate device identity, public-key fingerprints, requested scopes, expiry, challenge, protocol version, and registry epoch.
5. The companion independently displays the meaningful approval details, obtains fresh local user verification, signs the canonical request, and returns only the signature and signed statement.
6. The PWA and all relying components verify the master signature, challenge, scope, expiry, and epoch. The application host may relay/store the signed grant but cannot change it.
7. The native companion must not sign arbitrary bytes supplied silently by the PWA. It must parse and enforce an allowlisted request schema, show the device and requested permissions, reject unknown operations, and rate-limit signing.
8. If the companion is unavailable, the PWA must not silently assume master authority. Emergency replacement uses the separately defined offline recovery ceremony.

The handoff mechanism (Universal Links/custom URL scheme, app extension, or another native bridge) is **not selected** here. It must be threat-modelled for origin binding, replay, app impersonation, request substitution, response spoofing, and malicious PWA code before implementation.

## 7. Browser/PWA security controls — minimum regardless of companion

- Enforce a strict CSP with nonce/hash-based script policy and no untrusted inline script. Pin third-party script assets or eliminate them from sensitive key paths.
- Use Subresource Integrity for externally loaded scripts where supported and appropriate; bundle security-critical code locally and review every dependency update.
- Keep the sensitive unlock/signing surface minimal. Do not load analytics, advertising, tag managers, remote widgets, or unreviewed scripts on key-handling pages.
- Require HTTPS, strict origin checks, CSRF protection, no-store responses for key operations, and short-lived challenges bound to origin, operation, device, and epoch.
- Do not persist plaintext or usable private key material in localStorage, sessionStorage, Cache Storage, service-worker caches, URLs, or logs.
- If non-extractable CryptoKeys are persisted in IndexedDB, treat this as browser-managed persistence only. Test read/write across restart, upgrade, private browsing, storage eviction, backup/restore, and supported browser versions.
- Clear best-effort transient byte buffers on lock/logout and invalidate in-flight decryptions. Document that JavaScript memory zeroing cannot guarantee erasure of all engine/OS copies.
- Lock immediately on explicit logout, device revocation, and relevant page lifecycle events; enforce elapsed-time checks when a suspended mobile page resumes.
- A verifier report can attest measured release bytes. It cannot prove that the browser executed only those bytes, that an extension/OS is clean, or that the user is interacting with a trustworthy display.

## 8. Required platform test matrix

Before implementation is approved, test real devices and exact OS/browser versions rather than relying on user-agent strings or feature detection alone.

| Test | iOS Safari / PWA | Native iOS | Android browser / PWA | Native Android |
|---|---|---|---|---|
| WebAuthn PRF create/get and stable credential-bound output | Required; include platform passkeys and external security keys | Test native authentication integration separately | Required across supported authenticators | Test native credential/biometric APIs |
| AES-GCM/HKDF/Ed25519/X25519 operations and known-answer vectors | Required | Required for selected native suite | Required | Required |
| Non-extractable CryptoKey export rejection | Required | N/A for enclave keys | Required | N/A for Keystore keys |
| IndexedDB CryptoKey round-trip and eviction | Required for every persisted type; specifically test X25519 | N/A for enclave keys | Required | N/A for Keystore keys |
| Hardware-backed key creation and attestation | Not exposed as an app-selected Secure Enclave key through PWA | Verify Secure Enclave P-256 key attributes and user-presence policy | Browser does not expose a reliable hardware-backed guarantee | Verify StrongBox/TEE security level and fail closed if required level is absent |
| Same-origin script compromise exercise | Demonstrate that injected script can invoke page-accessible key operations; verify mitigations and limits | Confirm private key remains in enclave while malicious PWA cannot request unapproved signing | Same as iOS PWA | Confirm native app API validates every signed request |
| Backup, restore, device migration, lost-device recovery | Test browser profile/passkey sync and key re-enrolment behaviour | Test enclave key non-migratability and recovery ceremony | Test browser sync and authenticator portability | Test hardware key non-migratability and recovery |
| App/PWA handoff, request substitution, replay | Test Universal Link/deep-link handoff and malicious page scenarios | Test companion parser, display, signing and response authentication | Test equivalent Android App Link handoff if supported | Test companion parser and response authentication |

### Test artefacts required

- Exact device model, OS version, browser version, authenticator type/provider, and hardware security capability.
- WebAuthn PRF outputs verified as credential-bound without recording the secret output itself.
- Official cryptographic test-vector results and cross-platform interoperability records.
- Hardware-backed key attributes/attestation where the platform supports it; redact unique device identifiers.
- IndexedDB persistence/restart/eviction test results, including X25519.
- App handoff threat tests and negative tests for unknown signing operations.
- Clear pass/fail criteria and minimum supported OS/browser versions.

## 9. Decisions and gates

**Recommended direction:** Hybrid PWA + native master companion. The master authority should use a native hardware-backed key on the owner's phone if the project intends to claim hardware-backed master authority. The PWA remains the application interface and may remain a client for additional devices under a lower, explicitly documented browser custody level.

**Cryptographic-profile change required:** Phase 1.3's Ed25519/X25519 proposal must be reviewed against iOS Secure Enclave's P-256-only key restriction. The likely master-phone profile is P-256 ECDSA signing plus separate P-256 ECDH key agreement inside Secure Enclave, while verifier and release signing retain their own independent profiles. The final P-256/HPKE interoperability profile must be proven with native CryptoKit and browser clients before it replaces the proposal.

**Owner decisions required before implementation:**
- Whether to approve a native master companion.
- Whether hardware-backed Secure Enclave custody is a hard requirement for master authority.
- Whether to revise the master/device authority curve profile to P-256 for platform custody, or explicitly accept software-backed Ed25519/X25519 custody.
- The minimum supported iOS/Safari and Android/browser versions.
- Whether additional devices may use browser-managed keys with a lower assurance tier.

No implementation or key generation should begin until these decisions are recorded. The current design remains proposed.

## 10. Completion checklist

- [x] Assess repository browser/passkey/Gallery key flows and absence of a native companion.
- [x] Establish Safari PRF, WebCrypto Ed25519/X25519, and native HPKE API support constraints from current platform documentation.
- [x] Distinguish non-extractable browser keys from hardware-backed Secure Enclave keys.
- [x] Identify Safari IndexedDB X25519 persistence issue as a test gate, not a universal platform conclusion.
- [x] Compare PWA-only, native companion, and hybrid custody models.
- [x] Recommend native master companion if hardware-backed master authority is required.
- [ ] Owner decision on native companion and master authority algorithm profile.
- [ ] Real-device interoperability and hardware-backed custody evidence before implementation.

**Conclusion:** Phase 1.5 finds that a PWA can support client-side encryption and passkey-derived wrapping, but it cannot by itself promise Secure Enclave custody for SentryIQ's arbitrary master-authority key. The master-phone assurance target requires a native companion or an explicit acceptance of browser/software-key limitations. Phase 1.6 should not finalise key-envelope distribution until this decision is made.
