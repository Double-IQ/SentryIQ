# SentryIQ Android master-key adapter

This Android library is the Android Keystore counterpart to the iOS Secure Enclave adapter.

## Current implementation profile

- Initial implementation floor: Android API 31. This is provisional; the final supported API/device matrix remains a qualification decision.
- Separate P-256 ECDSA signing and P-256 ECDH key pairs are generated in Android Keystore.
- StrongBox is requested first and accepted only when KeyInfo reports SECURITY_LEVEL_STRONGBOX.
- TEE-backed keys are accepted only when an injected independent attestation verifier approves both certificate chains. The default is no verifier, so TEE fallback is disabled by default.
- Software and unknown security levels are never eligible for master authority.
- Both keys require hardware-enforced local authentication and an unlocked device. The current implementation uses a 30-second authentication validity window; the companion must invoke BiometricPrompt/device-credential authentication before each sensitive operation.
- P-256 public keys are exported as SubjectPublicKeyInfo PEM. Key IDs use SHA-256 over the 64-byte uncompressed P-256 point, matching the iOS adapter.
- ES256 signatures are converted to 64-byte JOSE form and normalized to low-S. ECDH output is immediately passed through HKDF-SHA256; the raw shared secret is not returned.

## First-run and recovery

Call createInitialMasterKeyset() only after the owner explicitly approves initial Android master setup and the caller supplies two fresh, distinct attestation challenges from the trusted bootstrap flow.

Call loadExisting() for an existing identity, supplying the original challenges from the protected bootstrap receipt. Missing or partial aliases fail closed. The adapter never silently creates a replacement keyset during load, signing, or key agreement.

## TEE attestation boundary

The IndependentTeeAttestationVerifier must be implemented by a separately trusted verifier, not by code running on the Android device being attested. It must validate the certificate chain to current trusted roots, revocation status, challenge binding, application identity, verified boot state, security level, and key authorizations. The repository does not yet provide that production verifier; without it, TEE fallback is rejected.

Attestation evidence is returned to the bootstrap caller. Do not pin a static Google attestation root in this app: Android's attestation roots and revocation status are maintained upstream and must be refreshed by the independent verifier.

## Test boundary

The Gradle unit tests use ephemeral software P-256 keys only to test public-key encoding and signature conversion. They do not generate Android Keystore keys or qualify any physical device. StrongBox/TEE behaviour, biometric authentication, and attestation require a representative real-device matrix.
