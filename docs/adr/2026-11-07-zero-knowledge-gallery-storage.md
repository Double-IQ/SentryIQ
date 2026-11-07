# ADR: Zero-knowledge Gallery storage with Backblaze B2

- **Status:** Proposed implementation baseline
- **Date:** 2026-11-07
- **Branch:** `feature/zero-knowledge-gallery-storage`

## Context

SentryIQ is a self-hosted PHP application with a Gallery domain and an existing encrypted local-photo implementation. The current Gallery upload path receives plaintext image bytes in PHP, normalizes images and creates derivatives on the server, then encrypts the resulting WebP originals and thumbnails with the Vault Master Key before writing them to the private runtime directory. The current image endpoint reads and decrypts those objects on the server before returning image bytes to the browser.

The existing passkey flow also sends the WebAuthn PRF result to PHP, where PHP derives a wrapping key, unwraps the Vault Master Key, and stores that key in the PHP session as `$_SESSION['master_key']`. Consequently, the current Gallery encryption is server-side application encryption at rest, not browser-side end-to-end encryption.

The target design is different: the browser must encrypt photo content before upload; neither PHP nor Backblaze should receive plaintext photo bytes or a plaintext photo-decryption key. The application remains responsible for authentication, authorization, object lifecycle and metadata access.

There are currently no user photos to migrate, so the new storage format can be introduced without a legacy-photo migration.

## Decision

Build a separate browser-controlled Gallery cryptographic identity. Do not reuse `$_SESSION['master_key']` as a Gallery encryption key, and do not send Gallery private keys, photo data-encryption keys, passkey PRF output, or plaintext photos to PHP.

### Cryptographic envelope

1. Generate a per-user public/private key pair in the browser using Web Crypto. The initial implementation uses RSA-OAEP with SHA-256 and a 3072-bit modulus; validate supported browsers and key-generation performance before production.
2. Generate a random 256-bit Gallery root key in the browser. Encrypt the private-key JWK with this root key using AES-256-GCM. The root key and plaintext private-key JWK exist only in browser memory while setting up or unlocking Gallery.
3. Wrap the Gallery root key separately for every enrolled passkey. Derive each wrapping key from that passkey's WebAuthn PRF output using HKDF-SHA-256, a dedicated random Gallery PRF salt (never the Vault's existing PRF salt), and credential-specific domain separation. Store one authenticated root-key envelope per credential ID. PRF outputs are credential-specific: two passkeys do not produce interchangeable outputs, even with the same PRF input.
4. Create a separate recovery envelope that wraps the same Gallery root key with a random user-held 256-bit recovery secret. Show the recovery secret once and require the user to save it securely before enabling uploads. The server stores only the encrypted recovery envelope, never the recovery secret. Recovery must work without a passkey and must be tested before production.
5. Keep every PRF output and the recovery secret in browser memory only. PHP verifies the WebAuthn assertion and checks credential ownership but never receives PRF output, the Gallery root key, the private key, the recovery secret or a photo DEK. The browser uses the Gallery-specific PRF output to unwrap the root key and then decrypts the private-key envelope. The Gallery PRF input salt is generated independently of the existing Vault PRF input, because the Vault flow currently sends its own PRF result to PHP.
6. Generate a fresh random 256-bit AES-GCM data-encryption key (DEK) for each photo object. Encrypt the original and every browser-generated derivative with authenticated encryption, using a fresh 96-bit nonce for each encryption and authenticated metadata that binds the ciphertext to its photo ID, object role, and format version.
7. Wrap each object DEK with the user's Gallery public key using RSA-OAEP. Store the wrapped DEK with the encrypted photo metadata. Future sharing can add one wrapped DEK per authorized recipient without re-encrypting the photo.
8. Use opaque random object identifiers. Encrypt privacy-sensitive metadata such as original filenames, album names, captions, MIME types and image dimensions. Do not use plaintext content hashes as duplicate indexes; initial release should omit cross-object deduplication to avoid equality leakage.
### Upload and download

- Browser validates/decodes the selected image, creates any required WebP derivatives and thumbnails locally, encrypts each object, then uploads ciphertext directly to a private Backblaze B2 bucket.
- PHP authenticates the user, checks Gallery permissions, allocates opaque object IDs and issues short-lived, object-scoped upload authorization. PHP must not proxy plaintext or ciphertext unless required for a narrowly scoped control operation.
- The browser uploads ciphertext directly to B2. B2 application credentials remain server-side in protected runtime configuration and are never sent to JavaScript.
- For viewing, PHP checks ownership/permissions and issues a short-lived, read-only authorization for the exact object. The browser downloads ciphertext, verifies/decrypts it locally, and creates a temporary Blob URL for display. Revoke Blob URLs when no longer needed and avoid persistent browser caches.
- Store ciphertext objects with a generic content type such as `application/octet-stream`. Do not rely on B2 object metadata for private filenames or media details.
- Keep the bucket private. Configure restrictive CORS for the exact SentryIQ origin and only the required methods/headers.
- Introduce a storage adapter so Gallery logic is not coupled to one Backblaze API. Use the B2 S3-compatible API with AWS Signature Version 4 presigned PUT/GET URLs. B2 supports SigV4 presigning; sign the exact regional host, bucket/object path, HTTP method and required headers. Do not use browser-based presigned POST. Keep URL expiry short and validate the final hosting/runtime implementation.

### Key lifecycle and recovery

- Keep B2 credentials and any server-side signing secret outside the public web root, outside the repository, and outside the application database. Restrict filesystem permissions and process access.
- The server stores public keys, encrypted private-key envelopes, wrapped per-photo DEKs and non-secret envelope metadata only.
- Never persist a plaintext Gallery private key or DEK in PHP sessions, logs, database rows, temporary files or browser localStorage.
- Support passkey-based unlock using the WebAuthn PRF extension where available. Each new passkey receives its own envelope for the Gallery root key, so multi-device enrollment does not require changing the Gallery public/private key pair. A user-held recovery secret wraps the same root key and is required before production; losing all passkeys and the recovery secret means the photos cannot be recovered.
- Recovery must preserve the zero-knowledge property: server operators must not be able to recover the private key by themselves. The recovery secret is generated client-side, displayed once, and never sent to PHP. Rotation requires the browser to unwrap the root key and create a new recovery envelope.
- Key rotation must re-wrap DEKs for the new public key in the browser. It must not require plaintext photo upload to PHP.

## Consequences and trade-offs

- PHP and Backblaze cannot decrypt stored photo objects from a database dump, B2 bucket copy, or B2 credentials alone.
- Server-side image processing, thumbnail generation, content inspection, plaintext antivirus scanning and plaintext duplicate detection are incompatible with this boundary. These operations must happen on the user's device before encryption, or be explicitly excluded.
- Ciphertext size, object count, access time and some operational metadata may remain visible to the hosting provider and B2. Encrypt sensitive metadata and use opaque object keys to reduce leakage.
- A compromised authenticated browser, malicious JavaScript served by the application origin, XSS, browser extensions, or a compromised user device can still expose photos while they are unlocked. Strong CSP, dependency minimization, output encoding, secure session handling and independent security testing remain essential.
- The current PHP session still contains the existing Vault Master Key for the current vault implementation. This ADR does not claim that the entire SentryIQ vault is zero-knowledge. The Gallery cryptographic identity must be independent, and existing passkey handling must not be mistaken for a client-only Gallery key flow.
- The existing Gallery upload, derivative, local storage, and image-serving endpoints must be replaced or disabled as part of the cutover. Do not leave an alternate plaintext upload or server-decryption route enabled.

## Implementation sequence

1. Add versioned Gallery crypto envelope formats and browser crypto module with unit tests and known-answer tests.
2. Redesign passkey registration/login so the browser retains PRF output; PHP only verifies WebAuthn and establishes the authenticated application session.
3. Implement Gallery identity creation, private-key wrapping/unwrapping, recovery and multi-device enrollment.
4. Add Backblaze configuration validation and a storage adapter that issues narrowly scoped, short-lived authorizations.
5. Replace the current PHP multipart upload and server-side image processing with browser-side derivative generation, encryption and direct ciphertext upload.
6. Replace server-side image decryption with authenticated ciphertext download and browser-side decryption.
7. Remove or fail-closed all legacy plaintext/server-decryption Gallery paths.
8. Test authorization boundaries, ciphertext tampering, nonce handling, replay, expiry, cross-user access, key recovery, key rotation, CSP/XSS mitigations, and B2 bucket privacy before enabling production uploads.

## Acceptance criteria

- A downloaded B2 object is not a viewable image and contains no plaintext photo bytes.
- PHP upload/download endpoints never receive plaintext photo bytes, Gallery DEKs, Gallery private keys or passkey PRF output.
- A database and B2 bucket compromise, without a user's unlocked private key or recovery secret, is insufficient to decrypt photos.
- Every upload and download authorization is authenticated, object-scoped, method-scoped and short-lived.
- No B2 application credential or private Gallery key is present in browser source, public files, Git history, logs or the database.
- The old server-side Gallery upload and image-decryption routes cannot be used as a fallback.
- A documented recovery and multi-device path is tested before production use.
