# Secure Gallery key-rotation validation checklist

Run this checklist only in a dedicated staging account and staging Backblaze bucket. Do not use production photos or production key stores for first validation.

## Before testing

- [ ] Confirm the staging Gallery data directory is outside the public web root and has owner-only permissions.
- [ ] Back up the staging key store, object index and rotation journal.
- [ ] Enrol at least one Gallery passkey that supports the WebAuthn PRF extension.
- [ ] Confirm the recovery code can unlock the existing Gallery before changing anything.
- [ ] Upload several test photos with original, thumbnail, preview and metadata objects.
- [ ] Record the four B2 object keys, sizes and provider-side checksums for each test photo.
- [ ] Confirm every test photo downloads and decrypts before migration.

## Keyring upgrade and second key

- [ ] Open Gallery using the existing passkey.
- [ ] Add an encryption key and confirm the UI reports it as inactive.
- [ ] Confirm the active key ID has not changed and a new upload still uses the original key.
- [ ] Lock and unlock with the enrolled passkey; confirm both keys load.
- [ ] Lock and unlock with the recovery code; confirm both keys load and every existing photo remains readable.
- [ ] Confirm the server stores only the encrypted private-key envelope, not a private JWK or root key.

## Rotation and resume

- [ ] Start rotation to the inactive key and complete the recent-passkey confirmation.
- [ ] Confirm new uploads use the target key ID.
- [ ] Confirm older photos still decrypt while migration is in progress.
- [ ] Confirm B2 ciphertext object keys, sizes and checksums remain unchanged by DEK rewrapping.
- [ ] Close Safari or terminate the PWA part-way through migration.
- [ ] Reopen Gallery, unlock it, and resume the same rotation.
- [ ] Confirm already migrated envelopes are skipped and remaining envelopes continue.
- [ ] Upload another photo during migration; confirm it uses the target key.
- [ ] Delete a photo during migration; confirm deletion and migration do not corrupt other photos.
- [ ] Leave an upload pending across a rotation attempt; confirm finalization is blocked until it commits or cleanup completes.

## Rollback and retirement

- [ ] After the inventory reaches zero old-key references, confirm the journal enters `ready_to_retire`.
- [ ] Confirm the previous key remains in the keyring and old photos remain readable during the 24-hour rollback window.
- [ ] Abort one staging rotation during the rollback window; confirm the previous key becomes active again and both keys remain.
- [ ] Start a fresh rotation and complete migration.
- [ ] Before the rollback window expires, attempt finalization; confirm the server rejects it and keeps the old key.
- [ ] After the 24-hour window expires, confirm finalization performs a fresh locked inventory check and retires the old key.
- [ ] Lock and unlock with passkey and recovery code; confirm all remaining photos still decrypt.
- [ ] Confirm the retired key ID is absent and the active key remains available.

## iOS Safari / WebAuthn PRF checks

- [ ] Test on a physical iPhone/iPad using the supported Safari version.
- [ ] Confirm passkey PRF output is returned consistently during unlock and recent-passkey confirmation.
- [ ] Confirm the keyring opens after app backgrounding, reload, and a fresh browser session.
- [ ] Navigate away from Gallery and restore it with Safari's back navigation; confirm the restored page is locked, requires a fresh unlock, and shows no decrypted object URLs.
- [ ] Confirm recovery unlock works on a second enrolled device.
- [ ] Confirm a device without the required PRF capability fails safely without modifying the keyring.

## Backblaze and network checks

- [ ] Verify signed PUT/GET/DELETE operations against the staging bucket.
- [ ] Verify bucket CORS permits the required browser methods and headers.
- [ ] Confirm object authorization is method-scoped and short-lived.
- [ ] Confirm envelope migration does not request or transfer photo ciphertext from B2.
- [ ] Interrupt network access during an envelope update; confirm the stale revision is rejected or the operation can be retried safely.
- [ ] Confirm pending/cancelling uploads remain in the authoritative key-reference inventory until their object records are safely resolved.

## Evidence to retain

- CI run links and test account identifier (never passkeys, recovery codes or secrets).
- Browser and iOS version.
- Rotation journal state transitions and key-reference counts.
- Before/after B2 object sizes and checksums.
- Any console/network errors, with tokens, signed URLs and credential IDs redacted.

Do not merge or deploy until the staging checklist is complete and the remaining failure cases are resolved.
