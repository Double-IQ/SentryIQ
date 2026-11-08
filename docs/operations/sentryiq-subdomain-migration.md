# SentryIQ subdomain migration runbook

Status: planning only. No DNS, hosting, runtime configuration, or production files have been changed.

## Target

- Current application URL observed in tracked page metadata: `https://bichet.co.za/SentryIQ`
- Proposed canonical application origin: `https://sentryiq.bichet.co.za`
- The old URL should remain available during a controlled transition. Do not redirect it until the new origin has passed the complete authentication and storage test plan.

## Important findings from the repository audit

1. **The installed origin is stored in protected runtime configuration.** First-run setup derives `base_url` from `SERVER_NAME` and the deployed script path, then writes it into both the root `sentryiq_config.php` pointer and the protected runtime configuration. The passkey handlers read the root pointer configuration. These files are not tracked in Git and must be handled as protected production configuration, not overwritten by a code deployment.
2. **WebAuthn origin and RP ID are coupled today.** `app/Auth/PasskeyAuth.php` and `app/Auth/GalleryPasskeyAuth.php` derive both the expected browser origin and WebAuthn RP ID from `base_url`. The old host yields RP ID `bichet.co.za`; the new host would yield `sentryiq.bichet.co.za`. Existing passkey credentials are scoped to the old RP ID and will not work with the new RP ID. Do not change `base_url` before choosing and testing a passkey migration strategy.
3. **Recommended security posture:** use the new host as its own RP ID and re-enrol passkeys after authenticating through the existing recovery/password flow. This gives the app a narrower WebAuthn scope. First inspect only the credential count and confirm a tested recovery path; never export or expose credential secrets. If preserving existing credentials is required, separately assess an explicit parent-domain RP ID (`bichet.co.za`) as a compatibility exception, including the expanded subdomain trust boundary and exact-origin server validation. Do not silently broaden the RP ID.
4. **Gallery passkeys are coupled too.** Gallery passkey verification derives its RP ID and expected origin in `app/Auth/GalleryPasskeyAuth.php`. Test Gallery key-envelope recovery and passkey re-enrolment, not just ordinary vault login.
5. **Session cookies are host-only.** The security bootstrap sets Secure, HttpOnly, SameSite=Strict, path=/ cookies without a Domain attribute. Users should expect to authenticate again at the new hostname. Do not set a parent-domain cookie just to carry sessions across hosts.
6. **Backblaze B2 CORS is origin-specific.** The operations guide requires the exact application origin, and the current bucket policy was configured for `https://bichet.co.za`. Add `https://sentryiq.bichet.co.za` as an exact allowed origin before testing browser transfers; retain the old origin during transition only if still needed. Do not use wildcard origins. Verify PUT, GET, HEAD (if used), and DELETE.
7. **Absolute old-origin metadata exists.** The main page contains absolute Open Graph image URLs pointing to `https://bichet.co.za/SentryIQ`. Replace these with safe origin-relative or canonical new-origin URLs as part of the release. Audit all other generated links and email templates before cutover.
8. **Application URLs are otherwise largely relative.** The passkey browser requests use same-origin relative paths, which is good. The B2 endpoint is derived from protected storage configuration and its host is added to Gallery CSP dynamically.
9. **No tracked service worker or web-app manifest was found in the repository tree at the time of this audit.** If one is added before migration, its scope, start URL, cache contents, and update behavior must be included in the migration test.

## Required pre-cutover checks

- [ ] Confirm the hosting plan supports the subdomain and identify the exact document root for `sentryiq.bichet.co.za`.
- [ ] Confirm the new document root will contain only the intended SentryIQ public application files; keep the protected data directory outside it.
- [ ] Confirm DNS A/AAAA/CNAME records and HTTPS certificate for the new hostname. Do not change the old hostname yet.
- [ ] Take and verify a backup of the application files, database (if applicable), and complete protected runtime directory. Keep secrets out of Git and support tickets.
- [ ] Confirm the exact installed `base_url` values in the root pointer config and protected runtime config without disclosing their contents.
- [ ] Record only the number of registered vault passkeys and Gallery passkey envelopes. Confirm password/recovery access before changing RP ID.
- [ ] Decide and document whether passkeys will be re-enrolled under RP ID `sentryiq.bichet.co.za` (preferred) or whether a parent-domain RP ID compatibility exception is justified.
- [ ] Update exact B2 CORS origins and test encrypted upload, download, and delete from the new origin.
- [ ] Review CSP, redirects, cookie settings, email links, update endpoints, and all absolute URLs.
- [ ] Test password + 2FA unlock, passkey registration/login, recovery, vault lock/logout, CSRF-protected actions, Gallery passkey unlock/recovery, B2 operations, and iPhone Safari.
- [ ] Confirm both Integrity Nodes monitor the new canonical origin and signed release manifest before cutover.
- [ ] Keep the old URL available for a defined rollback window. Avoid a blanket redirect until all tests pass.
- [ ] After cutover, verify that the old origin cannot serve a second active copy of the application or create ambiguous authentication/security behavior. Then retire it deliberately.

## Cutover sequence

1. Prepare the subdomain document root, DNS, and TLS without modifying the current deployment.
2. Deploy the same reviewed release to the new document root, preserving the protected runtime and data paths. Do not run first-run setup on the new host.
3. Apply the reviewed runtime configuration and RP ID strategy. Update canonical metadata and B2 CORS.
4. Run the complete test matrix on the new origin with a test account or confirmed recovery path.
5. Point users to the new canonical origin only after tests pass. Keep the old origin stable during the rollback window.
6. Update Integrity Node targets and verify signed-manifest checks from both nodes.
7. Retire or redirect the old origin only after explicit validation and a backup.

## Safety constraints

- Never copy runtime secrets into the repository or paste them into chat.
- Never expose `sentryiq_config.php`, `passkeys.json`, Gallery key files, B2 credentials, or session contents.
- Do not delete old passkeys, Gallery envelopes, data directories, or the old deployment as part of the initial cutover.
- Do not use a parent-domain session cookie to simplify migration.
- Treat a successful DNS lookup or HTTP 200 as insufficient; authentication, cryptographic recovery, and encrypted storage flows must all pass.
