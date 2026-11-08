# SentryIQ subdomain migration runbook

Status: subdomain provisioning and B2 CORS preparation completed (user-confirmed); application deployment and runtime migration have not started. No production application files or runtime configuration have been changed.

## Target

- Current application URL observed in tracked page metadata: `https://bichet.co.za/SentryIQ`
- Proposed canonical application origin: `https://sentryiq.bichet.co.za`
- The old URL should remain available during a controlled transition. Do not redirect it until the new origin has passed the complete authentication and storage test plan.

## Provisioning status (2026-11-08)

The following items have been confirmed by the operator:

- The new hostname `https://sentryiq.bichet.co.za` resolves to the hosting account.
- The operator reports that HTTPS loads without a browser certificate warning.
- Directory indexing was disabled with `Options -Indexes`; the empty document root now returns HTTP 403 rather than an index listing. The host's configured `ErrorDocument` also returned 403; this is a hosting presentation issue to tidy later, not evidence that the application is deployed.
- Backblaze bucket `SentryIQ-G1` remains private (`allPrivate`) and its CORS rule now allows both exact origins: `https://bichet.co.za` and `https://sentryiq.bichet.co.za`. Allowed operations are GET, HEAD, PUT and DELETE; allowed headers are authorization, range and content-type. No wildcard origin is configured.

These checks do **not** establish that the new document root is ready for application files or that the application works there. Before deployment, obtain the exact document-root path and verify the protected runtime directory can remain outside it. Do not run first-run setup.

## Important findings from the repository audit

1. **The installed origin is stored in protected runtime configuration.** First-run setup derives `base_url` from `SERVER_NAME` and the deployed script path, then writes it into both the root `sentryiq_config.php` pointer and the protected runtime configuration. The passkey handlers read the root pointer configuration. These files are not tracked in Git and must be handled as protected production configuration, not overwritten by a code deployment.
2. **WebAuthn origin and RP ID are coupled today.** `app/Auth/PasskeyAuth.php` and `app/Auth/GalleryPasskeyAuth.php` derive both the expected browser origin and WebAuthn RP ID from `base_url`. The old host yields RP ID `bichet.co.za`; the new host would yield `sentryiq.bichet.co.za`. Existing passkey credentials are scoped to the old RP ID and will not work with the new RP ID. Do not change `base_url` before choosing and testing a passkey migration strategy.
3. **Recommended security posture:** use the new host as its own RP ID and re-enrol passkeys after authenticating through the existing recovery/password flow. This gives the app a narrower WebAuthn scope. First inspect only the credential count and confirm a tested recovery path; never export or expose credential secrets. If preserving existing credentials is required, separately assess an explicit parent-domain RP ID (`bichet.co.za`) as a compatibility exception, including the expanded subdomain trust boundary and exact-origin server validation. Do not silently broaden the RP ID.
4. **Gallery passkeys are coupled too.** Gallery passkey verification derives its RP ID and expected origin in `app/Auth/GalleryPasskeyAuth.php`. Test Gallery key-envelope recovery and passkey re-enrolment, not just ordinary vault login.
5. **Session cookies are host-only.** The security bootstrap sets Secure, HttpOnly, SameSite=Strict, path=/ cookies without a Domain attribute. Users should expect to authenticate again at the new hostname. Do not set a parent-domain cookie just to carry sessions across hosts.
6. **Backblaze B2 CORS is origin-specific.** The operator has updated the private bucket policy to allow both exact origins, `https://bichet.co.za` and `https://sentryiq.bichet.co.za`, with GET, HEAD, PUT and DELETE plus the required authorization, range and content-type headers. Verify actual browser transfers from the new origin before cutover; do not use wildcard origins.
7. **Open Graph metadata is being made deployment-origin aware.** The migration-preparation branch changes the main page's Open Graph and Twitter image URLs to derive from the protected `base_url` setting instead of hard-coding the old origin. This change must be reviewed, merged, and deployed before cutover. Continue auditing other generated links and email templates.
8. **Application URLs are otherwise largely relative.** The passkey browser requests use same-origin relative paths, which is good. The B2 endpoint is derived from protected storage configuration and its host is added to Gallery CSP dynamically.
9. **No tracked service worker or web-app manifest was found in the repository tree at the time of this audit.** If one is added before migration, its scope, start URL, cache contents, and update behavior must be included in the migration test.

## Required pre-cutover checks

- [ ] Confirm the hosting plan supports the subdomain and identify the exact document root for `sentryiq.bichet.co.za`.
- [ ] Confirm the new document root will contain only the intended SentryIQ public application files; keep the protected data directory outside it.
- [x] Operator confirms the new hostname resolves and HTTPS loads without a browser certificate warning. Do not change the old hostname yet.
- [ ] Take and verify a backup of the application files, database (if applicable), and complete protected runtime directory. Keep secrets out of Git and support tickets.
- [ ] Confirm the exact installed `base_url` values in the root pointer config and protected runtime config without disclosing their contents.
- [ ] Record only the number of registered vault passkeys and Gallery passkey envelopes. Confirm password/recovery access before changing RP ID.
- [ ] Decide and document whether passkeys will be re-enrolled under RP ID `sentryiq.bichet.co.za` (preferred) or whether a parent-domain RP ID compatibility exception is justified.
- [x] Add the new exact B2 CORS origin while retaining the old origin. Browser upload, download and delete from the new origin remain to be tested.
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
