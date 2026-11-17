# Native PHP release-attestation verification

The application updater verifies the downloaded release ZIP's GitHub/Sigstore
attestation before it extracts the archive or writes any application files.
Verification uses the native PHP `k2gl/sigstore-verify` implementation; it
does not invoke GitHub CLI, `exec`, `shell_exec`, or `proc_open`.

## Private runtime configuration

Add this key to the existing private `sentryiq_config.php` array:

```php
'sigstore_vendor_autoload' => '/absolute/private/path/to/vendor/autoload.php',
```

This setting belongs in the **private** configuration file
`<data_dir>/sentryiq_config.php`, created by SentryIQ first-run setup. When
the sibling `sentryiq-tuf-patched-private/vendor/autoload.php` exists beside
`httpdocs`, first-run setup discovers that exact private autoloader and writes
its resolved absolute path into the private config. If it is absent or unsafe,
the setting is written as empty and update installation remains fail-closed
until a valid private path is configured. The small
`httpdocs/sentryiq_config.php` pointer file contains only the private
`data_dir` and base URL; do not put Sigstore settings in that public-web-root
pointer. The path must point to a Composer autoloader outside the public web
root and must load exactly `k2gl/sigstore-verify 1.6.1` and patched
`k2gl/tuf 1.2.1`; the updater checks these installed package versions at
runtime and fails closed on a mismatch. Keep the entire vendor directory
private. Never copy Composer dependencies into `httpdocs`.

The updater creates its persistent TUF root store at
`<data_dir>/sigstore-tuf/`, with private directory/file permissions. The
first verification starts from the package's bundled
`sigstore-tuf-root.json`; later verifications load the persisted root. A
root is persisted only after the TUF updater completes refresh and validates
the `trusted_root.json` target. A corrupt or unsafe persisted root fails
closed; it is never silently replaced with the bundled bootstrap root.

## Verification sequence

1. Download the release ZIP and checksum over HTTPS and verify the checksum.
2. Resolve the release tag through GitHub's commit API.
3. Query GitHub's attestations API using the ZIP SHA-256 digest.
4. Accept only an attestation entry whose repository ID is the canonical
   SentryIQ repository ID, and download its bundle from an HTTPS Azure Blob
   host without following redirects.
5. Refresh Sigstore TUF metadata using the persisted root or bundled bootstrap.
6. Verify the bundle's Fulcio certificate chain, exact GitHub Actions workflow
   identity and tag ref, DSSE signature, Rekor transparency-log evidence, and
   trusted-root material using the native PHP verifier.
7. Parse the authenticated in-toto Statement and require SLSA Provenance v1,
   the exact ZIP subject name/digest, canonical repository ID/name, release
   workflow path, tag ref, `push` event, GitHub-hosted runner, builder identity,
   and exactly one matching source commit.
8. Compare the attested source commit to GitHub's current resolution of the
   release tag, then apply the release trust policy.
9. Only after every check passes does the updater extract and validate the ZIP.

All failures reject the update. The checksum remains a transport/integrity
check; it is not treated as a signature or provenance substitute.

## SentryIQ application-host configuration

This updater integration belongs on the **production SentryIQ application host**.
It does not belong on HelioHost. HelioHost is the separate Node C security
host; its private Composer installation must not be treated as the production
application's dependency directory or shared with the application host.

The private updater setting belongs in
`<data_dir>/sentryiq_config.php`:

```php
'sigstore_vendor_autoload' => '/absolute/private/path/to/vendor/autoload.php',
```

First-run setup attempts to discover
`<account-root>/sentryiq-tuf-patched-private/vendor/autoload.php` on the
SentryIQ application host and stores its resolved absolute path in the private
config. This is only an optional discovery convention: if that directory is
not present or is unsafe, the setting remains empty and update installation
fails closed until the administrator installs the pinned dependencies in a
private directory on the application host and configures the actual path.
Do not copy an absolute path from HelioHost or assume both hosts share a
filesystem.

The public-web-root `sentryiq_config.php` pointer contains only `data_dir`
and base URL. It must not contain Sigstore settings or credentials. The
configured Composer autoloader must be outside the public webroot and load
exactly `k2gl/sigstore-verify 1.6.1` and patched `k2gl/tuf 1.2.1`; the
updater checks these versions at runtime. Keep the entire vendor tree private.

The updater creates its persistent TUF root store at
`<data_dir>/sigstore-tuf/`. The first verification starts from the package's
bundled `sigstore-tuf-root.json`; later verifications load the persisted
root. A root is persisted only after the TUF updater completes refresh and
validates the `trusted_root.json` target. A corrupt or unsafe persisted root
fails closed; it is never silently replaced with the bundled bootstrap root.

The release archive carries the three first-run bootstrap PHP files under
`runtime/`. The root `.htaccess` denies HTTP access to that directory.
First-run setup copies those files into the private data directory with
restrictive permissions, then removes the packaged copies. Do not expose the
`runtime/` directory or move those files into the HelioHost Node C account.

No application-host filesystem path is assumed here. The exact private vendor
path and data directory must be established on the SentryIQ application host
during its separately authorized deployment.

## Validation boundary

The parser unit tests use synthetic statements and prove that malformed or
misbound claims are rejected. They do not simulate cryptographic verification.
Cryptographic verification is performed only by `SigstoreVerifier::verify()`;
the parser's trusted-claims entry point receives the resulting authenticated
DSSE envelope. Live HelioHost native verifier and TUF persistence evidence is
recorded separately in PR #38.
