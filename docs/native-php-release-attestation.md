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
`<data_dir>/sentryiq_config.php`, created by SentryIQ first-run setup. The
small `httpdocs/sentryiq_config.php` pointer file contains only the private
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
   SentryIQ repository ID, and download its raw-Snappy-compressed bundle from
   an HTTPS Azure Blob host without following redirects. Decompress it with
   the bounded native PHP Snappy block decoder before parsing bundle JSON.
5. Refresh Sigstore TUF metadata using the persisted root or bundled bootstrap.
6. Verify the bundle's Fulcio certificate chain, exact GitHub Actions workflow
   identity and tag ref, DSSE signature, Rekor transparency-log evidence, and
   trusted-root material using the native PHP verifier.
7. Parse the authenticated in-toto Statement and require SLSA Provenance v1,
   the exact ZIP subject name/digest, canonical repository ID/name, release
   workflow path, tag ref, `push` event, GitHub-hosted runner, builder identity,
   the full workflow-definition commit extracted from the authenticated Fulcio leaf certificate's Build Config Digest extension (OID `1.3.6.1.4.1.57264.1.19`), and exactly one matching source commit. The digest accepts GitHub's documented `sha1:` prefix and is normalized to a full 40-character SHA-1; it is never inferred from the deprecated certificate `.1.3` claim or from the SLSA statement.
8. Compare the attested source commit to GitHub's current resolution of the
   release tag, then apply the release trust policy.
9. Only after every check passes does the updater extract and validate the ZIP.

The release ZIP and checksum downloads follow redirects only when each `Location`
header is HTTPS and targets the explicit GitHub release-asset host allowlist.
The GitHub API request does not follow redirects. All failures reject the update.
The checksum remains a transport/integrity check; it is not treated as a
signature or provenance substitute.

## HelioHost configuration example

With the existing directory layout where `sentryiq-tuf-patched-private`
sits beside `httpdocs`, and the private data directory is also outside
`httpdocs`, add the setting to the private
`<data_dir>/sentryiq_config.php` array using the absolute path to the
existing Composer autoloader. For example (adjust the account path to the
actual HelioHost account path):

```php
'sigstore_vendor_autoload' => '/home/ACCOUNT/sentryiq-tuf-patched-private/vendor/autoload.php',
```

Do not use `dirname(__DIR__)` here: the private config is nested under the
data directory, not beside `httpdocs`. Confirm the exact absolute path is
readable before enabling updates. Do not
move or merge the separate `sentryiq-attestation-private`,
`sentryiq-probe-private`, or TUF private directories as part of this change.

This PR does not change the live host configuration or deploy files. The new
setting is required before the production updater can apply a release; with it
absent, update installation fails closed.

## Validation boundary

The parser unit tests use synthetic statements and prove that malformed or
misbound claims are rejected. The Fulcio parser is also tested against the
actual v0.1.2 release certificate. The Snappy decoder tests cover literal and
copy operations, overlapping copies, malformed lengths, and output bounds.
These tests do not simulate cryptographic verification.
Cryptographic verification is performed only by `SigstoreVerifier::verify()`;
the parser's trusted-claims entry point receives the resulting authenticated
DSSE envelope. Live HelioHost native verifier and TUF persistence evidence is
recorded separately in PR #38.
