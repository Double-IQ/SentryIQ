# First-run protected storage configuration on cPanel

The first-run installer no longer guesses a private-data path from the PHP source directory. It requires an explicit `SENTRYIQ_DATA_DIR` environment value and fails closed when the value is missing or unsafe. It also requires a separate high-entropy `SENTRYIQ_INSTALL_TOKEN` so a random visitor cannot claim a fresh installation. The release package carries the four protected runtime templates under `runtime/`; the installer copies them from that directory into protected storage and removes the packaged copies after successful setup. Apache rules deny direct HTTP requests to `/runtime/`.

## Expected SentryIQ cPanel layout

For the currently recorded hosting layout:

```text
/home/bicheveb/
├── sentryiq.bichet.co.za/     # cPanel subdomain document root
└── sentryiq-private/          # protected runtime directory
```

The expected value is:

```text
SENTRYIQ_DATA_DIR=/home/bicheveb/sentryiq-private
```

Do not put this directory under the subdomain document root or inside `public_html`.

## Supplying the environment value

The hosting environment must expose `SENTRYIQ_DATA_DIR` to the PHP web SAPI as either an environment variable or a server variable. On Apache hosts where `mod_env` and per-directory `SetEnv` are enabled, the hosting operator may configure the following in the subdomain document root's `.htaccess`:

```apache
SetEnv SENTRYIQ_DATA_DIR /home/bicheveb/sentryiq-private
SetEnv SENTRYIQ_INSTALL_TOKEN <owner-generated-43-character-token>
```

The owner confirms the hosting environment can expose the variable to PHP and that `open_basedir` permits the intended private directory. The exact mechanism is still provider-specific; this owner confirmation is not a runtime test. This directive must be confirmed compatible with the provider's Apache/PHP handler before it is added. If the provider does not permit it, ask support to set the variable for the subdomain's PHP process. Do not substitute a guessed path or weaken PHP `open_basedir`.

## Owner-only first-run authorization

Before exposing first-run setup, generate a random token containing at least 32 URL-safe characters (recommended: 32 random bytes encoded as unpadded Base64URL, which produces 43 characters). Use a password manager's secure random generator; do not reuse an account password or place the token in Git, a ticket, email, or chat.

Expose it to PHP as `SENTRYIQ_INSTALL_TOKEN`, using the same provider-approved mechanism as `SENTRYIQ_DATA_DIR`. The installer requires the token in a dedicated password field and compares it in constant time. If the variable is absent, malformed, or the submitted token does not match, initialization is refused. The token is never written to application logs or runtime configuration.

After successful first-run initialization, remove the `SENTRYIQ_INSTALL_TOKEN` setting from the hosting environment or `.htaccess`, and remove the public `first_run.php` installer entry point from the deployed document root. Keep the protected runtime directory and pointer configuration intact. The installer also returns 404 once the pointer configuration exists, but removing the entry point is the preferred cleanup.

Never send the token to support or paste it into ChatGPT. If the provider must configure it, enter it directly through the hosting control panel or the provider's authenticated support channel.

## Installer validation

Before creating the directory, the installer checks that:

- the configured value is an absolute path with no `.` or `..` path components;
- it is not a web-root-like path (`public_html`, `htdocs`, or `www`);
- its parent already exists and resolves canonically (no symlinked parent);
- it is a direct child of the cPanel account root, derived from the actual document root;
- it is not the document root or a descendant of it.

After creation, the installer additionally verifies that the resulting directory resolves outside the document root, applies mode `0700`, and can be written to by PHP.

The application must not be initialized until both required environment values are confirmed to reach PHP, the owner token passes its format check without being disclosed, and the private-storage checks pass. A missing or invalid value is a hard stop, not a reason to fall back to a path inferred from the source tree.

## Operator check before first-run

1. Confirm the actual subdomain document root in cPanel.
2. Confirm the intended private directory is a sibling of that document root under the account home.
3. Generate a unique owner installation token and configure `SENTRYIQ_INSTALL_TOKEN` without committing or sharing it.
4. Run a controlled pre-deployment check proving both `SENTRYIQ_DATA_DIR` and `SENTRYIQ_INSTALL_TOKEN` reach the PHP web SAPI for this subdomain; report only pass/fail and token-format validity, never the token value.
5. Verify PHP can resolve and perform a private write/read/delete probe in the protected directory under the active `open_basedir` policy.
6. Only then upload and expose the first-run installer.

No production configuration or cPanel setting is changed by this document.
