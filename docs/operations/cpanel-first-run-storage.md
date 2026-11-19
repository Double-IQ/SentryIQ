# First-run protected storage configuration on cPanel

The first-run installer no longer guesses a private-data path from the PHP source directory. It requires an explicit `SENTRYIQ_DATA_DIR` environment value and fails closed when the value is missing or unsafe.

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
```

The owner confirms the hosting environment can expose the variable to PHP and that `open_basedir` permits the intended private directory. The exact mechanism is still provider-specific; this owner confirmation is not a runtime test. This directive must be confirmed compatible with the provider's Apache/PHP handler before it is added. If the provider does not permit it, ask support to set the variable for the subdomain's PHP process. Do not substitute a guessed path or weaken PHP `open_basedir`.

## Installer validation

Before creating the directory, the installer checks that:

- the configured value is an absolute path with no `.` or `..` path components;
- it is not a web-root-like path (`public_html`, `htdocs`, or `www`);
- its parent already exists and resolves canonically (no symlinked parent);
- it is a direct child of the cPanel account root, derived from the actual document root;
- it is not the document root or a descendant of it.

After creation, the installer additionally verifies that the resulting directory resolves outside the document root, applies mode `0700`, and can be written to by PHP.

The application must not be initialized until the variable is confirmed to reach PHP and these checks pass. A missing or invalid value is a hard stop, not a reason to fall back to a path inferred from the source tree.

## Operator check before first-run

1. Confirm the actual subdomain document root in cPanel.
2. Confirm the intended private directory is a sibling of that document root under the account home.
3. Run a controlled pre-deployment check proving `SENTRYIQ_DATA_DIR` reaches the PHP web SAPI for this subdomain.
4. Verify PHP can resolve and perform a private write/read/delete probe in the protected directory under the active `open_basedir` policy.
5. Only then upload and expose the first-run installer.

No production configuration or cPanel setting is changed by this document.
