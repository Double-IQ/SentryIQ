# Isolated private-host attestation FPM adapter

**Reference deployment template only. Not deployed or approved for production.** This adapter is designed for a dedicated PHP-FPM pool under a separate OS identity. It must not be exposed through the normal SentryIQ PHP-FPM pool and must not be placed in the public document root.

## Required boundary

- The FPM pool runs as a dedicated sentryiq-attestor OS user, distinct from the SentryIQ web/PHP-FPM identity.
- The attestor identity has read-only access to only the approved application inspection paths.
- The private data directory is owned by the attestor identity, exact mode 0700, and outside the document root.
- The JSON service config and Ed25519 signing key are owner-owned regular files with exact mode 0600.
- The pre-provisioned nonce lock is a regular owner-owned file with exact mode 0600; the nonce store fails closed if it is absent or unsafe.
- The FPM socket is private and accessible only to the reverse-proxy identity and the attestor service.
- The HTTPS reverse proxy exposes only the exact POST /private-host-attestation route, rejects duplicate/combined Authorization and Content-Type headers, rejects query strings, and limits request bodies to 4 KiB.
- No public PHP route may read the signing key or invoke the collector.

If the hosting provider cannot supply this isolation, do not weaken the design. Use a separately approved isolated host/service or an independently reviewed trust-boundary redesign.

## Install layout

Example paths (replace with actual provider-approved paths):

- Application source: /srv/sentryiq/app
- Entrypoint: /srv/sentryiq/deploy/private-host-attestation/fpm-entrypoint.php
- Public document root: /home/sentryiq/public_html
- Private data: /srv/sentryiq-private (mode 0700, attestor-owned)
- Private config: /srv/sentryiq-private/private-host-attestation.json (mode 0600)
- Signing key: /srv/sentryiq-private/collector.key (mode 0600)
- Nonce lock: /srv/sentryiq-private/private-host-nonces.lock (mode 0600)
- FPM socket: /run/php-fpm/private-host-attestation.sock

The entrypoint and application code must be installed outside the document root. The PRIVATE_HOST_ATTESTATION_CONFIG FastCGI parameter must be set by server configuration, never derived from a request header or query parameter.

## Private JSON configuration

Create the JSON file in the private data directory. This is a schema example, not a ready-to-use configuration:

~~~json
{
  "public_web_root": "/home/sentryiq/public_html",
  "private_data_directory": "/srv/sentryiq-private",
  "signing_key_path": "/srv/sentryiq-private/collector.key",
  "expected_files": {
    "app/Updates/UpdateManager.php": "REPLACE_WITH_APPROVED_LOWERCASE_SHA256"
  },
  "private_config": {
    "runtime-bootstrap": {
      "path": "runtime/bootstrap.php",
      "sha256": "REPLACE_WITH_APPROVED_LOWERCASE_SHA256"
    }
  },
  "monitored_directories": [
    "app/Updates"
  ],
  "node_tokens": {
    "integrity-a": "REPLACE_WITH_DISTINCT_RANDOM_URL_SAFE_TOKEN_A",
    "integrity-b": "REPLACE_WITH_DISTINCT_RANDOM_URL_SAFE_TOKEN_B"
  }
}
~~~

Populate the inventories only from an independently verified release and independently approved private-configuration baseline. Never derive the expected hashes from the live host being attested. Do not reuse Node A and Node B bearer credentials.

Provision the directory and files as the service owner, with exact modes. For example, after the provider has approved the paths and identity:

~~~sh
install -d -o sentryiq-attestor -g sentryiq-attestor -m 0700 /srv/sentryiq-private
install -o sentryiq-attestor -g sentryiq-attestor -m 0600 /dev/null /srv/sentryiq-private/private-host-nonces.lock
# Install the reviewed JSON config and base64 Ed25519 secret-key file as 0600.
~~~

Do not generate or install production credentials as part of a repository change.

## PHP-FPM pool example

Provider-level PHP-FPM configuration is required; a cPanel account-level PHP setting is not equivalent to a separate OS identity.

~~~ini
[private-host-attestation]
user = sentryiq-attestor
group = sentryiq-attestor
listen = /run/php-fpm/private-host-attestation.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
clear_env = yes
security.limit_extensions = .php
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = on
php_admin_value[open_basedir] = /srv/sentryiq/app:/srv/sentryiq/deploy/private-host-attestation:/srv/sentryiq-private:/tmp
php_admin_value[expose_php] = Off
php_admin_value[allow_url_fopen] = Off
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen
~~~

The service code requires PHP 8.1+ with Sodium and POSIX extensions. Confirm the exact PHP-FPM pool configuration, process identity, filesystem ACLs and socket permissions with the provider. The proxy user must not be able to read the private config or signing key.

## Nginx FastCGI route example

This is a reference for an Nginx front end. It is not a cPanel/Apache configuration and must be reviewed against the actual provider's Nginx version and configuration. Place the exact-match location inside the canonical HTTPS virtual host:

~~~nginx
location = /private-host-attestation {
    if ($request_method != POST) { return 405; }
    if ($args != "") { return 400; }
    if ($http_authorization ~ ",") { return 400; }
    if ($http_content_type ~ ",") { return 400; }

    client_max_body_size 4k;
    client_body_timeout 5s;
    fastcgi_read_timeout 15s;
    fastcgi_request_buffering on;

    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /srv/sentryiq/deploy/private-host-attestation/fpm-entrypoint.php;
    fastcgi_param SCRIPT_NAME /private-host-attestation;
    fastcgi_param PRIVATE_HOST_ATTESTATION_CONFIG /srv/sentryiq-private/private-host-attestation.json;
    fastcgi_param HTTP_AUTHORIZATION $http_authorization;
    fastcgi_param CONTENT_TYPE $content_type;
    fastcgi_pass unix:/run/php-fpm/private-host-attestation.sock;
}

location /private-host-attestation {
    return 404;
}
~~~

The Nginx configuration must preserve duplicate-header rejection. The FPM entrypoint independently rejects inconsistent FastCGI/server header values and the framework-neutral handler rejects duplicate header names and invalid bearer/content-type values. TLS certificate, canonical host routing, request-size limits and reverse-proxy ownership remain provider responsibilities.

## Acceptance before enabling the route

1. Verify the FPM process UID differs from the public SentryIQ PHP-FPM UID.
2. Verify the public identity cannot read the private config, nonce state, lock or signing key.
3. Verify the attestor identity cannot write application source, release files or policy inventories.
4. Verify only the exact canonical HTTPS POST route reaches the dedicated FPM socket.
5. Verify duplicate Authorization/Content-Type headers, comma-combined values, query strings, non-POST methods and bodies over 4 KiB are rejected.
6. Verify A/B tokens map to their fixed node identities and replayed node/nonce pairs return 409.
7. Verify valid requests return only the signed envelope with no-store headers; no file contents, tokens, config values or private paths are returned.
8. Inject collector, nonce-store, socket and upstream failures; all must fail closed and produce the independent Node A alert.
9. Run the full real Cloudflare-to-host exchange before marking the integration complete.

No service, FPM pool, reverse-proxy route, key, credential, inventory, or production host configuration is created by this template.
