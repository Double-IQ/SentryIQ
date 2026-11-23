# Private host deployment attestation contract

- **Target:** Production SentryIQ application host.
- **Independent verifiers:** Integrity Nodes A and B.
- **Shared failure domain:** BTM-SA / Node 4 shares the SentryIQ host.
- **Separate host:** HelioHost is Node C only; it is not the SentryIQ application host.
- **Implementation status (2026-11-21):** Collector core, A/B HTTPS client, framework-neutral authenticated handler, durable nonce store, and regression tests are merged into `main` via [PR #99](https://github.com/Double-IQ/SentryIQ/pull/99), merge commit `043988f723c3cdb77cab586cbddc805892be2710`. No host service, listener, keys, credentials, policy baselines, or production deployment have been provisioned.

## Security boundary

Public-origin checks cover signed static assets and HTTP security headers. They cannot establish the integrity of private PHP source, private runtime files, PHP configuration, or other files outside the public webroot.

The collector must run outside the public application request path under a dedicated OS identity or equivalent platform isolation. Its signing key and policy must be inaccessible to the SentryIQ PHP-FPM/web identity. It must have read-only access to the selected application/private files and no write access to application code, release artifacts, TUF roots, Node A/B keys, Node 4 event data, or alert configuration. If the hosting platform cannot provide this boundary, private-host attestation remains unavailable and must fail closed; a public PHP endpoint holding the signing key is not an acceptable substitute.

## Implemented software

### Collector core

`app/Updates/PrivateHostAttestationCollector.php` implements read-only inspection and detached Ed25519 signing. Its constructor receives a fixed administrator-supplied policy:
- public-webroot-relative expected file paths and SHA-256 digests, with optional pinned permission modes;
- optional monitored directories, where unexpected files and symlinks are reported;
- private-data-root-relative configuration paths and approved SHA-256 digests;
- collector identity and a protected Ed25519 secret-key file.

The collector rejects invalid relative paths, symlinked inspected paths, missing/unreadable files, digest mismatches, optional permission mismatches, and discovered unexpected files or special filesystem entries (including FIFOs, sockets and device nodes) in monitored directories. For pinned files it hashes an already-open descriptor, compares device/inode identity with `lstat` before and after reading, and checks descriptor metadata for changes during the read; it does not hash a pathname after a separate check. This narrows pathname/symlink substitution races, but portable PHP path APIs cannot provide the same guarantee as OS-level `openat`/`O_NOFOLLOW` traversal. The production service must therefore run with read-only access and under an OS identity that prevents untrusted writers from modifying inspected paths during collection. It returns hashes and metadata only, never file contents. It signs both approval and rejection decisions over the exact JSON payload bytes.

The signing key must be a regular file under the private data directory with exact `0600` permissions. The collector reads it through a verified descriptor and checks device/inode identity and metadata before and after reading; it does not silently repair permissions. These PHP filesystem checks are not a substitute for OS-level ownership, ACL, race resistance, or isolation from privileged processes. The core does not itself verify a Sigstore manifest, derive the expected inventory, establish file ownership baselines, or provision the signing key.

### A/B transport client

`app/Updates/PrivateHostAttestationClient.php` accepts only `integrity-a` or `integrity-b`, a strong URL-safe bearer token, and the pinned HTTPS route `https://sentryiq.bichet.co.za/private-host-attestation`. It sends only node identity, nonce, release version, commit, manifest digest, and artifact digest. It sends no paths or expected hashes. TLS peer/host verification is mandatory, redirects are disabled, and timeouts and response sizes are bounded. The JSON envelope is passed unchanged to the independently pinned node-side verifier.

Each node must have its own bearer token, collector public key, and locally held expected file/configuration maps. Neither node may accept trust material or expected baselines supplied by the production host.

### Host request handler and replay store

`app/Updates/PrivateHostAttestationRequestHandler.php` is framework-neutral service logic, not an HTTP listener. It accepts POST JSON only, authenticates the bearer token, binds each distinct token to exactly one of the A/B node identities, rejects extra fields and caller-selected paths, and calls the collector only after the nonce callback accepts the challenge. It returns 409 for replay, 401 for authentication failure, 400 for malformed requests, and 503 for collector or replay-store failure.

`app/Updates/PrivateHostAttestationNonceStore.php` supplies a filesystem-backed nonce callback. It stores SHA-256 hashes of node/nonce pairs, uses an exclusive lock, atomically replaces a bounded state file, prunes expired entries, and fails closed rather than discarding replay history when full. Its directory must already have exact 0700 permissions, be outside the webroot, and be writable only by the isolated service identity; the constructor validates permissions and does not change an operator-supplied directory. The lock file must be pre-provisioned as a regular file with exact 0600 permissions; the store opens it without creating it or changing its mode, and verifies the opened inode against `lstat`. Existing state files must also have exact 0600 permissions. State updates use exclusive temporary-file creation, complete writes, `fflush`/`fsync`, and atomic rename.

A reference isolated PHP-FPM entrypoint now exists at `deploy/private-host-attestation/fpm-entrypoint.php`. It requires the dedicated `fpm-fcgi` SAPI, an owner-only JSON config outside the document root, a private 0700 data directory owned by the attestor UID, a 0600 config file, bounded request-body reading, no-store response headers, and fail-closed generic errors. Its deployment examples are in `deploy/private-host-attestation/README.md`; they include a separate FPM pool and an exact-match Nginx FastCGI route. CI lints the entrypoint and checks its security contract. This is reference adapter code only, not a provisioned listener or live reverse-proxy configuration. Provider-specific network routing, TLS termination, OS service identity, process supervision, key/bearer-token provisioning, policy generation, and service ownership/ACL setup remain unimplemented and unverified.

## Policy and release binding

The operator must produce the collector's fixed inventory from the same authenticated native Sigstore release-verification path used by the integrity nodes:
1. Verify the signed release manifest and exact ZIP with the pinned GitHub/SLSA trust policy.
2. Bind the attestation to release version, source commit, manifest SHA-256, and ZIP SHA-256.
3. Map ordinary deployed files to signed manifest entries.
4. Map private runtime files moved during first-run to the corresponding signed runtime inventory entries explicitly.
5. Pin private configuration hashes through an independently authenticated administrative approval process. A new hash is not approved merely because the host reports it.
6. Define monitored directories and permission/ownership baselines explicitly. Do not infer policy from arbitrary paths or from the live host's untrusted claims.

The current collector accepts fixed expected maps supplied by its protected bootstrap; it does not generate or cryptographically verify those maps itself. Policy generation and independent approval are deployment gates. Ownership-baseline enforcement is not currently implemented.

## Signed response and verifier contract

The collector signs exact UTF-8 JSON payload bytes using Ed25519. The node-side `PrivateHostAttestationVerifier` validates the signature, schema, exact `sentryiq-host-attestor` collector identity, timestamp window, nonce, canonical origin/repository, release identity and digests, expected file/configuration records, and overall decision. A signed rejection is retained as failed evidence; transport, signature, freshness, schema, or replay failures fail the run and activate the node's direct owner-alert route.

The payload includes:
- schema version, collector ID, issue/expiry timestamps, and exact request nonce;
- canonical SentryIQ origin and repository identity;
- release version/tag, commit, manifest digest, and artifact digest;
- bounded file results with expected/observed digests and result codes;
- bounded private-configuration results identified by policy ID and hashes only;
- an approve/reject decision.

Each A/B node generates its own fresh 32-byte nonce immediately before its collector request, independently of the Node 4 event-plane challenge. The collector handler consumes each node/nonce pair once. Node 4 is not a trust anchor and cannot override an A/B decision.

## Operational acceptance gates

Before either node is configured to rely on this capability, demonstrate on the actual production host:
1. A clean release and independently approved private-config baseline produce a valid signed approval.
2. Changes to private PHP/runtime/configuration files produce signed rejection without disclosing contents.
3. Missing, unreadable, symlinked, extra, and permission-changed files fail closed.
4. Forged signatures, altered payloads, wrong keys, wrong release identities/digests, stale/future timestamps, and replayed nonces are rejected.
5. Callers cannot request arbitrary paths, commands, or file contents.
6. The web application identity cannot read the signing key, alter policy, or alter service evidence.
7. Collector, application, and host outages trigger independent A/B alerts.
8. No Node 4 result can turn a failed or missing private-host attestation into approval.

The current tests exercise the collector, A/B client, handler, replay store, signature verification, replay rejection, token/node binding, malformed requests, unexpected files, and mismatch rejection. CI passing demonstrates software regression coverage only; it does not prove production-host isolation, ownership, network reachability, or deployment readiness.

## cPanel feasibility gate

The currently recorded production deployment plan identifies the SentryIQ application host as a cPanel account with no shell/SSH access confirmed. That hosting model does not, by itself, establish that the account can run a persistent isolated service under a separate OS identity or configure an HTTPS reverse proxy to it. Do not treat cPanel Cron Jobs, PHP-FPM, or a normal PHP web route as equivalent to the required isolation boundary.

Before implementation is considered deployable on this host, the hosting provider must explicitly confirm all of the following for the SentryIQ account:

1. A persistent PHP CLI (or equivalent) service can run under a dedicated OS user distinct from the web/PHP-FPM identity, with automatic supervision and restart.
2. That identity can be granted read-only access to only the approved application/private inspection paths, and cannot modify application code or the approved policy.
3. The signing key and nonce state can be stored outside the document root with enforced owner-only permissions and inaccessible to the web identity.
4. The service can listen on a private Unix socket or loopback-only port, not a public listener.
5. The provider can route only POST /private-host-attestation over the canonical HTTPS vhost to that private upstream, preserving duplicate-header rejection and request-size limits.
6. Service logs and failure/restart status can be inspected without exposing request credentials or signed payload contents.

If any requirement is unavailable, the current cPanel host cannot safely host this attestor under the specified trust model. The alternatives are a separately approved isolated host/service or a revised architecture with an independently reviewed trust boundary. A public PHP endpoint, cron-triggered polling script, or signing key readable by PHP-FPM is not an acceptable workaround.

## Deployment boundary

This contract applies only to the production SentryIQ application host. It is not a task for HelioHost Node C and does not describe BTM-SA / Node 4 as an independent host. The actual hosting platform's process identities, filesystem ACLs, scheduler, service/endpoint support, and TLS/reverse-proxy capabilities must be established before deployment. No host configuration or production deployment is performed by this repository change.
