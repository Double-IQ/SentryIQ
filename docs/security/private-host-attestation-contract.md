# Private host deployment attestation contract

- **Status:** Required architecture contract; collector implementation and host deployment remain outstanding.
- **Target:** Production SentryIQ application host.
- **Independent verifiers:** Integrity Nodes A and B.
- **Not a separate failure domain:** BTM-SA / Node 4 shares the SentryIQ host.
- **Not the target:** HelioHost is the separate Node C host, not the production application host.

## Why this exists

The public-origin checks verify signed static assets and HTTP security headers. They cannot prove the integrity of private PHP source, private runtime files, PHP configuration, or files outside the public webroot. A public PHP endpoint that simply hashes files is not sufficient: a compromised web application could alter its response or use any signing key readable by its PHP process.

A private host attestor must therefore have a trust boundary separate from the SentryIQ web application. If the host cannot provide that boundary, the system must report the private-code attestation capability as unavailable; it must not infer that the private files are healthy from successful HTTP checks.

## Host-side collector requirements

The collector runs on the production SentryIQ host under a dedicated OS identity or equivalent platform isolation:

- It has read-only access to the deployed application tree, the private runtime files copied during first-run, and the specific private configuration files included in the attestation policy.
- It has no write access to the application, webroot, release artifacts, TUF roots, Node A/B keys, Node 4 event store, or alert configuration.
- Its signing key is not readable by the SentryIQ PHP-FPM/web application identity. Prefer a hardware-backed or host-managed signing key. A key stored in a file readable by the web application does not provide this trust boundary.
- Its path inventory is fixed in protected collector configuration. A remote requester may supply a nonce, but may never supply arbitrary filesystem paths, commands, or file contents.
- It returns hashes and metadata only. It never returns PHP source, configuration contents, credentials, cookies, vault data, or other secrets.
- It runs independently of application request handling and continues to report failures if the SentryIQ web application is unavailable.

If the host platform cannot run a separate identity/service or protect the signing key from the web application, use a provider-supported file-integrity/deployment-attestation mechanism instead. Do not downgrade this requirement to a key embedded in the public PHP application.

## Files and expected state

The collector obtains the expected release inventory only from the authenticated native Sigstore release-verification path:

1. Verify the release manifest and ZIP using the same pinned GitHub/SLSA trust policy used by the integrity nodes.
2. Bind the report to the exact release version, source commit, manifest SHA-256 and ZIP SHA-256.
3. For ordinary deployed application files, compare the on-disk bytes with the matching signed manifest entry.
4. For packaged runtime/<name> files moved into private storage by first-run, compare the private deployed file with the corresponding signed runtime_files entry. The mapping is explicit and must not be inferred from arbitrary path names.
5. For private configuration files that are intentionally not part of the release ZIP, compare only their hashes against an operator-approved configuration baseline held outside the web application and outside the collector's writable area. Secret values are never emitted.
6. Report missing, extra, unreadable, symlinked, permission-changed, or digest-mismatched files as failures. Do not silently omit a file because it cannot be read.

The private configuration baseline must be changed only through an independently authenticated administrative procedure. A change to credentials or configuration is not automatically approved merely because the current application host presents a new hash.

## Challenge and signed response

Nodes A and B independently request an attestation using a fresh random 32-byte nonce. Authenticate each node with its own credential or mutual TLS identity; do not share a master token. The collector accepts only a nonce and a bounded request schema.

The collector returns a detached Ed25519 signature over the exact UTF-8 payload bytes. The signed payload contains at least:

- schema version, collector identity/version, issue and expiry times, and the exact request nonce;
- canonical SentryIQ origin and canonical repository identity;
- release version, tag, source commit, manifest digest and ZIP digest;
- a bounded list of fixed-policy file results, each containing path, expected digest, observed digest and result;
- bounded private-configuration hash results, containing policy identifiers and hashes only;
- overall approve or reject decision and explicit mismatch reasons.

The response is short-lived, nonce-bound, and single-use from the verifier's perspective. Nodes A and B pin the collector public key independently. They verify the signature over the exact received payload bytes, validate the nonce and freshness, and compare the release identity with their own independently verified release. Node 4 is not a trust anchor for this process.

### Verifier payload contract implemented for Nodes A and B

The node-side `PrivateHostAttestationVerifier` accepts a JSON envelope containing base64 `payload` bytes and a base64 Ed25519 `signature`. The signature covers the exact decoded payload bytes. The signed payload uses `schema_version: 1` and contains:

- `collector_id`, `issued_at`, `expires_at`, `nonce`;
- `target_origin`, `repository`, `repository_id`, `release_version`, `tag`, `commit`;
- `manifest_sha256`, `artifact_sha256`;
- `files`: one record for every independently pinned deployed-file path, with `expected_sha256`, `observed_sha256`, and result `match`, `missing`, `unreadable`, `symlink`, `permission_mismatch`, or `digest_mismatch`; unexpected deployed paths use result `unexpected`;
- `private_config`: one record for every independently pinned configuration policy ID, with expected/observed hashes and result `match`, `missing`, `unreadable`, or `digest_mismatch`;
- `decision`: `approve` only when every required item matches and no unexpected files exist; otherwise `reject`.

The verifier rejects an omitted expected path or policy ID, duplicate records, a changed expected digest, an unexpected approval, invalid signature, wrong release identity, wrong nonce, stale/future report, or a payload exceeding the strict size bounds. A valid signed rejection is returned as a failed attestation so the node can sign and retain the rejection evidence. A missing/invalid response throws and activates the node's direct owner-alert path.

The A/B node constructors now require a private-host verification callback in addition to release Sigstore verification, origin asset checks, header checks, and direct alert delivery. Immediately before the collector request, each node generates a fresh local 32-byte nonce with a cryptographically secure random source; this nonce is independent of the Node 4 event-plane challenge. The callback receives the release version, commit, manifest/ZIP digests, locally generated collector nonce, parsed signed manifest, and target origin. It must authenticate to the collector with that node's own credential, verify the returned envelope using a locally pinned collector public key and locally held file/config baselines, and return the verifier result. It must not accept a collector key or expected baseline supplied by the production host. A signed rejection is included in the node's own signed event report; transport, signature, freshness, or schema failures alert directly and fail the run.

This verifier and the A/B integration seam are implemented and regression-tested. The production-host collector, authenticated transport, independently approved configuration baselines, and per-node bootstrap wiring are still not implemented or deployed. Until those pieces exist, Nodes A and B must not be configured with a placeholder callback that always approves.

A missing, stale, malformed, replayed, unsigned, or mismatched response is a failed attestation and triggers each node's direct owner-alert path. No response must never be interpreted as approval.

## Evidence and failure isolation

- The collector keeps a bounded local audit log containing signed report identifiers and outcomes, not secret file contents.
- Nodes A and B retain their own accepted/rejected evidence and alert independently.
- Node 4 may correlate a summary as an additional service, but cannot suppress A/B alerts or change the collector trust key.
- Export an evidence digest or immutable copy outside the SentryIQ host where available. Evidence stored only on the shared SentryIQ/Node 4 host is not tamper-proof against host administrators.
- A host-level outage or root compromise remains a common-mode risk for SentryIQ and Node 4. Nodes A/B must detect unavailable host attestation and alert through their independent routes.

## Acceptance tests

Before this capability is called operational, prove all of the following:

1. A clean deployed release and approved private-config baseline produce a valid signed report.
2. Changing one private PHP file produces a signed rejection identifying the path and digest mismatch.
3. Changing a private runtime file moved by first-run is detected against its signed runtime_files entry.
4. Changing a private config file produces a rejection without disclosing its contents.
5. Missing, unreadable, symlinked, extra and permission-changed files fail closed.
6. A forged signature, changed payload byte, wrong collector key, wrong release identity, wrong manifest/ZIP digest, stale timestamp or replayed nonce is rejected.
7. A caller cannot request arbitrary paths or read file contents.
8. The web application identity cannot read or use the collector signing key, modify the collector policy, or alter its evidence.
9. Collector outage, SentryIQ web application outage and host outage all cause independent A/B alerts.
10. No Node 4 result can turn a failed or missing private host attestation into approval.

## Deployment boundary

This contract applies only to the production SentryIQ application host. It is not a task for HelioHost Node C and not a claim that BTM-SA / Node 4 is independently hosted. Implementation requires confirmation of the application host's supported process identities, filesystem ACLs, scheduler and service/endpoint capabilities. No host configuration or deployment is performed by this document.


## Collector core implementation status

`app/Updates/PrivateHostAttestationCollector.php` now implements the read-only signing core for the schema above. Its administrator-supplied policy is fixed at construction: public-webroot-relative file paths and SHA-256 digests, private-data-root-relative configuration paths and approved digests, a collector ID, and a protected Ed25519 secret-key file. A request can provide only the nonce and release identity fields; it cannot choose paths or retrieve file contents. The collector returns a detached signature over the exact JSON payload bytes and signs a rejection when a pinned file or configuration digest differs, is missing, is unreadable, or is symlinked.

The signing-key file must reside inside the private data directory and have no group/other permissions. The private data directory must resolve outside the public webroot. The class deliberately does not create an HTTP listener, accept arbitrary remote requests, provision OS identities, or choose its own policy. A host adapter must run it under a dedicated OS identity that cannot write the application or policy and whose key is unreadable to PHP-FPM. Do not load this class from the public application request path.

This is a collector core, not yet a deployable host service. The current core does not yet discover unexpected files or enforce per-file mode/ownership baselines, and its PHP filesystem checks do not replace OS-level isolation against a hostile privileged process. Those controls, a host-supported authenticated transport, collector key provisioning, and a verified deployment-to-policy generation process remain acceptance blockers. The existing verifier continues to fail closed on unexpected entries and permission-mismatch evidence, but this core does not yet emit those result classes.

The collector regression test exercises a clean signed approval, signed digest and permission-mismatch rejections, unexpected-file detection, invalid challenge rejection, and refusal to place private storage inside the webroot. The native integrity CI workflow now lints and executes that test on PHP 8.1 through 8.5. Passing this test does not establish host isolation or production deployment.


## A/B HTTPS transport client

`PrivateHostAttestationClient` now implements the node-side authenticated request transport. It accepts only `integrity-a` or `integrity-b`, a distinct URL-safe bearer token, and the pinned HTTPS route `https://sentryiq.bichet.co.za/private-host-attestation`. It sends only the node ID, fresh nonce, release version, source commit, manifest digest and artifact digest. It never sends file paths or expected hashes. Redirects are disabled, TLS peer and hostname validation are mandatory, request timeouts and response sizes are bounded, and non-200 or malformed responses fail closed. The returned envelope bytes are passed unchanged to the independently pinned `PrivateHostAttestationVerifier`.

This defines the A/B-to-host transport contract, not the host-side service. The route must be terminated by a host adapter that authenticates the node token, enforces one-time/fresh challenge handling, invokes the collector under its separate OS identity, and returns only the signed envelope. Do not implement this route as a PHP-FPM script that can read the collector signing key. The host adapter and service isolation remain unimplemented and must be validated against the actual hosting platform before enabling either node callback.


Example Node A callback wiring (Node B uses its own token, public key and pinned baselines):

```php
$privateHostClientA = new PrivateHostAttestationClient(
    'integrity-a',
    $collectorBearerTokenA
);
$privateHostVerifierA = new PrivateHostAttestationVerifier(
    $collectorPublicKeyA
);
$verifyPrivateHostA = static function (
    string $version,
    string $commit,
    string $manifestDigest,
    string $artifactDigest,
    string $nonce,
    array $manifest,
    string $origin
) use ($privateHostClientA, $privateHostVerifierA, $expectedFilesA, $expectedPrivateConfigA): array {
    $envelope = $privateHostClientA->request(
        $nonce,
        $version,
        $commit,
        $manifestDigest,
        $artifactDigest
    );
    return $privateHostVerifierA->assertAttested(
        $envelope,
        $nonce,
        $version,
        $commit,
        $manifestDigest,
        $artifactDigest,
        $expectedFilesA,
        $expectedPrivateConfigA
    );
};
```

Pass `$verifyPrivateHostA` as the final `IntegrityNodeA` constructor argument. Keep `$collectorBearerTokenA`, `$collectorPublicKeyA`, and both expected maps in Node A's private runtime configuration. Node B must independently use `integrity-b` and different credentials/key material. The callback example is wiring only; it cannot succeed against production until the host-side service owns and serves the pinned route.
