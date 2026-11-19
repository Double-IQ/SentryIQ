# BTM-SA / Node 4 deployment boundary

Node 4 is the BTM-SA event and alert plane hosted on the same physical host as
SentryIQ. It is a separate application trust domain, not a separate host or
independent failure domain. A host outage or host-level compromise affects
both SentryIQ and Node 4. Integrity Nodes A and B must therefore retain their
own independent owner-alert paths.

## Components

- `IntegrityEventClient`: strict HTTPS client for A/B challenge requests and signed report submissions; verifies TLS and refuses redirects.
- `IntegrityNodeEventRunner`: binds local manifest/artifact digests into the challenge, passes the returned nonce to the existing Node A/B verifier, checks the files did not change, and submits the signed report.
- `integrity_event.php`: machine-to-machine HTTPS endpoint. It supports
  authenticated `challenge` requests and signed `report` submissions.
- `IntegrityEventReportVerifier`: verifies one signed A/B report at a time,
  including signed rejections.
- `FileIntegrityEventStore`: uses an exclusive filesystem lock and atomic
  state-file replacement to consume each challenge once and retain evidence.
- A/B Ed25519 public keys and per-node bearer tokens are supplied only through
  the private runtime configuration.
- `PrivateHostAttestationRequestHandler` is framework-neutral code for a separate
  isolated host service. It is not exposed by `integrity_event.php` or wired into
  the ordinary SentryIQ web-PHP process. Its listener/reverse-proxy adapter is a
  separate deployment gate because the collector signing key must not be
  readable by the normal web application.

The event endpoint is not part of the user login/session flow. It accepts only
POST JSON over HTTPS, has no browser CORS surface, applies a strict body limit,
and returns no-store responses. `IntegrityEventRequestDecoder` rejects duplicate JSON object fields at every depth (including equivalent escaped key spellings), malformed
objects and oversized bodies. The endpoint then enforces an exact field set for
each action: challenge requests cannot carry paths or extra claims, and report
requests contain only the signed envelope. A report must pass both its
node-specific bearer token and its Ed25519 signature.

## Private runtime configuration

The endpoint and CLI monitor first read the small `sentryiq_config.php` pointer in the application webroot, then use its `data_dir` to load the actual `<data_dir>/sentryiq_config.php` private configuration. Node 4 secrets (`integrity_event`, tokens, public keys and alert sender) belong only in that private file; they must not be copied into the webroot pointer. `IntegrityNode4RuntimeConfig` enforces that the resolved data directory is outside the webroot with exact `0700` permissions and that the private config is a regular file inside it with exact `0600` permissions. Weak permissions are rejected, never repaired automatically.

The following is a shape example only. Never commit actual values:

```php
return [
    'data_dir' => '/absolute/path/outside/httpdocs/sentryiq-data',
    'integrity_event' => [
        'enabled' => true,
        'target_origin' => 'https://sentryiq.bichet.co.za',
        // A private callable that sends one incident and returns true only on success.
        'alert_sender' => static function (array $incident, string $idempotencyKey): bool {
            // Connect this to the host's configured mail or webhook transport.
            return false;
        },
        'storage_dir' => '/absolute/path/outside/httpdocs/sentryiq-data/integrity-events',
        'node_tokens' => [
            'integrity-a' => '<unique-random-token-for-node-a>',
            'integrity-b' => '<unique-random-token-for-node-b>',
        ],
        'node_public_keys' => [
            'integrity-a' => '<base64-ed25519-public-key-a>',
            'integrity-b' => '<base64-ed25519-public-key-b>',
        ],
    ],
];
```

Before enabling the endpoint, create the dedicated storage directory under
`data_dir`, outside `httpdocs`, owned by the SentryIQ PHP account and writable
only by that account (mode 0700 is enforced). Create the lock file once during provisioning with `install -m 0600 /dev/null /absolute/path/to/integrity-events.lock`. Pre-provision `integrity-events.lock` as a regular file with exact mode 0600 before starting the endpoint; the store refuses to create or chmod this operator-supplied lock. The state file is created through exclusive temporary-file creation and atomic rename with exact mode 0600. Existing lock/state files with any other mode or a symlinked path are rejected. The endpoint refuses a storage directory outside the resolved
private data directory. Keep the per-node tokens and private signing keys out
of Git, release ZIPs, webroot, and shared configuration exports.

Generate independent random bearer tokens for A and B. Do not reuse their
Ed25519 private signing keys as bearer tokens. Install only the corresponding
public keys on Node 4. The private signing keys remain on their respective
nodes. The runtime loader requires exactly both node IDs, distinct URL-safe bearer tokens of at least 40 characters, and distinct valid Ed25519 public keys. It also pins `target_origin` to `https://sentryiq.bichet.co.za`; incomplete or misdirected configuration fails closed.


Generate two separate 48-byte random tokens (64 URL-safe characters) on a trusted administrative terminal; run the command twice and keep each output secret:

```sh
php -r 'echo rtrim(strtr(base64_encode(random_bytes(48)), "+/", "-_"), "="), PHP_EOL;'
```

Place token A only in Node 4's private `node_tokens['integrity-a']` and Node A's private runtime config; place token B only in the matching B entries. Transfer each token to its node over a secure channel. Do not paste tokens into GitHub issues, pull requests, source files, or shared logs.


## Private-host attestation is not wired into the ordinary web application

The A/B `PrivateHostAttestationClient` targets `https://sentryiq.bichet.co.za/private-host-attestation`. The repository contains the collector, verifier, nonce store and framework-neutral request handler, but intentionally does not expose that handler through the normal SentryIQ PHP web process. A real listener or reverse-proxy adapter must run under a separate OS identity with exclusive read access to the collector key and private-file inventory. Do not add a normal `.htaccess` rewrite to a PHP endpoint running under the same cPanel account: that would let a web-app compromise read the signing key and forge its own host attestation.

If the current shared cPanel account cannot provide a separate service identity and read-only access boundary, A/B private-host attestation cannot be enabled there. A/B remain fail-closed until an approved isolated service exists. Public HTTP checks must not be described as verification of private PHP or configuration files.

## Protocol

1. A/B use `IntegrityEventClient` to authenticate to `POST /integrity_event.php` with
   `Authorization: Bearer <node-token>` and JSON action `challenge`.
2. Challenge request binds node ID, target origin, release version, commit,
   artifact SHA-256 and manifest SHA-256.
3. Node 4 returns a random 32-byte nonce with a ten-minute expiry, allowing bounded native Sigstore verification before report submission.
4. The node signs a schema-v2 report containing that nonce and the same bound
   release/evidence fields.
5. The node submits action `report` with its bearer token and the detached
   signature envelope.
6. Node 4 verifies signature, identity, timestamps, evidence and exact
   challenge binding. Under one exclusive lock it consumes the challenge and
   writes the evidence record in a single atomic state update.
7. Reuse, expired challenges, cross-node tokens, wrong release bindings and
   invalid signatures fail closed.

The store is deliberately bounded at 5,000 reports and 16 MiB. It refuses
further writes when full rather than silently discarding evidence. Retention,
export and alert-delivery jobs remain follow-on components.

## Shared-host limitation

This service improves logical isolation, credential separation and evidence
handling, but does not create host-level independence. Node 4 must not be
counted as an independent monitor. Nodes A/B must continue to alert the owner
directly if Node 4 or the SentryIQ host becomes unavailable or compromised.

## Deployment status

Code and CI tests do not mean the endpoint is deployed. Runtime configuration,
private directory creation, token/key installation, HTTPS reachability,
scheduled challenge/report exchange, incident correlation and notification
delivery require separate verification on the existing SentryIQ host. No
production configuration or host files are changed by this pull request.


## Evidence and alert retention

The event store retains report evidence for seven days, prunes expired
challenges, and retains delivered alert records for thirty days. Pending alerts
are never removed by retention. The hard report cap is 5,000 records and the
alert outbox cap is 2,000 records; exceeding either cap fails closed rather
than silently dropping live evidence or pending alerts. At a fifteen-minute
schedule for both A and B, seven days produces about 1,344 reports, within the
current report cap. Schedule each A/B node no more frequently than every
fifteen minutes: verification can take several minutes and the per-node run
lock deliberately rejects overlapping jobs. Node 4 treats reports older than
thirty minutes as stale. The Node 4 monitor prunes retention before each
evaluation.

## Scheduled processing

After a real `alert_sender` callable is configured, schedule the CLI monitor
under the SentryIQ account (for example, every five minutes; this is separate from the fifteen-minute A/B node schedule):

```sh
php /absolute/path/to/SentryIQ/bin/integrity-node4-monitor.php
```

The script refuses web execution and refuses to run until the private storage,
target origin and alert transport are configured. It exits zero only when both
independent node reports are fresh and approved and the alert outbox has no
undelivered notifications. The A/B nodes still need their
own independent schedules to call `IntegrityNodeEventRunner`; Node 4's cron
does not replace those checks.


## Independent direct alerts from Nodes A and B

Node 4 shares the SentryIQ host and is not a failure-independent alert destination. Each separately hosted node must therefore configure its own direct owner-alert callback, with credentials and destination held in that node's private configuration and delivery performed from that node's own provider. The callback is invoked for attestation rejection and public-origin content mismatch; a callback delivery failure fails the node run rather than silently treating the alert as delivered.

The A/B constructors require their node-bound `PrivateHostAttestationGate`, a direct `$notifyFailure` callback and an origin-header verifier. Node C requires its own direct-alert callback and origin-header verifier, but no private-host gate. A node cannot be constructed without the required security checks and separately configured owner-alert transport. The event runner requires a direct alert callback and invokes it if Node 4 cannot issue a challenge or accept the signed report:

**On Node A only** (its own host, credentials and schedule):

```php
$nodeAOwnerAlert = static function (string $nodeId, string $reason, array $context): void {
    // Deliver directly from Node A's provider to the owner.
};
$nodeA = new IntegrityNodeA($signerA, $verifyAttestation, $privateHostGateA, null, $nodeAOwnerAlert, $verifyHeaders);
$clientA = new IntegrityEventClient($node4Endpoint, 'integrity-a', $node4BearerTokenA);
$runnerA = new IntegrityNodeEventRunner($clientA, $nodeAOwnerAlert);
```

**On Node B only** (a different provider/account, with no Node A secrets):

```php
$nodeBOwnerAlert = static function (string $nodeId, string $reason, array $context): void {
    // Deliver directly from Node B's provider to the owner.
};
$nodeB = new IntegrityNodeB($signerB, $verifyAttestation, $privateHostGateB, null, $nodeBOwnerAlert, $verifyHeaders);
$clientB = new IntegrityEventClient($node4Endpoint, 'integrity-b', $node4BearerTokenB);
$runnerB = new IntegrityNodeEventRunner($clientB, $nodeBOwnerAlert);
```

This is an injection point, not a configured transport: no email/webhook provider, credentials, or recipient are fabricated by the code. A/B are not production-ready until each host supplies and tests its own direct transport. Node 4's own alert sender also remains a separate required configuration item.


## Independent release asset retrieval

Before a node calls its verifier, it must stage the exact tagged release assets from the canonical GitHub Release. `IntegrityReleaseArtifactFetcher` downloads `release-manifest.json` and `sentryiq-<version>.zip` into a private per-release directory. The caller must supply the node's actual public webroot; the fetcher rejects any staging path inside it and rejects symlinked path components. It restricts downloads and redirects to HTTPS GitHub release-asset hosts on port 443, rejects unsafe versions, bounds the manifest to 5 MB and the ZIP to 250 MB, and writes files with private permissions. The node must then run the native Sigstore adapter against both files before using the manifest. The fetcher does not treat checksums or downloaded content as trusted by themselves.

Example staging step (run independently on each node):

```php
$assets = (new IntegrityReleaseArtifactFetcher())->fetch(
    $releaseVersion,
    $privateDataDirectory . '/integrity-releases/' . $releaseVersion,
    $publicWebRoot
);
// Pass $assets['manifest_path'] and $assets['artifact_path'] to the node verifier.
```

The fetcher is a staging component, not a scheduled runner. Each node still needs its own protected runtime configuration, release-selection policy, schedule, signing key and direct alert transport.


## Scheduled node entry point

```sh
SENTRYIQ_INTEGRITY_NODE_CONFIG=/absolute/private/path/integrity-node.php php /absolute/path/to/SentryIQ/bin/integrity-node-run.php
```

`bin/integrity-node-run.php` is CLI-only. The private PHP configuration must return a fully constructed `IntegrityNodeScheduledRunner`. The runner requires a final `IntegrityNodeVerifierBinding` that wraps the concrete `IntegrityNodeA`, `IntegrityNodeB` or `IntegrityNodeC` class for the same node ID; arbitrary verification callbacks are not accepted. The runner stages the selected release assets outside the webroot, invokes the node verifier, and for A/B performs the Node 4 challenge/report exchange. Node C generates its own nonce and never contacts Node 4. Exit status is zero only for an approved result; rejected results and operational failures exit nonzero.

The private configuration must supply a `resolveRelease` callable returning the release version and full source commit from the live `/VERSION` marker and canonical GitHub tag. The installed-version baseline is stored separately in the node's private monotonic state store. Initialize it once with `bin/integrity-node-baseline.php`, using a mode-0600 private PHP config containing only the independently confirmed known-good version, commit, manifest digest and ZIP digest. The script creates the state lock safely and refuses to overwrite an existing baseline. Delete the one-time baseline config after use. Never select GitHub's newest release blindly. The public-path allowlist, private data directory, actual webroot, signing identity, native Sigstore verifier and direct owner-alert transport are all node-local configuration.

Example construction pattern (illustrative; use that node's own paths, signer and credentials):

```php
$nodeAVerifier = new IntegrityNodeVerifierBinding('integrity-a', $nodeA);
$runner = new IntegrityNodeScheduledRunner(
    'integrity-a',
    new IntegrityReleaseArtifactFetcher(),
    $resolveDeployedRelease,
    $nodeAVerifier,
    $nodeAOwnerAlert,
    $privateDataDirectory,
    $publicWebRoot,
    'https://sentryiq.bichet.co.za',
    $publicPathAllowlist,
    $runnerAEventExchange,
);
return $runner;
```

Use separate private configuration files and cron schedules on A, B and C. A and B must each have their own Node 4 token, signing key, verifier dependencies and direct alert destination. C must use only `integrity-c` credentials and must omit the Node 4 event exchange. Do not place any of these private configurations or keys on the SentryIQ/BTM-SA host for convenience.
