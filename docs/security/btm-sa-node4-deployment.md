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

The event endpoint is not part of the user login/session flow. It accepts only
POST JSON over HTTPS, has no browser CORS surface, applies a strict body limit,
and returns no-store responses. A report must pass both its node-specific
bearer token and its Ed25519 signature.

## Private runtime configuration

The endpoint and CLI monitor first read the small `sentryiq_config.php` pointer in the application webroot, then use its `data_dir` to load the actual `<data_dir>/sentryiq_config.php` private configuration. Node 4 secrets (`integrity_event`, tokens, public keys and alert sender) belong only in that private file; they must not be copied into the webroot pointer. `IntegrityNode4RuntimeConfig` enforces that the resolved data directory is outside the webroot and that the private config is a real file inside it.

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
only by that account (mode 0700 is enforced). The state and lock files are created
with mode 0600 under a restrictive umask, and existing files with broader permissions are rejected. The endpoint refuses a storage directory outside the resolved
private data directory. Keep the per-node tokens and private signing keys out
of Git, release ZIPs, webroot, and shared configuration exports.

Generate independent random bearer tokens for A and B. Do not reuse their
Ed25519 private signing keys as bearer tokens. Install only the corresponding
public keys on Node 4. The private signing keys remain on their respective
nodes. The runtime loader requires exactly both node IDs, distinct URL-safe bearer tokens of at least 40 characters, and distinct valid Ed25519 public keys. It also pins `target_origin` to `https://sentryiq.bichet.co.za`; incomplete or misdirected configuration fails closed.

## Protocol

1. A/B use `IntegrityEventClient` to authenticate to `POST /integrity_event.php` with
   `Authorization: Bearer <node-token>` and JSON action `challenge`.
2. Challenge request binds node ID, target origin, release version, commit,
   artifact SHA-256 and manifest SHA-256.
3. Node 4 returns a random 32-byte nonce with a five-minute expiry.
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


## Scheduled processing

After a real `alert_sender` callable is configured, schedule the CLI monitor
under the SentryIQ account (for example, every five minutes):

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

The A/B constructors require a fourth argument `$notifyFailure` for attestation rejection and origin mismatch. Node C has the same mandatory direct-alert requirement. A node cannot be constructed without a separately configured owner-alert transport. The event runner requires a direct alert callback and invokes it if Node 4 cannot issue a challenge or accept the signed report:

**On Node A only** (its own host, credentials and schedule):

```php
$nodeAOwnerAlert = static function (string $nodeId, string $reason, array $context): void {
    // Deliver directly from Node A's provider to the owner.
};
$nodeA = new IntegrityNodeA($signerA, $verifyAttestation, null, $nodeAOwnerAlert);
$clientA = new IntegrityEventClient($node4Endpoint, 'integrity-a', $node4BearerTokenA);
$runnerA = new IntegrityNodeEventRunner($clientA, $nodeAOwnerAlert);
```

**On Node B only** (a different provider/account, with no Node A secrets):

```php
$nodeBOwnerAlert = static function (string $nodeId, string $reason, array $context): void {
    // Deliver directly from Node B's provider to the owner.
};
$nodeB = new IntegrityNodeB($signerB, $verifyAttestation, null, $nodeBOwnerAlert);
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
