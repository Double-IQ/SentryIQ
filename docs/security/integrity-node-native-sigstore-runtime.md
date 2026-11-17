# Scheduled Integrity Node runtime with native Sigstore verification

This is the concrete composition contract joining the native verifier, the public-origin node, the scheduled runner and (for A/B) the Node 4 challenge exchange.

## Per-node private bootstrap

The protected PHP config file loaded by `bin/integrity-node-run.php` must return one `IntegrityNodeScheduledRunner`. It is created independently on each node host. The code below is the shared composition pattern; substitute only that host's private paths, signer key, alert transport, release resolver and (for A/B) Node 4 token. Never copy one node's private configuration or signing key to another node.

The deployed-release resolver reads the live `/VERSION` file from `https://sentryiq.bichet.co.za`, then resolves that exact `v<version>` tag to a full commit in the canonical `Double-IQ/SentryIQ` repository. It never selects GitHub's newest release. The resolver fails closed if the public VERSION file or matching tag cannot be read. The node's `installed_version` anti-rollback baseline comes from its own private monotonic state store, not from the public origin.

## Common construction pattern

Load the classes from the SentryIQ application code, then create the private native adapter and node-specific signer:

```php
use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityNodeB;
use SentryIQ\Updates\IntegrityNodeC;
use SentryIQ\Updates\IntegrityNodeScheduledRunner;
use SentryIQ\Updates\IntegrityNodeEventRunner;
use SentryIQ\Updates\IntegrityEventClient;
use SentryIQ\Updates\IntegrityNodeReleaseStateStore;
use SentryIQ\Updates\IntegrityDeployedReleaseResolver;
use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;
use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\NativeSigstoreIntegrityAttestationVerifier;

// These values are supplied only by this host's protected configuration.
$nodeId = 'integrity-a'; // exactly one of integrity-a, integrity-b, integrity-c
$signer = new IntegrityReportSigner($nodeId, $base64Ed25519SecretKey);
$releaseState = new IntegrityNodeReleaseStateStore($privateDataDirectory, $publicWebRoot);
$resolveDeployedRelease = new IntegrityDeployedReleaseResolver();

// Initialize this once, manually, after independently confirming the known-good
// release already deployed on this node's target. Do not run this on every cron.
// $releaseState->initializeBaseline('<verified-version>', '<verified-40-character-commit>');

$attestation = NativeSigstoreIntegrityAttestationVerifier::fromPrivatePaths(
    $privateVendorAutoload,
    $privateDataDirectory
);

// This callable must send directly from this node/provider to the owner.
// It must throw unless delivery succeeds. It must not depend on Node 4.
$directOwnerAlert = static function (string $nodeId, string $reason, array $context): void {
    // Invoke this host's separately configured mail/webhook transport.
    // Do not return normally unless the transport confirms delivery.
};

// Empty means check every static asset in the signed manifest; a non-empty list is a subset.
$publicPathSubset = [];

// Construct only the verifier matching this host's identity.
$node = match ($nodeId) {
    'integrity-a' => new IntegrityNodeA($signer, $attestation, null, $directOwnerAlert),
    'integrity-b' => new IntegrityNodeB($signer, $attestation, null, $directOwnerAlert),
    'integrity-c' => new IntegrityNodeC($signer, $attestation, null, $directOwnerAlert),
    default => throw new RuntimeException('Unknown Integrity Node identity.'),
};

// Adapt the scheduled runner's 8-argument contract to the node's verify()
// method. The native Sigstore adapter is called twice inside that method:
// once for release-manifest.json and once for the exact release ZIP.
$verify = static fn(
    string $manifestPath,
    string $artifactPath,
    string $version,
    string $commit,
    string $installedVersion,
    string $origin,
    array $publicPaths,
    string $nonce
): array => $node->verify(
    $manifestPath,
    $artifactPath,
    $version,
    $commit,
    $installedVersion,
    $origin,
    $publicPaths,
    $nonce
);

$eventRunner = null;
if ($nodeId === 'integrity-a' || $nodeId === 'integrity-b') {
    $node4Client = new IntegrityEventClient(
        'https://sentryiq.bichet.co.za/integrity_event.php',
        $nodeId,
        $node4BearerToken
    );
    $eventRunner = new IntegrityNodeEventRunner($node4Client, $directOwnerAlert);
}

return new IntegrityNodeScheduledRunner(
    $nodeId,
    new IntegrityReleaseArtifactFetcher(),
    $resolveDeployedRelease, // callable(): version, commit from live VERSION + canonical Git tag
    $verify,
    $directOwnerAlert,
    $privateDataDirectory,
    $publicWebRoot,
    'https://sentryiq.bichet.co.za',
    $publicPathSubset, // [] means every signed static public asset; otherwise a subset
    $releaseState,
    $eventRunner
);
```

The signed release manifest carries a `public_http_files` list containing only byte-verifiable static assets. Dynamic PHP endpoints are not compared with their packaged source bytes; private runtime files remain outside HTTP checks. Leave `$publicPathSubset` empty to check every signed static asset, or provide a subset.

The CLI preloads the node classes, native verifier and runtime dependencies before requiring the protected config file. The config file only needs to construct the host-specific objects and return the runner. The CLI validates the config file path and requires it to return the runner. The private monotonic state baseline must already exist; first-run bootstrap is an explicit one-time administrator action.

## Node-specific boundaries

- **Node A:** use only the A signing key, A bearer token and A host's private vendor/data directories. Configure a Node 4 event client and event runner. Keep direct alerts independent of Node 4.
- **Node B:** use only the B signing key, B bearer token and B host's private vendor/data directories. It must be hosted and administered independently of A. Configure its own Node 4 client and event runner, plus its own direct alerts.
- **Node C (HelioHost):** use only the C signing key and HelioHost private vendor/data directories. Do not construct a Node 4 client or event runner. Its scheduler creates a local random nonce and direct-alerts from HelioHost.

Node 4 / BTM-SA is on the same host as SentryIQ. It is not an independent host failure domain. A and B must remain able to alert the owner directly if the SentryIQ/Node 4 host is down.

## CLI and schedule

Set `SENTRYIQ_INTEGRITY_NODE_CONFIG` to the absolute path of this host's protected PHP config, then run:

```sh
php /absolute/private-or-code-path/SentryIQ/bin/integrity-node-run.php
```

Create one independent schedule per A/B/C host. Do not place all three node schedules or private keys on the SentryIQ/Node 4 host.

## Per-node anti-rollback state

Each A/B/C host keeps its own `integrity-release-state.json` in its private data directory. The baseline is initialized once with a release version and commit that the administrator has independently confirmed as the known-good deployed build. A run is serialized with an exclusive lock; older versions and same-version/different-commit tag changes are rejected. The state advances only after the node returns an approved verification result. A rejected or incomplete check never advances the pin. Do not initialize the baseline from the live `/VERSION` response alone.

## Deployment gates not fabricated by this code

Before a host can run this bootstrap, its administrator must supply and test: the deployed-release resolver, exact public path allowlist, node-specific Ed25519 key, independent alert transport, private vendor autoload path, private data directory and (for A/B) unique Node 4 bearer token. Node 4 separately needs A/B public keys, matching bearer tokens, private event storage and a real alert sender.

No production endpoint, release marker, host path, recipient, provider credential or secret is invented here. The repository code and CI do not prove that any node has been provisioned, scheduled or deployed.
