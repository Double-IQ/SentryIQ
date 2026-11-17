# Scheduled Integrity Node runtime with native Sigstore verification

This is the concrete composition contract joining the native verifier, the public-origin node, the scheduled runner and (for A/B) the Node 4 challenge exchange.

## Per-node private bootstrap

The protected PHP config file loaded by `bin/integrity-node-run.php` must return one `IntegrityNodeScheduledRunner`. It is created independently on each node host. The code below is the shared composition pattern; substitute only that host's private paths, signer key, alert transport, release resolver and (for A/B) Node 4 token. Never copy one node's private configuration or signing key to another node.

The release resolver is deliberately an injected administrator-controlled source. It must return the version and full source commit actually deployed at `https://sentryiq.bichet.co.za`, plus that deployed version as `installed_version`. It must not return GitHub's newest release merely because it exists. No public endpoint is assumed to provide this marker.

## Common construction pattern

Load the classes from the SentryIQ application code, then create the private native adapter and node-specific signer:

```php
use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityNodeB;
use SentryIQ\Updates\IntegrityNodeC;
use SentryIQ\Updates\IntegrityNodeScheduledRunner;
use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;
use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\NativeSigstoreIntegrityAttestationVerifier;

// These values are supplied only by this host's protected configuration.
$nodeId = 'integrity-a'; // exactly one of integrity-a, integrity-b, integrity-c
$signer = new IntegrityReportSigner($nodeId, $base64Ed25519SecretKey);
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
    $resolveDeployedRelease, // callable(): version, commit, installed_version
    $verify,
    $directOwnerAlert,
    $privateDataDirectory,
    $publicWebRoot,
    'https://sentryiq.bichet.co.za',
    $explicitPublicPathAllowlist,
    $eventRunner
);
```

The imports above are illustrative; the private bootstrap must also load the corresponding application classes before constructing them. The existing CLI validates the config file path and requires it to return the runner.

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

## Deployment gates not fabricated by this code

Before a host can run this bootstrap, its administrator must supply and test: the deployed-release resolver, exact public path allowlist, node-specific Ed25519 key, independent alert transport, private vendor autoload path, private data directory and (for A/B) unique Node 4 bearer token. Node 4 separately needs A/B public keys, matching bearer tokens, private event storage and a real alert sender.

No production endpoint, release marker, host path, recipient, provider credential or secret is invented here. The repository code and CI do not prove that any node has been provisioned, scheduled or deployed.
