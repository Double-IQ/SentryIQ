# Scheduled Integrity Node runtime with native Sigstore verification

This is the concrete composition contract joining the native verifier, the public-origin node, the scheduled runner and (for A/B) the Node 4 challenge exchange.

## Per-node private bootstrap

The protected PHP config file loaded by `bin/integrity-node-run.php` must return one `IntegrityNodeScheduledRunner`. It is created independently on each node host. The code below is a composition pattern, not a deployable shared config: each host must create its own file locally. Substitute only that host's private paths, signer key, collector pin, collector bearer token, Node 4 token, alert transport, release resolver and approved policy maps. Never copy one node's private configuration, secret key, bearer token, collector pin or mutable state to another node. A and B must not point at the same private data directory or release-state files.

The deployed-release resolver reads the live `/VERSION` file from `https://sentryiq.bichet.co.za`, then resolves that exact `v<version>` tag to a full commit in the canonical `Double-IQ/SentryIQ` repository. The root `VERSION` file is also included in the signed `public_http_files` inventory, so the node checks that the marker bytes actually match the attested release rather than trusting the origin's version claim alone. It never selects GitHub's newest release. The resolver fails closed if the public VERSION file or matching tag cannot be read. The node's `installed_version` anti-rollback baseline comes from its own private monotonic state store, not from the public origin.

## Common construction pattern

Load the classes from the SentryIQ application code, then create the private native adapter and node-specific signer:

```php
use SentryIQ\Updates\IntegrityNodeA;
use SentryIQ\Updates\IntegrityNodeB;
use SentryIQ\Updates\IntegrityNodeC;
use SentryIQ\Updates\IntegrityNodeScheduledRunner;
use SentryIQ\Updates\IntegrityNodeVerifierBinding;
use SentryIQ\Updates\IntegrityNodeEventRunner;
use SentryIQ\Updates\IntegrityOriginSecurityHeaderVerifier;
use SentryIQ\Updates\IntegrityEventClient;
use SentryIQ\Updates\IntegrityNodeReleaseStateStore;
use SentryIQ\Updates\IntegrityNodeEvidenceStore;
use SentryIQ\Updates\IntegrityDeployedReleaseResolver;
use SentryIQ\Updates\IntegrityReleaseArtifactFetcher;
use SentryIQ\Updates\IntegrityReportSigner;
use SentryIQ\Updates\NativeSigstoreIntegrityAttestationVerifier;
use SentryIQ\Updates\PrivateHostAttestationVerifier;
use SentryIQ\Updates\PrivateHostAttestationClient;
use SentryIQ\Updates\PrivateHostAttestationGate;

// These values are supplied only by this host's protected configuration.
$nodeId = 'integrity-a'; // exactly one of integrity-a, integrity-b, integrity-c
$signer = new IntegrityReportSigner($nodeId, $base64Ed25519SecretKey);
$releaseState = new IntegrityNodeReleaseStateStore($privateDataDirectory, $publicWebRoot);
$resolveDeployedRelease = new IntegrityDeployedReleaseResolver();

// Initialize this once, manually, after independently confirming the known-good
// release already deployed on this node's target. Do not run this on every cron.
// $releaseState->initializeBaseline('<verified-version>', '<verified-40-character-commit>', '<manifest-sha256>', '<zip-sha256>');

$headerVerifier = new IntegrityOriginSecurityHeaderVerifier();
$verifyHeaders = static fn(string $origin): array => $headerVerifier->verify($origin);

// A/B require a collector key pinned independently in each node's private config.
// Each host also has its own bearer token; do not reuse the token on the other node.
$privateHostVerifier = new PrivateHostAttestationVerifier($pinnedCollectorPublicKeyBase64);
$privateHostGate = null;
if ($nodeId === 'integrity-a' || $nodeId === 'integrity-b') {
    $privateHostVerifier = new PrivateHostAttestationVerifier($pinnedCollectorPublicKeyBase64);
    $privateHostClient = new PrivateHostAttestationClient($nodeId, $privateHostBearerToken);
    // These maps are independently reviewed and pinned in this node's protected
    // config; do not derive them from the live host being attested.
    $privateHostGate = new PrivateHostAttestationGate(
        $nodeId,
        $privateHostClient,
        $privateHostVerifier,
        $approvedDeployedFileDigestMap,
        $approvedPrivateConfigDigestMap
    );
}

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
    'integrity-a' => new IntegrityNodeA($signer, $attestation, $privateHostGate, null, $directOwnerAlert, $verifyHeaders),
    'integrity-b' => new IntegrityNodeB($signer, $attestation, $privateHostGate, null, $directOwnerAlert, $verifyHeaders),
    'integrity-c' => new IntegrityNodeC($signer, $attestation, null, $directOwnerAlert, $verifyHeaders),
    default => throw new RuntimeException('Unknown Integrity Node identity.'),
};

// The scheduled runner accepts only this final binding around the concrete
// A, B or C verifier. It does not accept an arbitrary verification callback.
$nodeVerifier = new IntegrityNodeVerifierBinding($nodeId, $node);

$eventRunner = null;
if ($nodeId === 'integrity-a' || $nodeId === 'integrity-b') {
    $node4Client = new IntegrityEventClient(
        'https://sentryiq.bichet.co.za/integrity_event.php',
        $nodeId,
        $node4BearerToken
    );
    $eventRunner = new IntegrityNodeEventRunner($node4Client, $directOwnerAlert);
}

$evidenceStore = null;
if ($nodeId === 'integrity-c') {
    $evidenceStore = new IntegrityNodeEvidenceStore(
        $privateDataDirectory,
        $publicWebRoot,
        $signer->publicKeyBase64()
    );
}

return new IntegrityNodeScheduledRunner(
    $nodeId,
    new IntegrityReleaseArtifactFetcher(),
    $resolveDeployedRelease, // callable(): version, commit from live VERSION + canonical Git tag
    $nodeVerifier,
    $directOwnerAlert,
    $privateDataDirectory,
    $publicWebRoot,
    'https://sentryiq.bichet.co.za',
    $publicPathSubset, // [] means every signed static public asset; otherwise a subset
    $releaseState,
    $eventRunner,
    $evidenceStore
);
```

Nodes A and B also require the node-bound `PrivateHostAttestationGate` shown above; they refuse construction without it. A valid signed rejection is included in the node's signed report and triggers the direct alert route. A transport/signature/freshness failure triggers a direct alert and fails the run. Node C does not call this collector because it is hosted separately and is not the production-host verifier. The collector and transport remain unimplemented deployment gates; do not use an always-approve placeholder.

Each node also verifies the origin's HSTS, CSP, framing, MIME-sniffing, referrer and permissions headers. The SentryIQ `.htaccess` now declares that conservative header policy. The signed release manifest carries a `public_http_files` list containing only byte-verifiable static assets. Dynamic PHP endpoints are not compared with their packaged source bytes; private runtime files remain outside HTTP checks. Leave `$publicPathSubset` empty to check every signed static asset, or provide a subset.

The CLI preloads the node classes, native verifier, concrete `IntegrityNodeVerifierBinding` and runtime dependencies before requiring the protected config file. The config file only needs to construct the host-specific objects and return the runner. The CLI requires an absolute, readable, regular, non-symlink config file with exact `0600` permissions; broader or merely read-only modes are rejected. It then requires the file and requires it to return the runner. The private monotonic state baseline must already exist; first-run bootstrap is an explicit one-time administrator action.


### Mandatory A/B trust-separation checks

For **each** of Node A and Node B, the administrator must independently provision and record the following values on that node—not on the SentryIQ/Node 4 host:

- A unique Ed25519 report-signing private key generated locally, with its public key registered only in the corresponding Node 4 identity slot.
- A unique Node 4 bearer token, distinct from the other node's token.
- A unique private-host collector bearer token and the independently verified collector public-key pin. The collector public key may be the same collector identity for both nodes, but each node must pin it in its own protected configuration; the bearer credentials must remain distinct.
- A node-local private data directory, vendor autoload path, release-state directory, lock and initial release baseline. A and B must not share any writable directory, state file, key file or host account.
- A separately approved file inventory and private-configuration digest map. These maps must be reviewed against the actual target host; a copied example or map generated from the current untrusted host is not an approved baseline.
- A direct alert route that does not depend on Node 4 or the SentryIQ host.

Node 4's private runtime config must contain exactly the two A/B bearer tokens and report public keys, and must reject duplicates. The Node 4 runtime config already checks that the A/B token values and decoded report public keys differ. That check is necessary but not sufficient: it cannot prove the external hosts are physically independent or that their private collector pins, deployment inventories, data directories and release baselines are separate.

For A/B private-host verification, construct a `PrivateHostAttestationGate` rather than passing an ad-hoc closure. The gate binds the exact node ID to a `PrivateHostAttestationClient`, a `PrivateHostAttestationVerifier` with that host's locally pinned collector key, and that node's approved file/config digest maps. Nodes A and B now require this final gate as a typed constructor dependency and reject a gate bound to the other node; arbitrary callables can no longer replace it. Pass the gate as the node's private-host verifier dependency. It rejects a client for the other node, empty file inventories, malformed policy digests and non-canonical origins before a scheduled check. At each run it also requires every pinned deployed-file digest to match the verified release manifest, preventing a stale or unrelated inventory from being attested. Its credential and collector-key fingerprints are safe audit identifiers; never log or export the underlying secrets. This binding enforces in-process composition, but it cannot prove physical host separation or that an administrator-approved baseline is trustworthy.

The CLI's `SENTRYIQ_INTEGRITY_NODE_CONFIG` variable selects one protected PHP file and validates basic path privacy; it does not itself prove that the returned object graph uses node-exclusive keys, pins, tokens, alert destinations, baselines or directories. The private bootstrap must enforce those values operationally. Do not mark A/B provisioned until both hosts have been independently inspected and a successful scheduled run plus direct-alert failure test has been observed on each.

## Node-specific boundaries

- **Node A:** use only the A signing key, A bearer token and A host's private vendor/data directories. Configure a Node 4 event client and event runner. Keep direct alerts independent of Node 4.
- **Node B:** use only the B signing key, B bearer token and B host's private vendor/data directories. It must be hosted and administered independently of A. Configure its own Node 4 client and event runner, plus its own direct alerts.
- **Node C (HelioHost):** use only the C signing key and HelioHost private vendor/data directories. Do not construct a Node 4 client or event runner. Its scheduler creates a local random nonce and direct-alerts from HelioHost.

Node 4 / BTM-SA is on the same host as SentryIQ. It is not an independent host failure domain. A and B must remain able to alert the owner directly if the SentryIQ/Node 4 host is down.

## Generate each node's signing key locally

Before writing the protected node config, generate the node's Ed25519 identity on that node host. Run this once per host, with that host's private data directory and public webroot:

```sh
php /absolute/code-path/SentryIQ/bin/integrity-node-keygen.php integrity-a /absolute/private-data /absolute/public-webroot
```

Use `integrity-b` on Node B and `integrity-c` on Node C. The command refuses to overwrite an existing key, stores the raw private key as a mode-0600 file outside the webroot, and prints only the public key (base64) and file paths. It never prints or exports the private key. Keep each private key on its own node; transfer only A/B public keys to the Node 4 private configuration. Do not generate all three identities on the SentryIQ/Node 4 host.

The protected node config reads the raw private key file and base64-encodes its bytes for the signer; it must never embed the key in the public pointer config or write it to logs:

```php
if (is_link($privateSigningKeyPath) || !is_file($privateSigningKeyPath)
    || ((fileperms($privateSigningKeyPath) ?: 0) & 0077) !== 0) {
    throw new RuntimeException('Node signing key file must be private and non-symlinked.');
}
$secretKeyBytes = file_get_contents($privateSigningKeyPath);
if (!is_string($secretKeyBytes) || strlen($secretKeyBytes) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    throw new RuntimeException('Node signing key is unavailable or invalid.');
}
$base64Ed25519SecretKey = base64_encode($secretKeyBytes);
sodium_memzero($secretKeyBytes);
$signer = new IntegrityReportSigner($nodeId, $base64Ed25519SecretKey);
unset($base64Ed25519SecretKey);
```

The key file must be a regular non-symlink file with mode 0600 in a mode-0700 private directory. The public-key base64 printed by key generation is the only key material copied to Node 4; the private key stays on its originating host.

## CLI and schedule

Set `SENTRYIQ_INTEGRITY_NODE_CONFIG` to the absolute path of this host's protected PHP config, then run:

```sh
php /absolute/private-or-code-path/SentryIQ/bin/integrity-node-run.php
```

Create one independent schedule per A/B/C host. Do not place all three node schedules or private keys on the SentryIQ/Node 4 host.

## Per-node anti-rollback state

Each A/B/C host keeps its own `integrity-release-state.json` in its private data directory. The private data directory must already be an exact `0700` directory; the constructor validates this and never changes operator-supplied permissions. Before first use, the administrator must pre-provision `integrity-release-state.lock` as a regular, non-symlink file with exact `0600` permissions. The store opens that existing file without creating it or changing its mode and verifies the opened inode against `lstat`. The state file is created atomically with exact `0600` permissions and is rejected if it is not a regular `0600` file. The baseline is initialized once with a release version, commit, manifest SHA-256 and ZIP SHA-256 that the administrator has independently confirmed as the known-good deployed build. Pin both artifact digests at bootstrap; subsequent checks reject same-version artifact replacement as well as tag retargeting. A run is serialized with the pre-provisioned exclusive lock; older versions and same-version/different-commit tag changes are rejected. The state advances only after the node returns an approved verification result. A rejected or incomplete check never advances the pin. Do not initialize the baseline from the live `/VERSION` response alone.

## Private PHP and configuration attestation remains separate

These HTTP checks do not attest the deployed PHP source, private runtime files or configuration. A successful public-asset check must not be reported as proof that the deployed PHP tree matches the signed release ZIP. Full deployment integrity still requires a separately authenticated, read-only host collector or out-of-band file-reading channel that compares private deployment files against the attested package. The collector's signing key must not be readable by the web application; hardware-backed custody or an independently controlled host identity is preferred. Node 4 on the SentryIQ host cannot serve as an independent attestor of that same host.

## Deployment gates not fabricated by this code

Before a host can run this bootstrap, its administrator must supply and test: the deployed-release resolver, exact public path allowlist, node-specific Ed25519 key, independent alert transport, private vendor autoload path, private data directory, and (for C) a private evidence store. Nodes A/B additionally require unique Node 4 bearer tokens. Node 4 separately needs A/B public keys, matching bearer tokens, private event storage and a real alert sender.

No production endpoint, release marker, host path, recipient, provider credential or secret is invented here. The repository code and CI do not prove that any node has been provisioned, scheduled or deployed.
