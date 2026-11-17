# BTM-SA / Node 4 deployment boundary

Node 4 is the BTM-SA event and alert plane hosted on the same physical host as
SentryIQ. It is a separate application trust domain, not a separate host or
independent failure domain. A host outage or host-level compromise affects
both SentryIQ and Node 4. Integrity Nodes A and B must therefore retain their
own independent owner-alert paths.

## Components

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

The following is a shape example only. Never commit actual values:

```php
return [
    'data_dir' => '/absolute/path/outside/httpdocs/sentryiq-data',
    'integrity_event' => [
        'enabled' => true,
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
only by that account (normally mode 0700). The state and lock files are created
with mode 0600. The endpoint refuses a storage directory outside the resolved
private data directory. Keep the per-node tokens and private signing keys out
of Git, release ZIPs, webroot, and shared configuration exports.

Generate independent random bearer tokens for A and B. Do not reuse their
Ed25519 private signing keys as bearer tokens. Install only the corresponding
public keys on Node 4. The private signing keys remain on their respective
nodes.

## Protocol

1. A/B authenticate to `POST /integrity_event.php` with
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
