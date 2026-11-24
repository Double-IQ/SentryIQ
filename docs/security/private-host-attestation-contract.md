# Legacy A/B Private-Host Attestation Contract — Superseded

This contract describes the former Integrity Node A/B topology and is retained for historical implementation detail only. It is not the current security-node deployment contract.

Current target architecture:
- SentryIQ application/PWA: `https://sentryiq.bichet.co.za`.
- Independent specialised security verifier: HelioHost.
- Master device: owner's phone, sole normal authority for device enrolment and revocation.
- Additional devices: individually approved by the master device.
- Recovery: offline recovery authority and a deliberate master-replacement ceremony.

The former A/B bearer-token exchange, Node 4 dependency, and assumptions that HelioHost is "Node C" must not be treated as active topology. Existing collector, nonce-store, Ed25519 and file-inventory code may be reusable, but only after trust-boundary review against the new architecture.

The prior contract is preserved at `docs/security/private-host-attestation-contract-archive.md`. The new authoritative design is [Device-Rooted Security Architecture](../architecture/device-rooted-security-architecture.md), with work sequenced in [Design and Implementation Plan](../architecture/design-implementation-plan.md).

No signing keys, endpoints, credentials, or production service have been provisioned by this documentation change.
