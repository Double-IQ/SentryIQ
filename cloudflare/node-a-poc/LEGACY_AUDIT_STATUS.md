# Legacy Cloudflare Node A Audit — Superseded

**Status:** Retired as an active deployment plan on 2026-11-24.  
**Replacement:** [Device-Rooted Security Architecture](../../docs/architecture/device-rooted-security-architecture.md) and [Design and Implementation Plan](../../docs/architecture/design-implementation-plan.md).

The Cloudflare Worker/R2/Durable Object Node A deployment was not provisioned or accepted in production. The owner selected a different target topology:

- SentryIQ application: `https://sentryiq.bichet.co.za`.
- Independent security verifier: HelioHost.
- Master device and normal device-authorisation authority: owner's phone.
- Additional devices: enrolled only by explicit cryptographic approval from the master phone.
- Emergency master replacement: offline recovery ceremony.

Cloudflare, Val Town, and the previous A/B/C node topology are not active deployment targets.

The source code, tests, CI evidence, and detailed investigation below are retained as historical engineering evidence until Phase 0.5 of the new plan maps each file and dependency. They are not instructions to provision Cloudflare resources or continue the old deployment sequence.

No production deployment, account mutation, release publication, key generation, or baseline initialisation is authorised by this status change.
