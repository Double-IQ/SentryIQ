# Legacy Cloudflare Node A Proof of Concept

**Status: retired as an active deployment target on 2026-11-24.**

The code and tests in this directory are retained temporarily for dependency review and possible reuse of generic, well-tested components. They do not represent the approved SentryIQ deployment topology and must not be deployed to Cloudflare.

The previous README is preserved at [README_ARCHIVE.md](README_ARCHIVE.md).

Current architecture:
- SentryIQ PWA: `https://sentryiq.bichet.co.za`.
- Independent security verifier: HelioHost.
- Master device: owner's phone.
- Other devices: cryptographically enrolled only by the master device.
- Lost master: offline recovery ceremony.

See [Device-Rooted Security Architecture](../../docs/architecture/device-rooted-security-architecture.md) and [Design and Implementation Plan](../../docs/architecture/design-implementation-plan.md).

Do not delete this directory or its dependencies until the new plan's Phase 0.5 inventory records every consumer, reusable component, test dependency, workflow reference, and safe retirement action.
