# Legacy Cloudflare Deployment Guide — Retired

This guide is preserved as historical reference at [DEPLOYMENT_ARCHIVE.md](DEPLOYMENT_ARCHIVE.md). It is not an active deployment instruction.

**Current target:** SentryIQ remains at `https://sentryiq.bichet.co.za`; HelioHost hosts the independent, specialised security verifier; the owner's phone is the master device and sole normal device-enrolment authority.

Do not provision Cloudflare Workers, R2, Durable Objects, routes, Cron triggers, or Cloudflare secrets for this architecture. Follow [the device-rooted architecture](../../docs/architecture/device-rooted-security-architecture.md) and [the new implementation plan](../../docs/architecture/design-implementation-plan.md).

No production deployment, key generation, trust-baseline initialisation, or release publication is authorised by this file.
