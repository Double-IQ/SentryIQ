# Legacy Integrity Node A — Cloudflare Workers Design — Superseded

This document describes a former Cloudflare Workers deployment design. Cloudflare is not part of the current SentryIQ deployment target.

Current target:
- SentryIQ application/PWA: `https://sentryiq.bichet.co.za`.
- One independent, specialised security verifier: HelioHost.
- Owner's phone: master device and sole normal device-enrolment authority.
- Offline recovery authority: lost-master recovery.

The former Cloudflare Worker, R2, Durable Object, KV and Cron deployment assumptions must not be provisioned for the current architecture. The original document is preserved at [integrity-node-a-cloudflare-workers-archive.md](integrity-node-a-cloudflare-workers-archive.md).

Cloudflare-specific source and tests, if present on other branches, must be reviewed for reusable generic TUF, streaming, integrity and replay-protection components before removal. No source deletion or production mutation is authorised by this notice.

See [device-rooted security architecture](../architecture/device-rooted-security-architecture.md) and [design implementation plan](../architecture/design-implementation-plan.md).
