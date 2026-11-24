# Legacy Four-Node Resilience ADR — Superseded

This ADR documented the former four-logical-node design. It is retained as historical context only and is not the current SentryIQ architecture.

The owner-approved target is now:
- SentryIQ application/PWA at `https://sentryiq.bichet.co.za`.
- One independent, specialised security verifier on HelioHost.
- The owner's phone as master device and sole normal device-enrolment authority.
- Other devices individually authorised by the master phone.
- Offline recovery authority for lost-master replacement.

The old two-independent-monitor requirement, Nodes A/B/C, Node 4/BTM-SA aggregation, and four-node failure model are superseded. HelioHost is the one security node, not an additional third verifier and not a second SentryIQ installation.

Original ADR archived at [2026-11-08-four-node-resilience-architecture-archive.md](2026-11-08-four-node-resilience-architecture-archive.md). See [current device-rooted architecture](../architecture/device-rooted-security-architecture.md) and [implementation plan](../architecture/design-implementation-plan.md).
