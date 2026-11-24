# Legacy Integrity Node C — HelioHost Design — Superseded

This document describes the former Node C implementation and its role as an additional verifier alongside mandatory Nodes A and B. That topology is retired.

HelioHost is now the single independent, specialised security verifier for SentryIQ at `https://sentryiq.bichet.co.za`. It is not an additional Node C and does not inherit the old A/B/C identity scheme.

The existing Node C implementation may be a useful starting point because it already has independent release-attestation checks, public-asset verification, signed reports, local evidence retention, and no dependency on Node 4. It is not approved for deployment unchanged: its trust bootstrap, private-file inspection boundary, master-phone integration, recovery, and current deployment contract must be reviewed and adapted.

Original document archived at [integrity-node-c-heliohost-archive.md](integrity-node-c-heliohost-archive.md). See [current device-rooted architecture](../architecture/device-rooted-security-architecture.md) and [implementation plan](../architecture/design-implementation-plan.md).
