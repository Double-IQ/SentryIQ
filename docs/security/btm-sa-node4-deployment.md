# Legacy BTM-SA / Node 4 deployment guide — superseded

This guide described a same-host Node 4 event/alert service receiving reports from former Integrity Nodes A/B. That topology is retired and must not be deployed. The owner confirmed that no legacy nodes or Node 4 service were provisioned; merged code and CI are not operational evidence.

**Current target:** a single independent HelioHost verifier with its own report-signing key and read-only measurement boundary. It is not Node C and does not use the old A/B/Node 4 exchange. The SentryIQ application host is not an independent verifier host.

Original text: [archived deployment guide](archive/btm-sa-node4-deployment-legacy.md). Current authority: [device-rooted architecture](../architecture/device-rooted-security-architecture.md), [Phase 1 trust boundaries](../architecture/phase-1-data-flow-and-trust-boundaries.md), and [implementation plan](../architecture/design-implementation-plan.md).
