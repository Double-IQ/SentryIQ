# Legacy multi-node native Sigstore runtime guide — superseded

This guide documents the former A/B/C scheduled-node runtime, including A/B private-host gates and Node 4 exchange. It is retained for code/test archaeology only and is not an active provisioning or deployment guide. No legacy nodes were provisioned.

**Current target:** one independent HelioHost verifier, separately trusted by the owner's master phone. The verifier must not use A/B/C identities, Node 4 credentials, or the old private-host collector contract unchanged. Existing classes and tests remain quarantined until a reviewed single-verifier replacement and regression coverage exist.

Original text: [archived runtime guide](archive/integrity-node-native-sigstore-runtime-legacy.md). Current authority: [device-rooted architecture](../architecture/device-rooted-security-architecture.md), [Phase 1.5 platform assessment](../architecture/phase-1-platform-key-protection.md), [Phase 1.9 threat model](../architecture/phase-1-runtime-and-supply-chain-threat-model.md), and [implementation plan](../architecture/design-implementation-plan.md).
