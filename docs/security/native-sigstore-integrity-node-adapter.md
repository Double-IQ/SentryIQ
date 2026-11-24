# Legacy Native Sigstore adapter for Integrity Nodes A/B/C — superseded

This document describes the old A/B/C adapter contract and its shared GitHub/Sigstore trust roots. It is retained as historical code/test context only. It does not define the new HelioHost verifier trust model and is not a deployment instruction. No legacy nodes were provisioned.

The current target is one specialised HelioHost verifier with a dedicated signing key, independent policy and owner-phone trust pin. Release provenance, verifier reports, master-device signatures and content keys are separate roles.

Original text: [archived adapter guide](archive/native-sigstore-integrity-node-adapter-legacy.md). Current authority: [release trust policy](release-trust-policy.md), [Phase 1.3 cryptographic profile](../architecture/phase-1-cryptographic-profile.md), [Phase 1.4 key roles](../architecture/phase-1-key-role-separation.md), and [implementation plan](../architecture/design-implementation-plan.md).
