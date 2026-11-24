# Legacy Node A Execution Plan — Superseded

This Cloudflare-specific execution plan is no longer active. The agreed target architecture is documented in:

- [Device-Rooted Security Architecture](../../docs/architecture/device-rooted-security-architecture.md)
- [Design and Implementation Plan](../../docs/architecture/design-implementation-plan.md)
- [Legacy audit status](LEGACY_AUDIT_STATUS.md)

The detailed prior runbook is preserved in [EXECUTION_PLAN_ARCHIVE.md](EXECUTION_PLAN_ARCHIVE.md) as historical evidence only. Do not execute its Cloudflare provisioning, R2, Durable Object, Cron, Node 4 A/B, or baseline-initialisation steps.

Current next task: Phase 0.5 of the new plan — inventory old topology/origin references and classify active dependencies before removing or adapting code. No production mutation or destructive repository cleanup is authorised by this notice.
