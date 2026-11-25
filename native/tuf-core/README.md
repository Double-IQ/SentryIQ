# SentryIQ shared TUF core (prototype)

This crate is the first shared Rust verification boundary for the iOS and Android native companions. It uses Tuffet's offline trusted-metadata API and exposes a UniFFI-compatible function so Swift and Kotlin can call the same verifier rather than reimplementing TUF in two languages.

## Current scope

- Check the exact SHA-256 of the initial root against a fingerprint supplied through an independent out-of-band bootstrap ceremony.
- Ask Tuffet to parse and validate the initial root's self-signature threshold.
- Validate a supplied sequence of sequential root rotations. TUF requires each new root to be signed by the previous root threshold and its own new root threshold, with the next exact version.
- Verify a top-level metadata refresh (timestamp, snapshot, targets), optionally loading cached timestamp/snapshot/targets metadata first as a rollback baseline. Cached metadata must be supplied as a complete set or omitted for initial bootstrap.
- Enforce bounded input sizes and fail closed.

This prototype verifies timestamp, snapshot, and top-level targets bytes supplied by the caller, but it does **not** fetch metadata, persist trusted metadata, perform delegated-target traversal, consume one-use network challenges, or create a production trust anchor. The caller must atomically persist all accepted root and metadata state only after verification succeeds. The native app must not treat this function as full TUF refresh.

## Dependency decision

Tuffet 0.1.0 is a provisional candidate, not yet production-approved. It follows TUF 1.0, offers an offline TrustedMetadata API and backend-neutral cryptography, and lets SentryIQ own transport and protected storage. Its documented unsupported areas include TAP 4 multi-repository consensus and the optional mirrors role; SentryIQ's initial deployment is one repository and does not require either feature. We still need a security review, fixture interoperability checks, mobile cross-compilation, and dependency maintenance assessment before pinning it for production.

UniFFI provides generated Swift and Kotlin bindings from one Rust core. The current crate exports the function but binding generation and XCFramework/Android ABI packaging are separate integration tasks. A CI build is required before this prototype can be considered validated.

## Validation

```sh
cargo test --manifest-path native/tuf-core/Cargo.toml
```

No production root, private key, trust state, or repository metadata is included.