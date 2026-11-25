# SentryIQ shared TUF core (prototype)

This crate is the first shared Rust verification boundary for the iOS and Android native companions. It uses Tuffet's offline trusted-metadata API and exposes a UniFFI-compatible function so Swift and Kotlin can call the same verifier rather than reimplementing TUF in two languages.

## Current scope

- Check the exact SHA-256 of the initial root against a fingerprint supplied through an independent out-of-band bootstrap ceremony.
- Ask Tuffet to parse and validate the initial root's self-signature threshold.
- Validate a supplied sequence of sequential root rotations. TUF requires each new root to be signed by the previous root threshold and its own new root threshold, with the next exact version.
- Verify a top-level metadata refresh (timestamp, snapshot, targets), optionally loading cached timestamp/snapshot/targets metadata first as a rollback baseline. Cached metadata must be supplied as a complete set or omitted for initial bootstrap.
- Authorise a target path through top-level or delegated targets metadata. The resolver follows TUF priority/depth-first rules, honours terminating delegations, checks each delegated metadata signature against its authorising parent, and rejects incomplete matching chains.
- Bound the number of delegated roles, target-path length, individual metadata sizes, and aggregate root/delegated-metadata inputs; unsafe paths and resource-limit violations fail closed.

The caller supplies metadata already fetched by its transport layer. Delegated verification establishes target authorisation only; it does **not** download target bytes or verify target length/hash. The core also does **not** fetch metadata, persist trusted metadata, consume one-use network challenges, or create a production trust anchor. The caller must atomically persist all accepted root and metadata state only after verification succeeds. The native app must not treat this function as a complete TUF client or production trust decision.

## Dependency decision

Tuffet 0.1.0 is a provisional candidate, not yet production-approved. It follows TUF 1.0, offers an offline TrustedMetadata API and backend-neutral cryptography, and lets SentryIQ own transport and protected storage. Its documented unsupported areas include TAP 4 multi-repository consensus and the optional mirrors role; SentryIQ's initial deployment is one repository and does not require either feature. We still need a security review, fixture interoperability checks, mobile cross-compilation, and dependency maintenance assessment before pinning it for production.

UniFFI provides generated Swift and Kotlin bindings from one Rust core. The current crate exports the function but binding generation and XCFramework/Android ABI packaging are separate integration tasks. A CI build is required before this prototype can be considered validated.

## UniFFI binding generation

The crate now exposes a pinned UniFFI 0.32.2 bindgen executable and a checked-in `uniffi.toml` naming the Kotlin package (`co.bichet.sentryiq.tuf`) and Swift module (`SentryIQTufCore`). CI builds the Rust cdylib and generates both language bindings from that exact library in library mode. Generated files are currently placed under the ignored Cargo target directory and are not yet linked into the Android AAR or iOS Swift package.

The binding-generation step validates the exported interface. The iOS and Android platform build scripts also package the generated wrappers with the compiled Rust libraries into the Swift package's XCFramework and Android module's `jniLibs`/JNA integration. CI exercises the iOS Swift-to-Rust call and an Android emulator instrumentation call; successful CI does not replace physical-device hardware assurance or independent security review.

The shared native API now exposes `verifyTargetDelegation` on both iOS and Android. It takes the target path and the set of delegated role metadata already fetched by the transport layer. Tuffet resolves matching delegations in priority order, honours terminating roles, limits traversal to 32 delegated roles, and checks each delegated metadata signature against the specific delegator that authorised it. Missing metadata for a matching delegation fails closed. The verifier returns only whether the target is authorised; it does not download or verify the target bytes.

## Native platform linkage

The platform build scripts generate UniFFI wrappers from the same Rust cdylib and build the Rust static/shared libraries for the supported native ABIs:

- iOS: `bash native/tuf-core/scripts/build-ios-xcframework.sh` creates `native/ios/SentryIQMaster/Libraries/SentryIQTufCore.xcframework` for arm64 device and arm64/x86_64 simulators. The Swift package links the XCFramework through its binary target.
- Android: `ANDROID_NDK_HOME=... bash native/tuf-core/scripts/build-android-libraries.sh` builds arm64-v8a, armeabi-v7a, and x86_64 libraries into the Android library's `jniLibs`; the generated Kotlin binding uses JNA.

The generated language source and compiled platform libraries are build outputs, not checked-in binaries. The platform CI workflows generate them before compiling/testing the native companion. The iOS test exercises an actual call through the Swift wrapper into the Rust library. Android CI cross-compiles all supported ABIs, packages the AAR, compiles Kotlin, and runs the native FFI instrumentation test on an emulator with KVM when the workflow completes successfully. Physical-device StrongBox/TEE assurance remains a separate qualification gate.

## Validation

```sh
cargo test --manifest-path native/tuf-core/Cargo.toml
```

No production root, private key, trust state, or repository metadata is included.