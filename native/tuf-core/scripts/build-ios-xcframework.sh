#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE="$ROOT/native/tuf-core"
IOS_PACKAGE="$ROOT/native/ios/SentryIQMaster"
TARGET="$CRATE/target"
HEADER_DIR="$TARGET/ios-headers"
SIM_DIR="$TARGET/ios-simulator-universal"

cd "$CRATE"
cargo build
cargo run --bin uniffi-bindgen -- generate --library target/debug/libsentryiq_tuf_core.dylib --language swift --out-dir target/bindings/swift
mkdir -p "$IOS_PACKAGE/Sources/SentryIQTufCoreBindings" "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include"
cp target/bindings/swift/SentryIQTufCore.swift "$IOS_PACKAGE/Sources/SentryIQTufCoreBindings/"
cp target/bindings/swift/SentryIQTufCoreFFI.h "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/"
cp target/bindings/swift/SentryIQTufCoreFFI.modulemap "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/module.modulemap"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin

cargo build --release --target aarch64-apple-ios
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-ios-sim
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target x86_64-apple-ios
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-darwin
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target x86_64-apple-darwin

mkdir -p "$HEADER_DIR" "$SIM_DIR"
cp "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/SentryIQTufCoreFFI.h" "$HEADER_DIR/"
cp "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/module.modulemap" "$HEADER_DIR/"
lipo -create \
  "$TARGET/aarch64-apple-ios-sim/release/libsentryiq_tuf_core.a" \
  "$TARGET/x86_64-apple-ios/release/libsentryiq_tuf_core.a" \
  -output "$SIM_DIR/libsentryiq_tuf_core.a"
lipo -create \
  "$TARGET/aarch64-apple-darwin/release/libsentryiq_tuf_core.a" \
  "$TARGET/x86_64-apple-darwin/release/libsentryiq_tuf_core.a" \
  -output "$TARGET/libsentryiq_tuf_core-macos-universal.a"

mkdir -p "$IOS_PACKAGE/Libraries"
rm -rf "$IOS_PACKAGE/Libraries/SentryIQTufCore.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET/aarch64-apple-ios/release/libsentryiq_tuf_core.a" -headers "$HEADER_DIR" \
  -library "$SIM_DIR/libsentryiq_tuf_core.a" -headers "$HEADER_DIR" \
  -library "$TARGET/libsentryiq_tuf_core-macos-universal.a" -headers "$HEADER_DIR" \
  -output "$IOS_PACKAGE/Libraries/SentryIQTufCore.xcframework"
