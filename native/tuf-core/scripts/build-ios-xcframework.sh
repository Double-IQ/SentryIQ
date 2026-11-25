#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE="$ROOT/native/tuf-core"
IOS_PACKAGE="$ROOT/native/ios/SentryIQMaster"
TARGET="$CRATE/target"
HEADER_DIR="$TARGET/ios-headers"
SIM_DIR="$TARGET/ios-simulator-universal"

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-ios
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target aarch64-apple-ios-sim
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target x86_64-apple-ios

mkdir -p "$HEADER_DIR" "$SIM_DIR"
cp "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/SentryIQTufCoreFFI.h" "$HEADER_DIR/"
cp "$IOS_PACKAGE/Sources/SentryIQTufCoreFFI/include/module.modulemap" "$HEADER_DIR/"
lipo -create \
  "$TARGET/aarch64-apple-ios-sim/release/libsentryiq_tuf_core.a" \
  "$TARGET/x86_64-apple-ios/release/libsentryiq_tuf_core.a" \
  -output "$SIM_DIR/libsentryiq_tuf_core.a"

mkdir -p "$IOS_PACKAGE/Libraries"
rm -rf "$IOS_PACKAGE/Libraries/SentryIQTufCore.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET/aarch64-apple-ios/release/libsentryiq_tuf_core.a" -headers "$HEADER_DIR" \
  -library "$SIM_DIR/libsentryiq_tuf_core.a" -headers "$HEADER_DIR" \
  -output "$IOS_PACKAGE/Libraries/SentryIQTufCore.xcframework"
