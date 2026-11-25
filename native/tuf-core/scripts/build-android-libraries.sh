#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE="$ROOT/native/tuf-core"
ANDROID_MODULE="$ROOT/native/android/SentryIQMaster/master"
: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to the installed Android NDK}"

HOST_TAG="linux-x86_64"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
export PATH="$TOOLCHAIN:$PATH"

cd "$CRATE"
cargo build
cargo run --bin uniffi-bindgen -- generate --library target/debug/libsentryiq_tuf_core.so --language kotlin --out-dir target/bindings/kotlin
mkdir -p "$ANDROID_MODULE/src/main/java/co/bichet/sentryiq/tuf"
cp target/bindings/kotlin/co/bichet/sentryiq/tuf/sentryiq_tuf_core.kt "$ANDROID_MODULE/src/main/java/co/bichet/sentryiq/tuf/"

rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

cargo build --release --target aarch64-linux-android
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target armv7-linux-androideabi
cargo build --manifest-path "$CRATE/Cargo.toml" --release --target x86_64-linux-android

JNI_LIBS="$ANDROID_MODULE/src/main/jniLibs"
mkdir -p "$JNI_LIBS/arm64-v8a" "$JNI_LIBS/armeabi-v7a" "$JNI_LIBS/x86_64"
cp "$CRATE/target/aarch64-linux-android/release/libsentryiq_tuf_core.so" "$JNI_LIBS/arm64-v8a/"
cp "$CRATE/target/armv7-linux-androideabi/release/libsentryiq_tuf_core.so" "$JNI_LIBS/armeabi-v7a/"
cp "$CRATE/target/x86_64-linux-android/release/libsentryiq_tuf_core.so" "$JNI_LIBS/x86_64/"
