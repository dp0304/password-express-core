#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build libaipass_ffi.so for arm64-v8a, armeabi-v7a and x86_64 with cargo-ndk, plus the
# Kotlin bindings (package com.aipass.core; needs JNA on the app side).
#
# REQUIREMENTS: Android NDK (ANDROID_NDK_HOME), `cargo install cargo-ndk`,
# `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`.
# Not runnable on a machine without the NDK / JDK — only the host build and the Kotlin
# source generation are verified there.
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$CRATE/../.." && pwd)"
OUT="${OUT:-$CRATE/build/android}"
API="${ANDROID_API:-26}"
if [ -z "${ANDROID_NDK_HOME:-}" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
  echo "error: ANDROID_NDK_HOME is not set to an installed Android NDK." >&2
  exit 1
fi
command -v cargo-ndk >/dev/null || { echo "error: cargo install cargo-ndk" >&2; exit 1; }
cd "$WS"
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android >/dev/null
rm -rf "$OUT" && mkdir -p "$OUT/jniLibs" "$OUT/kotlin"
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -P "$API" -o "$OUT/jniLibs" \
  build -p aipass-ffi --lib --release
cargo build -p aipass-ffi --features bindgen --bin uniffi-bindgen
cargo build -p aipass-ffi --lib
"$WS/target/debug/uniffi-bindgen" generate --library "$WS/target/debug/libaipass_ffi.dylib" \
  --language kotlin --out-dir "$OUT/kotlin"
echo "jniLibs: $OUT/jniLibs (copy to app/src/main/jniLibs)"
echo "Kotlin: $OUT/kotlin/com/aipass/core/aipass_core.kt"
