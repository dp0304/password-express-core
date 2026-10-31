#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build AIPassCoreFFI.xcframework (iOS device, iOS simulator arm64+x86_64, macOS arm64)
# plus the Swift bindings, for the iOS app.
#
# REQUIREMENTS: full Xcode (iOS SDKs), `rustup target add aarch64-apple-ios
# aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin`. It cannot run on a
# machine with Command Line Tools only (no iOS SDK) — the macOS host build and the
# swift-host-test package are what is verified there.
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$CRATE/../.." && pwd)"
OUT="${OUT:-$CRATE/build/apple}"
PROFILE="${PROFILE:-release}"
FLAG=$([ "$PROFILE" = release ] && echo --release || echo "")
DIR=$([ "$PROFILE" = release ] && echo release || echo debug)

if ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
  echo "error: iOS SDK not found — install Xcode (Command Line Tools are not enough)." >&2
  exit 1
fi
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
cd "$WS"
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-darwin; do
  rustup target add "$t" >/dev/null
  cargo build -p aipass-ffi --lib $FLAG --target "$t"
done
rm -rf "$OUT" && mkdir -p "$OUT/sim" "$OUT/headers" "$OUT/swift"
lipo -create \
  "$WS/target/aarch64-apple-ios-sim/$DIR/libaipass_ffi.a" \
  "$WS/target/x86_64-apple-ios/$DIR/libaipass_ffi.a" \
  -output "$OUT/sim/libaipass_ffi.a"

# bindings + headers (bindings are generated from the host build)
cargo build -p aipass-ffi --features bindgen --bin uniffi-bindgen
cargo build -p aipass-ffi --lib
"$WS/target/debug/uniffi-bindgen" generate --library "$WS/target/debug/libaipass_ffi.dylib" \
  --language swift --out-dir "$OUT/swift"
cp "$OUT/swift/AIPassCoreFFI.h" "$OUT/headers/"
# an xcframework needs a module map named module.modulemap
cp "$OUT/swift/AIPassCoreFFI.modulemap" "$OUT/headers/module.modulemap"

xcodebuild -create-xcframework \
  -library "$WS/target/aarch64-apple-ios/$DIR/libaipass_ffi.a" -headers "$OUT/headers" \
  -library "$OUT/sim/libaipass_ffi.a" -headers "$OUT/headers" \
  -library "$WS/target/aarch64-apple-darwin/$DIR/libaipass_ffi.a" -headers "$OUT/headers" \
  -output "$OUT/AIPassCoreFFI.xcframework"
echo "XCFramework: $OUT/AIPassCoreFFI.xcframework"
echo "Swift bindings: $OUT/swift/AIPassCore.swift (add to the app target or a Swift package)"
