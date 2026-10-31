#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the macOS host static library (with the `test-support` feature), regenerate the
# Swift bindings for the host-test package and run `swift build` + `swift test`
# (swift-testing; works with Command Line Tools, no Xcode needed).
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$CRATE/../.." && pwd)"
PKG="$CRATE/swift-host-test"
T="$WS/target/debug"
cd "$WS"
# order matters: the last build decides which libaipass_ffi.{a,dylib} sits in target/debug
cargo build -p aipass-ffi --features bindgen --bin uniffi-bindgen
cargo build -p aipass-ffi --features test-support --lib
GEN="$(mktemp -d)"
trap 'rm -rf "$GEN"' EXIT
"$T/uniffi-bindgen" generate --library "$T/libaipass_ffi.dylib" --language swift \
  --out-dir "$GEN" --no-format
mkdir -p "$PKG/lib" "$PKG/Sources/AIPassCore" "$PKG/Sources/AIPassCoreFFI/include"
cp "$GEN/AIPassCore.swift" "$PKG/Sources/AIPassCore/AIPassCore.swift"
cp "$GEN/AIPassCoreFFI.h" "$PKG/Sources/AIPassCoreFFI/include/AIPassCoreFFI.h"
# link the static library only (a .dylib next to it would be preferred by ld)
cp "$T/libaipass_ffi.a" "$PKG/lib/libaipass_ffi.a"
cd "$PKG"
# With Command Line Tools only, swift-testing lives outside the default framework path.
# The flags must be global: SwiftPM's generated test runner is compiled with
# `#if canImport(Testing)` and would otherwise silently run zero tests.
FLAGS=()
CLT=/Library/Developer/CommandLineTools/Library/Developer/Frameworks
if [ -d "$CLT/Testing.framework" ] && ! xcode-select -p 2>/dev/null | grep -q Xcode.app; then
  FLAGS=(-Xswiftc -F -Xswiftc "$CLT" -Xlinker -rpath -Xlinker "$CLT")
fi
swift build "${FLAGS[@]}"
OUT="$(mktemp)"
swift test "${FLAGS[@]}" "$@" 2>&1 | grep -v '^ld: warning' | tee "$OUT"
# fail loudly if no test ran (guards against the silent zero-test runner)
grep -Eq 'Test run with [1-9][0-9]* tests? .*passed' "$OUT" || { echo "error: no passing swift-testing run detected" >&2; rm -f "$OUT"; exit 1; }
rm -f "$OUT"
