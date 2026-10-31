#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regenerate the committed production bindings (no test-support) into bindings/swift and
# bindings/kotlin from the macOS host build. The bindings are target independent.
set -euo pipefail
CRATE="$(cd "$(dirname "$0")/.." && pwd)"
WS="$(cd "$CRATE/../.." && pwd)"
T="$WS/target/debug"
cd "$WS"
cargo build -p aipass-ffi --features bindgen --bin uniffi-bindgen
cargo build -p aipass-ffi --lib
rm -rf "$CRATE/bindings/swift" "$CRATE/bindings/kotlin"
"$T/uniffi-bindgen" generate --library "$T/libaipass_ffi.dylib" --language swift --out-dir "$CRATE/bindings/swift"
"$T/uniffi-bindgen" generate --library "$T/libaipass_ffi.dylib" --language kotlin --out-dir "$CRATE/bindings/kotlin" --no-format
echo "bindings written to $CRATE/bindings"
