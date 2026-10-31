#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the binaries (and the TypeScript SDK) and run the P0 end-to-end acceptance test.
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo build -p aipass-node -p aipass-cli -p aipass-mcp
if [ "${AIPASS_E2E_SKIP_SDK:-}" != "1" ]; then
  (cd sdk/typescript && { [ -d node_modules ] || pnpm install --frozen-lockfile; } && pnpm run --silent build)
fi
exec python3 -I tests/e2e/run_e2e.py "$@"
