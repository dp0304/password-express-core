// SPDX-License-Identifier: Apache-2.0
// Builds the two sidecar binaries bundled with the app (Tauri `externalBin`):
//   aipass-mcp      — from ../crates/aipass-mcp (MCP bridge launched by AI hosts)
//   aipass-nm-host  — from src-tauri/nm-host (native-messaging host for the extension)
// and copies them to src-tauri/binaries/<name>-<target-triple>[.exe].
// aipass-mcp is built with `cargo install --locked` into a private target dir so the shared
// open-source workspace target and lockfile are left untouched.
// Usage: node scripts/build-sidecars.mjs [--release]
import { execFileSync } from "node:child_process";
import { copyFileSync, chmodSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const tauriDir = join(root, "src-tauri");
const release = process.argv.includes("--release") || process.env.AIPASS_SIDECAR_RELEASE === "1";
const triple =
  process.env.TAURI_ENV_TARGET_TRIPLE ||
  execFileSync("rustc", ["-vV"], { encoding: "utf8" }).match(/^host: (.+)$/m)[1].trim();
const exe = triple.includes("windows") ? ".exe" : "";
const profile = release ? "release" : "debug";
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: "inherit" });

mkdirSync(join(tauriDir, "binaries"), { recursive: true });

// 1. aipass-nm-host (this component's own crate).
run("cargo", ["build", "-p", "aipass-nm-host", "--target", triple, ...(release ? ["--release"] : [])], tauriDir);
const nm = join(tauriDir, "target", triple, profile, `aipass-nm-host${exe}`);
copyFileSync(nm, join(tauriDir, "binaries", `aipass-nm-host-${triple}${exe}`));

// 2. aipass-mcp (open-source crate) into a private root + target dir.
const mcpRoot = join(tauriDir, "target", "sidecar-root");
run(
  "cargo",
  [
    "install", "--locked", "--force", "--path", resolve(root, "../crates/aipass-mcp"),
    "--root", mcpRoot, "--target-dir", join(tauriDir, "target", "sidecar-build"), "--target", triple,
    ...(release ? [] : ["--debug"]),
  ],
  root,
);
copyFileSync(join(mcpRoot, "bin", `aipass-mcp${exe}`), join(tauriDir, "binaries", `aipass-mcp-${triple}${exe}`));
if (!exe) {
  chmodSync(join(tauriDir, "binaries", `aipass-mcp-${triple}`), 0o755);
  chmodSync(join(tauriDir, "binaries", `aipass-nm-host-${triple}`), 0o755);
}
console.log(`sidecars ready for ${triple} (${profile})`);
