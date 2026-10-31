// SPDX-License-Identifier: Apache-2.0
// Smoke-test the built package: ESM and CJS entry points load, expose the same API, report the
// package.json version, and reproduce the CONTRACTS §1.6 signing vector.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const require = createRequire(import.meta.url);

const esm = await import(join(root, "dist", "index.js"));
const cjs = require(join(root, "dist", "index.cjs"));

const failures = [];
const check = (cond, message) => {
  if (!cond) failures.push(message);
};

for (const [name, mod] of [
  ["esm", esm],
  ["cjs", cjs],
]) {
  check(mod.VERSION === pkg.version, `${name}: VERSION ${mod.VERSION} !== package.json ${pkg.version}`);
  for (const sym of ["AIPassClient", "pair", "startPairing", "ConnectionKey", "SigningKey", "handleToolCall", "openAITools", "anthropicTools", "systemPrompt", "AIPassError"]) {
    check(typeof mod[sym] === "function", `${name}: missing export ${sym}`);
  }
  const key = mod.SigningKey.fromSeed("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8");
  check(key.publicKey === "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", `${name}: public key mismatch`);
  const signed = mod.signRequest("conn_01jbz3k6w8a7m2q4t5v9x0y1z4", key, {
    method: "GET",
    path: "/v1/resources?project_id=proj_01jbz3k6w8a7m2q4t5v9x0y1z3",
    body: "",
    ts: 1793318400,
    nonce: "qqqqqqqqqqqqqqqqqqqqqg",
  });
  check(
    signed.signature === "z-FXrTabpsAztih0b7vQ-r9wqLCSnkTZtGHBrGgL9U5aT6Nt4usP6qgRQb_FBzyl_DQ0xrNb0oSuphvOvmOjDg",
    `${name}: signature vector mismatch`,
  );
  check(mod.toolDefinitions().map((d) => d.name).join(",") === "resources_list,operations_request,operations_status,operations_cancel,access_request,access_release", `${name}: tool names`);
}
check(Object.keys(esm).sort().join(",") === Object.keys(cjs).sort().join(","), "esm and cjs export different names");

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`dist OK: @aipass/sdk ${pkg.version} (esm + cjs, ${Object.keys(esm).length} exports, signing vector reproduced)`);
