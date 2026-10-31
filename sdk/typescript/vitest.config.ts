// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    testTimeout: 20_000,
    // Tests start real node:http servers (TCP + unix socket); keep them isolated per file.
    pool: "forks",
  },
});
