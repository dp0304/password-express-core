// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true, host: "127.0.0.1" },
  build: { target: "es2022", sourcemap: false, cssCodeSplit: false, assetsInlineLimit: 0 },
  test: { environment: "jsdom", include: ["src/**/*.test.{ts,tsx}"] },
});
