// Unit tests for the web tier's pure logic (M-27).
//
// Scope is deliberately narrow: the helpers whose failure modes are silent.
// Rendering is covered end to end by scripts/acceptance/m5.sh and
// m8-console.sh against a live API, which is a better test of a
// server-rendered app than a jsdom mount would be.
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL(".", import.meta.url)),
      // Server modules under test import Next's "server-only" marker,
      // which has no entry point resolvable outside a Next build.
      "server-only": fileURLToPath(new URL("./lib/__tests__/server-only.stub.ts", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["lib/__tests__/**/*.test.ts"],
  },
});
