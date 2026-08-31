// Browser smoke configuration (DEV-031). The suite runs against an
// ALREADY-RUNNING stack — scripts/acceptance/e2e-browser.sh boots one and
// sets these variables — so the config carries no webServer block.
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? "http://localhost:3099",
  },
});
