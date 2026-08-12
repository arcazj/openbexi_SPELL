import { defineConfig, devices } from "@playwright/test";

const previewPort = Number(process.env.SPELL_E2E_PREVIEW_PORT ?? "4173");

export default defineConfig({
  testDir: "./e2e",
  outputDir: process.env.SPELL_E2E_OUTPUT_DIRECTORY ?? "test-results",
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  reporter: "html",
  use: {
    baseURL: process.env.SPELL_E2E_BASE_URL ?? `http://127.0.0.1:${previewPort}`,
    screenshot: "only-on-failure",
    trace: "on-first-retry",
  },
  webServer: process.env.SPELL_REAL_BACKEND
    ? undefined
    : {
        command: `npm run preview -- --strictPort --port ${previewPort}`,
        port: previewPort,
        reuseExistingServer: !process.env.CI,
      },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
});
