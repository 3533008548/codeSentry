import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const frontend = fileURLToPath(new URL('.', import.meta.url));
const chrome = process.env.CODESENTRY_CHROME
  ?? 'C:/Program Files/Google/Chrome/Application/chrome.exe';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:8766',
    viewport: { width: 1440, height: 1000 },
    headless: true,
    launchOptions: existsSync(chrome) ? { executablePath: chrome } : {},
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'node ./e2e/start-server.mjs',
    cwd: frontend,
    url: 'http://127.0.0.1:8766/api/session',
    timeout: 30_000,
    reuseExistingServer: false,
  },
});
