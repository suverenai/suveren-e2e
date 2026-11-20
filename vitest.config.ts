import { defineConfig } from 'vitest/config';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Load .env file into process.env before tests run
function loadDotenv(): Record<string, string> {
  try {
    const content = readFileSync(resolve(process.cwd(), '.env'), 'utf-8');
    const env: Record<string, string> = {};
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      env[trimmed.slice(0, eqIdx)] = trimmed.slice(eqIdx + 1);
    }
    return env;
  } catch {
    return {};
  }
}

export default defineConfig({
  test: {
    // Builds the gateway and the Authority Server once for the whole run,
    // instead of once per suite. See src/helpers/global-setup.ts.
    globalSetup: './src/helpers/global-setup.ts',
    // After every file: stop whatever the file's ProcessManagers still run.
    setupFiles: ['./src/helpers/vitest-setup.ts'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    // 'stack': after-hooks run in reverse order, so the setup file's afterAll runs last.
    sequence: { concurrent: false, hooks: 'stack' },
    fileParallelism: false,
    env: loadDotenv(),
    exclude: ['e2e/**', 'node_modules/**'],
  },
});
