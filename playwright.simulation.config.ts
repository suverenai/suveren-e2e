import { defineConfig } from '@playwright/test';
import base from './playwright.config';
import { SIMULATION_SPECS } from './e2e/simulation-specs';

// The same shared stack as the default config, but a SIMULATION gateway
// (fixtures.ts reads HAP_E2E_PW_SIMULATION) and only the specs that use the
// practice CRM / ERP / mailbox. See e2e/simulation-specs.ts.
process.env.HAP_E2E_PW_SIMULATION = '1';

export default defineConfig({
  ...base,
  testMatch: SIMULATION_SPECS,
  testIgnore: [],
});
