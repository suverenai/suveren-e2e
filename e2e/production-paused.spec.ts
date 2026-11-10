/**
 * A connector paused because it is set to test data on a production gateway.
 * The dashboard says that, not "while simulation mode is on", and the words
 * the AI gives the person walk the real card. Real stack, production gateway.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { join } from 'node:path';
import { test, expect, GW_MCP_URL, ensureUsersRegistered, ALICE, signInToGateway, handleOnboarding, cardTitlePattern } from './fixtures';

const EDIT_PATH = 'presses **Edit settings**, chooses **On this computer** under *Where does CRM get its data?*, presses **Save**';

test('paused in production: the dashboard line, and the AI\'s steps work on the real card', async ({ page }) => {
  test.setTimeout(240_000);
  await ensureUsersRegistered();
  await signInToGateway(page, ALICE.apiKey);
  await handleOnboarding(page);
  await page.waitForLoadState('networkidle');
  await page.click('.sidebar-item:has-text("Connectors")');
  await page.waitForURL('**/integrations');

  const card = page.locator('.card', { has: page.locator('.card-title', { hasText: cardTitlePattern('CRM') }) }).first();
  await card.waitFor({ state: 'visible', timeout: 15_000 });
  await card.scrollIntoViewIfNeeded();
  // The suite's production gateway already lists the practice CRM, set to test data: paused.
  await expect(card.getByText('Paused', { exact: true }).first()).toBeVisible({ timeout: 60_000 });

  // The AI's words, from the gateway itself, name the path this card offers.
  const client = new Client({ name: 'paused-agent', version: '1.0.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  const guide = ((await client.callTool({ name: 'list-authorizations', arguments: { domain: 'customers' } })).content as Array<{ text?: string }>)[0]?.text ?? '';
  await client.close();
  expect(guide).toContain(EDIT_PATH);
  expect(guide).not.toContain('**Activate CRM**');

  // Dashboard: paused the other way round, and it says so.
  await page.click('.sidebar-item:has-text("Dashboard")');
  await expect(page.locator('.page-title')).toHaveText('Dashboard');
  const line = page.getByTestId('paused-summary-production');
  // The stack lists both practice connectors, so both are held back.
  await expect(line).toContainText('2 connectors are paused in production');
  await expect(line).toContainText('— CRM, ERP.');
  await expect(line).toContainText('Set them to a real system on Connectors, or disable them.');
  await expect(page.getByTestId('paused-summary-simulation')).toHaveCount(0);
  const dir = process.env.E2E_SHOTS_DIR;
  if (dir) {
    await line.scrollIntoViewIfNeeded();
    for (const [suffix, scheme, viewport] of [['light', 'light', { width: 1280, height: 800 }], ['dark', 'dark', { width: 1280, height: 800 }], ['phone', 'light', { width: 390, height: 844 }]] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), scheme);
      await page.setViewportSize(viewport);
      await page.waitForTimeout(250);
      await page.screenshot({ path: join(dir, `dashboard-paused-production-${suffix}.png`) });
    }
    await page.emulateMedia({ colorScheme: 'light' });
    await page.setViewportSize({ width: 1280, height: 800 });
  }

  // Follow exactly those words on the real card: Edit settings, the choice, Save.
  await page.click('.sidebar-item:has-text("Connectors")');
  await page.waitForURL('**/integrations');
  const after = page.locator('.card', { has: page.locator('.card-title', { hasText: cardTitlePattern('CRM') }) }).first();
  await after.getByRole('button', { name: 'Edit settings' }).click();
  await after.getByRole('radio', { name: 'On this computer' }).check();
  await after.getByRole('button', { name: /^Save$/ }).click();
  await expect(after.getByText('Running', { exact: true }).first()).toBeVisible({ timeout: 60_000 });
  await page.click('.sidebar-item:has-text("Dashboard")');
  // Only ERP is left, in the singular.
  await expect(page.getByTestId('paused-summary-production')).toContainText('1 connector is paused in production — ERP.', { timeout: 30_000 });

  // These browser specs share one gateway: put CRM back as it was found, for the specs that follow.
  await page.click('.sidebar-item:has-text("Connectors")');
  await page.waitForURL('**/integrations');
  const edit = after.getByRole('button', { name: 'Edit settings' });
  await after.waitFor({ state: 'visible', timeout: 15_000 });
  if (!(await edit.isVisible().catch(() => false))) await after.locator('.card-title').click();
  await edit.click();
  await after.getByRole('radio', { name: 'Test data' }).check();
  await after.getByRole('button', { name: /^Save/ }).click();
  await expect(after.locator('.card-title')).toHaveText(/^CRM · Test data$/, { timeout: 60_000 });
});
