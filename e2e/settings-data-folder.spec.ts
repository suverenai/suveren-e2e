/**
 * Gateway PR #191 — Settings shows the data folder in use, read-only.
 *
 * Real stack: the gateway started by the shared setup has its own
 * SUVEREN_DATA_DIR (a temp folder). Settings must show exactly that path, with
 * the approved note: what is encrypted and what is not. No mocks.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test, expect, registerOnSP, signInToGateway, handleOnboarding, gatewayDataDir } from './fixtures';

// Runs only against a gateway that has the data-folder line (CI runs the
// journeys against the gateway's main branch, which may not have it yet).
const HAS_DATA_FOLDER = existsSync(join(import.meta.dirname, '..', '..', 'suveren-gateway', 'apps', 'ui', 'src', 'components', 'DataFolderLine.tsx'));

test.skip(!HAS_DATA_FOLDER, 'gateway without the Settings data-folder line (gateway #191)');

test('Settings shows "Data folder:" with the gateway\'s real data dir and the approved note', async ({ page }) => {
  test.setTimeout(90_000);
  const apiKey = await registerOnSP(page, 'Data Folder');
  await signInToGateway(page, apiKey);
  await handleOnboarding(page);
  await page.click('.sidebar-item:has-text("Settings")');
  await page.waitForURL('**/settings');

  const line = page.locator('.su-datafolder');
  await expect(line).toBeVisible({ timeout: 15_000 });
  await expect(line).toContainText('Data folder:');
  // The path is the one the running gateway uses (wrap hints add no text).
  await expect(line.locator('code')).toHaveText(gatewayDataDir(), { timeout: 15_000 });
  await expect(line).toContainText('everything the gateway stores on this computer');
  await expect(line).toContainText('Credentials, tickets and logs are encrypted;');
  await expect(line).toContainText('connector databases (CRM, records, ERP, email) are not.');
  // Read-only: nothing to edit or change inside the line.
  await expect(line.locator('input, button, select')).toHaveCount(0);
});
