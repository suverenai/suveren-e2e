/**
 * Switching the practice CRM from "Test data" to "On this computer" in the
 * gateway UI, on a PRODUCTION gateway (the suite's own shared stack, no
 * simulation mode) - and back. Real clicks, no API shortcut for the save.
 *
 * The practice CRM has no saved mode, so in production it is paused. The test:
 *   1. opens the CRM card, "Edit settings", picks the radio "On this computer",
 *      Save -> WITHOUT reloading the page the card reads "CRM · Local" (no
 *      "Simulation" tag) and is Running; reopening "Edit settings" shows
 *      "On this computer" selected;
 *   2. picks "Test data" again, Save -> the connector is Paused (production).
 *
 * Fails on gateway 0.41.2 behaviour: after a save the card kept the mode label
 * "Test data" and the edit form kept the OLD values until the page was reloaded
 * (the settings were read once, on mount). Fixed by reading them back after each
 * save (gateway 7ec35c2).
 *
 * Named zz-* so it runs LAST: it switches the shared gateway's CRM to a real
 * (local) system, and journey-1 expects the practice CRM to be paused.
 * Selectors use roles and the visible texts, not markup details.
 */
import { test, expect, ensureUsersRegistered, ALICE, signInToGateway, handleOnboarding, cardTitlePattern } from './fixtures';

/** A running connector moves to "In use" as a collapsed card: open it if the button is not there yet. */
async function openEdit(card: import('@playwright/test').Locator) {
  const edit = card.getByRole('button', { name: 'Edit settings' });
  if (!(await edit.isVisible().catch(() => false))) await card.locator('.card-title').click();
  await edit.click();
}

test('CRM: Test data -> On this computer -> Test data, no reload', async ({ page }) => {
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

  // Start: test data, not running on a production gateway.
  await expect(card).toContainText('CRM · Test data');
  await expect(card.getByText('Running', { exact: true })).toHaveCount(0);

  // Switch to the real system, through the card's own form.
  await openEdit(card);
  await card.getByRole('radio', { name: 'On this computer' }).check();
  await card.getByRole('button', { name: /^Save/ }).click();

  // No reload: the card shows the new mode and is Running.
  await expect(card.locator('.card-title')).toHaveText(/^CRM · Local$/, { timeout: 60_000 });
  await expect(card.getByText('Simulation', { exact: true })).toHaveCount(0);
  await expect(card.getByText('Running', { exact: true }).first()).toBeVisible({ timeout: 60_000 });

  // Reopening the form shows the saved choice, not the old one.
  await openEdit(card);
  await expect(card.getByRole('radio', { name: 'On this computer' })).toBeChecked();
  await expect(card.getByRole('radio', { name: 'Test data' })).not.toBeChecked();

  // And back: a simulated connector does not run in production.
  await card.getByRole('radio', { name: 'Test data' }).check();
  await card.getByRole('button', { name: /^Save/ }).click();
  await expect(card.locator('.card-title')).toHaveText(/^CRM · Test data$/, { timeout: 60_000 });
  await expect(card.getByText('Paused', { exact: true }).first()).toBeVisible({ timeout: 60_000 });
  await expect(card.getByText('Running', { exact: true })).toHaveCount(0);
});
