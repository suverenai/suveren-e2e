/**
 * Email in Gmail mode, credentials saved but no Google sign-in yet (production gateway, real stack).
 * "Change Credentials" must open the saved settings for editing. It used to drop the card back to its
 * first-time form, which showed the default test-data option ("No configuration needed …") and no fields,
 * so a wrong Client ID could not be corrected (found in Andreas's walkthrough, 2026-11-10).
 * The Client ID here is a placeholder: no Google call is made.
 */
import { test, expect, ensureUsersRegistered, ALICE, signInToGateway, handleOnboarding, cardTitlePattern, GW_URL } from './fixtures';

test('Email: Change Credentials opens the saved Gmail settings for editing', async ({ page, request }) => {
  test.setTimeout(180_000);
  await ensureUsersRegistered();
  await signInToGateway(page, ALICE.apiKey);
  await handleOnboarding(page);
  // Playwright sends every API request of this worker through ONE keep-alive agent
  // (playwright-core server/utils/happyEyeballs.js: keepAlive: true), so this PUT can go out on a pooled
  // socket the control plane is just closing after its idle timeout: "read ECONNRESET", before any byte
  // of an answer (CI runs 44676369532 and 44689442027, switch off). maxRetries retries only ECONNRESET.
  const put = await request.put(`${GW_URL}/vault/credentials/mail`, {
    maxRetries: 1,
    headers: { 'x-api-key': ALICE.apiKey },
    data: { mode: 'live', liveAdapter: 'gmail', clientId: 'placeholder-client.apps.googleusercontent.com', clientSecret: 'placeholder' },
  });
  expect(put.ok(), await put.text()).toBe(true);

  await page.click('.sidebar-item:has-text("Connectors")');
  await page.waitForURL('**/integrations');
  const card = page.locator('.card', { has: page.locator('.card-title', { hasText: cardTitlePattern('Email') }) }).first();
  await card.waitFor({ state: 'visible', timeout: 15_000 });
  // Wait until the card has read its saved credentials. Before that answer it is closed, and the same render
  // that shows this line also opens it by itself (a half set-up card opens until the person chooses). A click
  // that lands between "looked closed" and that render toggled the card shut again (CI run 44684355997).
  await expect(card.locator(':scope > summary')).toContainText('Credentials saved — connect your account', { timeout: 15_000 });
  if (!(await card.getByRole('button', { name: 'Change Credentials' }).isVisible().catch(() => false))) await card.locator('.card-title').click();
  await expect(card.getByRole('button', { name: /^Connect Email/ })).toBeVisible({ timeout: 30_000 });

  await card.getByRole('button', { name: 'Change Credentials' }).click();

  await expect(card.getByText('Edit settings')).toBeVisible();
  await expect(card.getByText('No configuration needed', { exact: false })).toHaveCount(0);
  await expect(card.getByRole('radio', { name: /^Gmail/ })).toBeChecked();
  const clientId = card.getByPlaceholder('From Google Cloud Console');
  await expect(clientId).toBeVisible();
  await expect(clientId).toHaveValue('placeholder-client.apps.googleusercontent.com');

  // Put Email back to its default, for the specs that follow on the same gateway.
  await request.put(`${GW_URL}/vault/credentials/mail`, { maxRetries: 1, headers: { 'x-api-key': ALICE.apiKey }, data: { mode: 'simulation' } });
});
