/**
 * Weekly limits in the browser (Andreas, 2026-11-23): email@0.11's `send_weekly_max`
 * ("Weekly send limit", the last 7 days). The give form shows the field with the
 * profile's own label, the review step names it with its value, and the signed
 * mandate shows it on the Mandates page. Labels come from the profile, never from code.
 *
 * Simulation gateway (the Email connector runs on its practice mailbox). Skipped when
 * the hap-profiles checkout has no email@0.11 (CI input `profiles_ref`).
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test, expect, SP_URL, registerOnSP, signInToGateway, handleOnboarding, activateIntegration } from './fixtures';
import type { Page } from '@playwright/test';
import { typeTitle } from '../src/helpers/give-page';
import { PROFILES_DIR } from '../src/helpers/gateway-stack.js';

const available = existsSync(join(PROFILES_DIR, 'email', '0.11.profile.json'));

test.describe.serial('Weekly send limit (browser)', () => {
  test.skip(!available, 'needs hap-profiles email@0.11');
  let page: Page;

  test.beforeAll(async ({ browser }) => { page = await browser.newPage({ viewport: { width: 1280, height: 1000 } }); });
  test.afterAll(async () => { await page?.close(); });

  test('setup: signed in, Email running', async ({ request }) => {
    test.setTimeout(120_000);
    const apiKey = await registerOnSP(page, 'Weekly Limits');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    expect(sess.ok()).toBe(true);
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'Email (simulation)');
  });

  test('the form shows "Weekly send limit"; review and the Mandates page name it with its value', async () => {
    test.setTimeout(90_000);
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.waitForSelector('.profile-grid:not([data-testid="picker-skeleton"])', { timeout: 10_000 });
    await page.locator('.card', { has: page.getByText('Email', { exact: true }) }).first().locator('button:has-text("Give a mandate")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/intent'), { timeout: 10_000 });

    const weekly = page.locator('#bounds-field-send_weekly_max');
    await expect(weekly).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('label[for="bounds-field-send_weekly_max"]')).toContainText('Weekly send limit');
    await page.locator('#bounds-field-send_daily_max').fill('2');
    await weekly.fill('3');
    const domains = page.locator('#context-field-allowed_domains');
    await domains.fill('kunde-gmbh.example');
    await domains.press('Enter');
    await page.screenshot({ path: test.info().outputPath('w1-form-weekly.png'), fullPage: true });

    await page.locator('button:has-text("Next")').click();
    await page.waitForSelector('.intent-textarea', { timeout: 10_000 });
    await page.fill('.intent-textarea', 'Weekly e2e: a few replies a week.');
    await page.locator('button:has-text("Continue to Review")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
    await typeTitle(page, 'Weekly replies');
    if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
    await expect(page.getByText(/Weekly send limit/).first()).toBeVisible();
    await page.screenshot({ path: test.info().outputPath('w2-review-weekly.png'), fullPage: true });

    await page.locator('button', { hasText: /^Sign mandate/ }).last().click();
    await page.waitForURL((url) => url.toString().includes('/mandates') && !url.toString().includes('/new/'), { timeout: 15_000 });
    await page.locator('text=Weekly replies').first().click();
    await expect(page.getByText(/Weekly send limit/).first()).toBeVisible({ timeout: 10_000 });
    await page.screenshot({ path: test.info().outputPath('w3-mandate-weekly.png'), fullPage: true });
  });
});
