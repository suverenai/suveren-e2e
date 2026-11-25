/**
 * Weekly limits in the browser (Andreas, 2026-11-23): email@0.11's optional
 * `send_weekly_max` (the last 7 days).
 *
 *  - The form names the field as it names every limit — the connector's limit words
 *    and the window: "Emails per week". Left empty it says "No limit".
 *  - The review step names the limits the same way ("Emails per day", "Emails per week"),
 *    never by field name (found 2026-11-23: it showed "send_weekly_max 3").
 *  - Left empty, the weekly limit is not set at all: sending stays allowed (the
 *    "at least one recipient" hint shows), the review lists no weekly row, and the
 *    signed mandate carries no send_weekly_max — before, an empty field became 0 and
 *    a count limit of 0 forbade every send.
 *
 * Simulation gateway (the Email connector runs on its practice mailbox). Skipped when
 * the hap-profiles checkout has no email@0.11 (CI input `profiles_ref`).
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test, expect, SP_URL, registerOnSP, signInToGateway, handleOnboarding, activateIntegration } from './fixtures';
import type { Page, APIRequestContext } from '@playwright/test';
import { typeTitle } from '../src/helpers/give-page';
import { PROFILES_DIR } from '../src/helpers/gateway-stack.js';

const available = existsSync(join(PROFILES_DIR, 'email', '0.11.profile.json'));
const FORM_HINT = 'At least one of these: Allowed recipients or Allowed domains. Needed while this mandate allows sending.';

test.describe.serial('Weekly send limit (browser)', () => {
  test.skip(!available, 'needs hap-profiles email@0.11');
  let page: Page;
  let apiKey = '';

  test.beforeAll(async ({ browser }) => { page = await browser.newPage({ viewport: { width: 1280, height: 1000 } }); });
  test.afterAll(async () => { await page?.close(); });

  async function openEmailForm() {
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.waitForSelector('.profile-grid:not([data-testid="picker-skeleton"])', { timeout: 10_000 });
    await page.locator('.card', { has: page.getByText('Email', { exact: true }) }).first().locator('button:has-text("Give a mandate")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/intent'), { timeout: 10_000 });
    await expect(page.locator('#bounds-field-send_weekly_max')).toBeVisible({ timeout: 15_000 });
  }

  async function toReview(title: string) {
    const domains = page.locator('#context-field-allowed_domains');
    await domains.fill('kunde-gmbh.example');
    await domains.press('Enter');
    await page.locator('button:has-text("Next")').click();
    await page.waitForSelector('.intent-textarea', { timeout: 10_000 });
    await page.fill('.intent-textarea', `Weekly e2e: ${title}`);
    await page.locator('button:has-text("Continue to Review")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
    await typeTitle(page, title);
    if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  }

  async function sign() {
    await page.locator('button', { hasText: /^Sign mandate/ }).last().click();
    await page.waitForURL((url) => url.toString().includes('/mandates') && !url.toString().includes('/new/'), { timeout: 15_000 });
  }

  /** The review row for a limit: its name, then its value. */
  const reviewRow = (name: string) => page.locator('dl.info-kv dt', { hasText: name });

  async function signedBounds(request: APIRequestContext, seen: number): Promise<Record<string, unknown>> {
    const until = Date.now() + 15_000;
    while (Date.now() < until) {
      const res = await request.get(`${SP_URL}/api/mandates/mine?status=active`, { headers: { 'x-api-key': apiKey } });
      const rows = ((await res.json()).mandates ?? []) as Array<Record<string, any>>;
      // The newest email@0.11 mandate (titles may be sealed, so not matched by title).
      const m = rows
        .filter((r) => String(r.profileId ?? r.profile_id ?? '').endsWith('/email@0.11') && r.bounds)
        .sort((a, b) => String(a.createdAt ?? '').localeCompare(String(b.createdAt ?? '')))
        .pop();
      if (m && seen < rows.length) return m.bounds as Record<string, unknown>;
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new Error('no email@0.11 mandate with bounds on the Authority Server');
  }

  async function activeCount(request: APIRequestContext): Promise<number> {
    const res = await request.get(`${SP_URL}/api/mandates/mine?status=active`, { headers: { 'x-api-key': apiKey } });
    return (((await res.json()).mandates ?? []) as unknown[]).length;
  }

  test('setup: signed in, Email running', async () => {
    test.setTimeout(120_000);
    apiKey = await registerOnSP(page, 'Weekly Limits');
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'Email (simulation)');
  });

  test('the form shows "Emails per week" ("No limit" while empty); the review names both limits with their values', async () => {
    test.setTimeout(90_000);
    await openEmailForm();
    await expect(page.locator('label[for="bounds-field-send_weekly_max"]')).toHaveText(/Emails per week/);
    await expect(page.locator('#bounds-field-send_weekly_max')).toHaveAttribute('placeholder', 'No limit');
    await page.locator('#bounds-field-send_daily_max').fill('2');
    await page.locator('#bounds-field-send_weekly_max').fill('3');
    await page.screenshot({ path: test.info().outputPath('w1-form-weekly.png'), fullPage: true });
    await toReview('Weekly replies');
    await expect(reviewRow('Emails per week')).toBeVisible();
    await expect(reviewRow('Emails per week').locator('xpath=following-sibling::dd[1]')).toHaveText('3');
    await expect(reviewRow('Emails per day')).toBeVisible();
    await expect(page.getByText('send_weekly_max', { exact: true })).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('w2-review-weekly.png'), fullPage: true });
    await sign();
    await page.screenshot({ path: test.info().outputPath('w3-mandates.png'), fullPage: true });
  });

  test('the weekly limit left empty is not set: sending stays allowed, no weekly row, no send_weekly_max signed', async ({ request }) => {
    test.setTimeout(90_000);
    await openEmailForm();
    await page.locator('#bounds-field-send_daily_max').fill('2');
    await expect(page.locator('#bounds-field-send_weekly_max')).toHaveValue('');
    await expect(page.getByTestId('at-least-one-hint')).toHaveText(FORM_HINT);
    const before = await activeCount(request);
    await toReview('Daily only');
    await expect(reviewRow('Emails per day')).toBeVisible();
    await expect(reviewRow('Emails per week')).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath('w4-review-daily-only.png'), fullPage: true });
    await sign();
    const bounds = await signedBounds(request, before);
    expect(bounds.send_daily_max).toBe(2);
    expect('send_weekly_max' in bounds).toBe(false);
  });

  test('generic: an optional DAILY limit left empty is not set either; a required limit left empty keeps Continue off', async ({ request }) => {
    test.setTimeout(90_000);
    await openEmailForm();
    // A required limit (here the test-data loads, shown in simulation, required in email@0.11) emptied: Continue waits.
    const setup = page.locator('#bounds-field-setup_daily_max');
    await setup.fill('');
    await expect(page.getByTestId('required-limits-empty')).toBeVisible();
    await expect(page.locator('button:has-text("Next")')).toBeDisabled();
    await page.screenshot({ path: test.info().outputPath('w5-required-empty.png'), fullPage: true });
    await setup.fill('0');
    await expect(page.getByTestId('required-limits-empty')).toHaveCount(0);
    // email's send_daily_max is optional: left empty it is no daily limit; the weekly one is set.
    await page.locator('#bounds-field-send_daily_max').fill('');
    await expect(page.locator('#bounds-field-send_daily_max')).toHaveAttribute('placeholder', 'No limit');
    await page.locator('#bounds-field-send_weekly_max').fill('3');
    await expect(page.getByTestId('at-least-one-hint')).toHaveText(FORM_HINT);
    const before = await activeCount(request);
    await toReview('Weekly only');
    await expect(reviewRow('Emails per week')).toBeVisible();
    await expect(reviewRow('Emails per day')).toHaveCount(0);
    await sign();
    const bounds = await signedBounds(request, before);
    expect(bounds.send_weekly_max).toBe(3);
    expect('send_daily_max' in bounds).toBe(false);
  });

  test('DEC-106: CRM deletes per day start at 0 (customers@0.12); with the other limits filled, Continue is on', async () => {
    test.setTimeout(90_000);
    await activateIntegration(page, 'CRM');
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.waitForSelector('.profile-grid:not([data-testid="picker-skeleton"])', { timeout: 10_000 });
    await page.locator('.card', { has: page.locator('text=CRM') }).first().locator('button:has-text("Give a mandate")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/intent'), { timeout: 10_000 });
    const deletes = page.locator('#bounds-field-delete_daily_max');
    await expect(deletes).toBeVisible({ timeout: 15_000 });
    await expect(deletes).toHaveValue('0');
    // writes per day has no default (a volume limit): Continue waits for it, then is on.
    await expect(page.getByTestId('required-limits-empty')).toBeVisible();
    await page.locator('#bounds-field-write_daily_max').fill('5');
    await expect(page.getByTestId('required-limits-empty')).toHaveCount(0);
    await expect(page.locator('button:has-text("Next")')).toBeEnabled();
    await page.screenshot({ path: test.info().outputPath('w6-crm-deletes-default.png'), fullPage: true });
  });
});
