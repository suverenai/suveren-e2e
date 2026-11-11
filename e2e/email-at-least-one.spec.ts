/**
 * The sign form for "an Email mandate must name who it may write to"
 * (email@0.10 `scopeSchema.atLeastOne`), in a real browser on the real stack.
 *
 *  - while the limits allow sending, step 2 says "at least one of these" over the
 *    recipient fields and the review step keeps Sign off until one is filled;
 *  - with a send limit of 0 (read only) neither is needed and the mandate signs;
 *  - with a domain the mandate signs;
 *
 * Simulation gateway (the Email connector runs on its practice mailbox).
 */
import { test, expect, SP_URL, GW_MCP_URL, INTERNAL_SECRET, registerOnSP, signInToGateway, handleOnboarding, activateIntegration, spApiAttest } from './fixtures';
import type { Page } from '@playwright/test';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const P = 'github.com/humanagencyprotocol/hap-profiles';
const EMAIL_09 = `${P}/email@0.9`;
const EMAIL_KEYS = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const EMAIL_SCOPE_KEYS = ['allowed_recipients', 'allowed_domains', 'allowed_attachment_sources'];

const FORM_HINT = 'At least one of these: Allowed recipients or Allowed domains. Needed while this mandate allows sending.';
const SIGN_HINT = 'Name at least one allowed recipient or domain in step 2: this mandate allows sending.';

test.describe.serial('An Email mandate must name who it may write to (browser)', () => {
  let page: Page;
  let apiKey = '';
  let did = '';

  test.beforeAll(async ({ browser }) => { page = await browser.newPage({ viewport: { width: 1280, height: 1000 } }); });
  test.afterAll(async () => { await page?.close(); });

  async function openEmailForm() {
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.waitForSelector('.profile-grid', { timeout: 10_000 });
    await page.locator('.card', { has: page.getByText('Email', { exact: true }) }).first().locator('button:has-text("Give a mandate")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/intent'), { timeout: 10_000 });
    await expect(page.locator('#bounds-field-send_daily_max')).toBeVisible({ timeout: 15_000 });
  }

  async function toReview(title: string) {
    await page.locator('button:has-text("Next")').click();
    await page.waitForSelector('.intent-textarea', { timeout: 10_000 });
    await page.fill('.intent-textarea', `At-least-one e2e: ${title}`);
    await page.locator('button:has-text("Continue to Review")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
    await page.locator('input[placeholder*="e.g."]').fill(title);
    if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  }

  const signButton = () => page.locator('button', { hasText: /^Sign mandate/ }).last();

  async function sign() {
    await signButton().click();
    await page.waitForURL((url) => url.toString().includes('/mandates') && !url.toString().includes('/new/'), { timeout: 15_000 });
  }

  test('setup: signed in, Email running', async ({ request }) => {
    test.setTimeout(120_000);
    apiKey = await registerOnSP(page, 'At Least One');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'Email (simulation)');
  });

  test('sending allowed, no recipient or domain: the form says at least one; Sign stays off', async () => {
    await openEmailForm();
    await page.locator('#bounds-field-send_daily_max').fill('3');
    await expect(page.getByTestId('at-least-one-hint')).toHaveText(FORM_HINT);
    await toReview('Neither');
    await expect(page.getByTestId('at-least-one-needed')).toHaveText(SIGN_HINT);
    await expect(signButton()).toBeDisabled();
  });

  test('send limit 0 (read only): no hint, Sign on, the mandate is signed', async () => {
    await openEmailForm();
    await page.locator('#bounds-field-send_daily_max').fill('0');
    await expect(page.getByTestId('at-least-one-hint')).toHaveCount(0);
    await toReview('Read only');
    await expect(page.getByTestId('at-least-one-needed')).toHaveCount(0);
    await expect(signButton()).toBeEnabled();
    await sign();
  });

  test('sending allowed with a domain: Sign on, the mandate is signed', async () => {
    await openEmailForm();
    await page.locator('#bounds-field-send_daily_max').fill('3');
    const domains = page.locator('#context-field-allowed_domains');
    await domains.fill('kunde-gmbh.example');
    await domains.press('Enter');
    await toReview('Customer domain');
    await expect(page.getByTestId('at-least-one-needed')).toHaveCount(0);
    await expect(signButton()).toBeEnabled();
    await sign();
  });

});
