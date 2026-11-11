/**
 * Andreas 2026-11-11: ERP updates get the same Now → New card as the CRM. An
 * item price change and a customer email change, proposed by the AI under a
 * review-only master-data mandate, on the real stack (Authority Server +
 * gateway + erp-mcp live/local; the only stand-in is the EU VIES service, which
 * none of these records uses), opened in a real browser:
 *   - the sealed tile reads "You approve this change";
 *   - exactly the changed field is one Now → New row (unchanged VAT is not);
 *   - Now is the ERP's own value, New is the bound one.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type Page } from '@playwright/test';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { ErpLocalStack, ERP_MANIFEST_PATH, P, proposalIdOf, resultJson } from '../src/helpers/erp-local-stack.js';
import { ViesStub } from '../src/helpers/vies-stub.js';
import { PROFILES_DIR } from '../src/helpers/gateway-stack.js';
import { openFirstApprovalInPanel } from '../src/helpers/gateway-ui.js';

const SHOTS = process.env.HAP_E2E_SHOTS_DIR;
const MASTER_DATA = `${P}/master-data@0.1`;
const MD_BOUNDS = {
  profile: MASTER_DATA, read_access: 'unlimited', customer_create_daily_max: 30, customer_update_daily_max: 30,
  customer_tax_daily_max: 30, customer_payment_daily_max: 0, item_create_daily_max: 30, item_update_daily_max: 30,
  item_price_daily_max: 30, list_price_max: 10_000, credit_limit_max: 0,
};
const available = existsSync(ERP_MANIFEST_PATH) && existsSync(join(PROFILES_DIR, 'master-data', '0.1.profile.json'));

const vies = new ViesStub();
let s: ErpLocalStack;
let browser: Browser;

async function propose(tool: string, args: Record<string, unknown>): Promise<string> {
  const r = await s.call(tool, args);
  expect(r.denied, r.text).toBe(false);
  expect(r.text).toMatch(/Awaiting commitment/);
  return proposalIdOf(r.text);
}

async function approveOk(id: string): Promise<any> {
  const done = await s.approve(id);
  expect(done.denied, done.text).toBe(false);
  return resultJson(done.text);
}

/** The first waiting card, signed in, in-app navigation only. */
async function openCard(): Promise<{ page: Page; tile: ReturnType<Page['locator']>; card: ReturnType<Page['locator']> }> {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto(`${s.cpUrl}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[type="password"]').fill(s.apiKey);
  await page.locator('button:has-text("Sign In")').click();
  await page.waitForURL((u) => !u.toString().includes('/login'), { timeout: 45_000 });
  await page.locator('.sidebar a[href="/approvals"]').click();
  await page.waitForURL('**/approvals');
  await openFirstApprovalInPanel(page);
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="approval-preview"]');
    return !!el && el.getAttribute('data-preview-status') !== 'loading';
  }, null, { timeout: 30_000 });
  const card = page.getByTestId('approval-panel').locator('[data-testid="approval-card"]').first();
  return { page, card, tile: card.getByTestId('sealed-values') };
}

async function compareRows(tile: ReturnType<Page['locator']>): Promise<string[]> {
  await tile.getByTestId('compare-table').waitFor({ timeout: 20_000 });
  return (await tile.getByTestId('compare-table').locator('tbody tr').allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').trim());
}

describe.skipIf(!available)('ERP updates show Now → New (real AS + gateway + erp-mcp live/local + browser)', () => {
  let item: any;
  let customer: any;

  beforeAll(async () => {
    const url = await vies.start();
    s = new ErpLocalStack({ asPort: 19855, mcpPort: 19856, cpPort: 19857, viesUrl: url, label: 'walkthrough-e' });
    await s.start();
    await s.grant(MASTER_DATA, MD_BOUNDS, {}, 'Walkthrough E: customers and catalogue, each change approved.');
    await new Promise((r) => setTimeout(r, 1_000));
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
    if (SHOTS) mkdirSync(SHOTS, { recursive: true });

    item = await approveOk(await propose('erp__create_item', { name: 'Beratungsstunde', kind: 'service', unit: 'Std.', list_price: 120, vat_rate: 20, sku: 'B-100' }));
    expect(item).toMatchObject({ list_price: 120, vat_rate: 20, revision: 1 });
    customer = await approveOk(await propose('erp__create_customer', { name: 'Kunde Ohne UID GmbH', address_lines: ['Kundenweg 2', '4020 Linz'], country: 'AT', email: 'alt@kunde.example' }));
    expect(customer).toMatchObject({ email: 'alt@kunde.example', revision: 1 });
  }, 400_000);

  afterAll(async () => {
    if (browser) await browser.close().catch(() => {});
    await s?.stop();
    await vies.stop();
  }, 60_000);

  it('an item price change: "You approve this change", List price 120.00 EUR → 130.00 EUR, VAT not shown as a change', async () => {
    const id = await propose('erp__update_item_price', { id: item.id, revision: 1, list_price: 130, vat_rate: 20 });
    const { page, card, tile } = await openCard();
    try {
      expect(await tile.locator('.av3-sealed-h').innerText()).toBe('You approve this change');
      expect(await compareRows(tile)).toEqual(['List price 120.00 EUR 130.00 EUR']);
      if (process.env.HAP_E2E_SHOW_CARD) console.error('[walkthrough E erp] item card:\n' + await card.innerText());
      if (SHOTS) await card.screenshot({ path: join(SHOTS, 'erp-item-price-card.png') });
    } finally {
      await page.close();
      await s.reject(id);
    }
  }, 120_000);

  it('a customer email change: "You approve this change", Email old → new', async () => {
    const id = await propose('erp__update_customer', { id: customer.id, revision: 1, email: 'neu@kunde.example' });
    const { page, card, tile } = await openCard();
    try {
      expect(await tile.locator('.av3-sealed-h').innerText()).toBe('You approve this change');
      expect(await compareRows(tile)).toEqual(['Email alt@kunde.example neu@kunde.example']);
      if (process.env.HAP_E2E_SHOW_CARD) console.error('[walkthrough E erp] customer card:\n' + await card.innerText());
      if (SHOTS) await card.screenshot({ path: join(SHOTS, 'erp-customer-card.png') });
    } finally {
      await page.close();
      await s.reject(id);
    }
  }, 120_000);
});
