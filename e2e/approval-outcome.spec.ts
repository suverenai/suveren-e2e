/**
 * After Approve the card stays until the outcome is known; a dead mandate
 * cannot be approved. Real stack, simulation gateway, a real AI client.
 *
 *   O1  Refused after approval: the limit fills up between proposing and
 *       approving. The person sees the refusal on the card at once, and it
 *       stays there while the next approval waits, until they press Next.
 *   O2  The last approval refused: the card stays until Close.
 *   O3  The mandate is revoked while the card is open: the card says so in
 *       plain words, Approve is gone, Reject still clears it.
 *   O4  No answer in time: the card says it does not know (screenshot state;
 *       the server's answer is held back by the test browser only here).
 *
 * Screenshots (light, dark, phone) go to E2E_SHOTS_DIR when set.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { join } from 'node:path';
import type { APIRequestContext, Page } from '@playwright/test';
import {
  test, expect, SP_URL, GW_MCP_URL, INTERNAL_SECRET,
  registerOnSP, signInToGateway, handleOnboarding, activateIntegration, spApiAttest, spApiReceipt, latestProfileId,
} from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const PROFILE = latestProfileId('customers');
const KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const boundsFor = (write: number) => ({ profile: PROFILE, read_access: 'unlimited', export_access: 'none', write_daily_max: write, delete_daily_max: 0, setup_daily_max: 0 });

async function mandate(request: APIRequestContext, apiKey: string, did: string, opts: { scope: string; mode: 'review' | 'automatic'; write: number; push: boolean }): Promise<string> {
  const intent = `Outcome e2e: ${opts.scope}.`;
  const bounds = boundsFor(opts.write);
  const scope = { contact_type: opts.scope };
  const boundsHash = computeBoundsHash(bounds, KEY_ORDER);
  const scopeHash = computeScopeHash(scope, Object.keys(scope));
  const att = await spApiAttest(request, apiKey, {
    profile_id: PROFILE, domain: 'owner', did, bounds, bounds_hash: boundsHash, scope_hash: scopeHash,
    gate_content_hashes: hashGateContent({ intent }),
    execution_context_hash: 'sha256:' + 'e'.repeat(64), commitment_mode: opts.mode, title: `Outcome ${opts.scope}`,
  });
  expect(att.status).toBe('active');
  if (opts.push) {
    const res = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
      body: JSON.stringify({ authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: scope, path: PROFILE, gateContent: { intent } }),
    });
    expect(res.ok, await res.text()).toBe(true);
  }
  return att.authorization_id as string;
}

async function propose(name: string, type: string): Promise<string> {
  const client = new Client({ name: 'outcome-agent', version: '1.0.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  try {
    const res = await client.callTool({ name: 'crm__create_contact', arguments: { name, email: `${name.toLowerCase().replace(/\W+/g, '.')}@panel.example`, type } });
    const body = ((res.content as Array<{ text?: string }>) ?? [])[0]?.text ?? '';
    expect(res.isError, body).toBeFalsy();
    expect(body).toMatch(/Awaiting commitment/);
    return body.match(/Proposal ID: ([a-f0-9]+)/)![1];
  } finally {
    await client.close();
  }
}

/** The light, dark and phone pictures of what is on screen now. Skipped when no folder is given. */
async function shots(page: Page, name: string): Promise<void> {
  const dir = process.env.E2E_SHOTS_DIR;
  if (!dir) return;
  const size = page.viewportSize() ?? { width: 1280, height: 800 };
  for (const [suffix, scheme, viewport] of [
    ['light', 'light', { width: 1280, height: 900 }],
    ['dark', 'dark', { width: 1280, height: 900 }],
    ['phone', 'light', { width: 390, height: 844 }],
  ] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), scheme);
    await page.setViewportSize(viewport);
    await page.waitForTimeout(250);
    await page.screenshot({ path: join(dir, `${name}-${suffix}.png`), fullPage: false });
  }
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize(size);
}

test.describe.serial('The outcome of an approval, and a dead mandate (real stack, simulation gateway)', () => {
  let apiKey = '';
  let did = '';
  let page: Page;
  let burner = '';
  let lastProposal = '';
  let revokedMandate = '';
  test.beforeAll(async ({ browser }) => { page = await browser.newPage({ viewport: { width: 1280, height: 900 } }); });
  test.afterAll(async () => { await page?.close(); });

  test('setup: a review mandate with room, and a mandate that can fill the shared limit', async ({ request }) => {
    test.setTimeout(180_000);
    apiKey = await registerOnSP(page, 'Outcome');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'CRM');
    await mandate(request, apiKey, did, { scope: 'customer', mode: 'review', write: 2, push: true });
    burner = await mandate(request, apiKey, did, { scope: 'vendor', mode: 'automatic', write: 50, push: false });
    await page.click('.sidebar-item:has-text("Dashboard")');
    await expect(page.locator('.page-title')).toHaveText('Dashboard');
  });

  test('O1: refused after approval shows the reason at once, and stays while the next one waits', async ({ request }) => {
    test.setTimeout(120_000);
    await propose('Refused Ruth', 'customer');
    await propose('Next Nora', 'customer');
    const panel = page.getByTestId('approval-panel');
    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });
    await expect(panel.getByTestId('approval-summary')).toHaveText('Create contact Refused Ruth', { timeout: 30_000 });

    // Between proposing and approving the shared daily limit is used up, on the server.
    for (let i = 0; i < 2; i++) {
      const t = await spApiReceipt(request, apiKey, { authorizationId: burner, profileId: PROFILE, action: 'crm__create_contact', actionType: 'write', idempotencyKey: `burn-${Date.now()}-${i}`, executionContext: { contact_type: 'vendor', action_type: 'write' } });
      expect(t.status, JSON.stringify(t.body)).toBe(201);
    }

    await panel.locator('button:has-text("Approve")').first().click();
    const refused = page.getByTestId('decision-refused');
    await expect(refused).toBeVisible({ timeout: 45_000 });
    await expect(refused.getByTestId('refusal-sentence')).toContainText('The daily limit is used up: 2 of 2');
    await expect(refused).toContainText('No ticket was issued');
    await shots(page, 'refused-after-approve');

    // The result does not time away, and the next approval has not replaced it.
    await page.waitForTimeout(4_000);
    await expect(refused).toBeVisible();
    await expect(page.getByTestId('result-dismiss')).toHaveText('Next');
    await page.getByTestId('result-dismiss').click();
    await expect(panel.getByTestId('approval-summary')).toHaveText('Create contact Next Nora', { timeout: 30_000 });
    await expect(panel.locator('button:has-text("Approve")')).toBeVisible();
  });

  test('O2: the last approval refused: the card stays until Close', async () => {
    test.setTimeout(120_000);
    const panel = page.getByTestId('approval-panel');
    await panel.locator('button:has-text("Approve")').first().click();
    const refused = page.getByTestId('decision-refused');
    await expect(refused).toBeVisible({ timeout: 45_000 });
    await page.waitForTimeout(4_000);
    await expect(panel).toHaveAttribute('aria-hidden', 'false');
    await expect(page.getByTestId('result-dismiss')).toHaveText('Close');
    await page.getByTestId('result-dismiss').click();
    await expect(panel).toHaveAttribute('aria-hidden', 'true', { timeout: 15_000 });
  });

  test('O3: the mandate is revoked while the card is open: plain words, no Approve', async ({ request }) => {
    test.setTimeout(120_000);
    revokedMandate = await mandate(request, apiKey, did, { scope: 'lead', mode: 'review', write: 50, push: true });
    lastProposal = await propose('Revoked Ronnie', 'lead');
    const panel = page.getByTestId('approval-panel');
    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });
    await expect(panel.locator('button:has-text("Approve")')).toBeVisible({ timeout: 30_000 });

    const r = await request.post(`${SP_URL}/api/authorizations/${revokedMandate}/revoke`, { headers: { 'x-api-key': apiKey }, data: {} });
    expect(r.ok()).toBe(true);

    const ended = page.getByTestId('mandate-ended');
    await expect(ended).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId('mandate-ended-head')).toHaveText('This mandate was revoked.');
    await expect(panel.locator('button:has-text("Approve")')).toHaveCount(0);
    await expect(panel.getByTestId('btn-change-needed')).toHaveCount(0);
    await expect(ended).not.toContainText('MANDATE_REVOKED');
    await shots(page, 'mandate-revoked-on-card');

    await panel.getByTestId('btn-reject').click();
    await expect(panel).toHaveAttribute('aria-hidden', 'true', { timeout: 15_000 });
    const got = await request.get(`${SP_URL}/api/proposals/${lastProposal}`, { headers: { 'x-api-key': apiKey } });
    expect((await got.json()).proposal.status).toBe('rejected');
  });

  test('O4 (picture): no answer in time, the card says it does not know', async ({ request }) => {
    test.setTimeout(120_000);
    await mandate(request, apiKey, did, { scope: 'partner', mode: 'review', write: 50, push: true });
    const id = await propose('Slow Sally', 'partner');
    const panel = page.getByTestId('approval-panel');
    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });
    await expect(panel.locator('button:has-text("Approve")')).toBeVisible({ timeout: 30_000 });
    // Only for the "no answer" picture: the browser keeps reading this proposal as approved.
    await page.route(new RegExp(`/api/proposals/${id}$`), async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const res = await route.fetch();
      const body = await res.json();
      await route.fulfill({ response: res, json: { proposal: { ...body.proposal, status: 'committed' } } });
    });
    await panel.locator('button:has-text("Approve")').first().click();
    await expect(page.getByTestId('decision-waiting')).toBeVisible({ timeout: 15_000 });
    await shots(page, 'outcome-waiting');
    await expect(page.getByTestId('decision-unknown')).toBeVisible({ timeout: 45_000 });
    await expect(page.getByTestId('decision-unknown')).toContainText('not known whether this ran');
    await shots(page, 'outcome-unknown');
    await page.unroute(new RegExp(`/api/proposals/${id}$`));
  });
});
