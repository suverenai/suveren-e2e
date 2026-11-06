/**
 * The approval panel (gateway PR #185) - what a person sees when an approval
 * "for me" arrives while they are on another page. Real stack, simulation
 * gateway (the practice CRM is the downstream); the agent is a real MCP client.
 *
 *   P1  the panel opens BY ITSELF over the Dashboard, shows the approval's card,
 *       and the person decides it from there: Approve -> the result shows, the
 *       panel closes, the contact exists. (Nothing here switches auto-open off.)
 *   P2  "Don't open automatically": the panel goes to the strip, a new approval
 *       only raises the count (strip, no panel) - and "Open automatically again"
 *       from the strip menu turns it back on: the next approval opens the panel.
 *       The setting is the gateway's per-user setting (/api/gateway-settings);
 *       each step is checked against it, not only against the screen.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { APIRequestContext, Page } from '@playwright/test';
import {
  test, expect,
  SP_URL, GW_URL, GW_MCP_URL, INTERNAL_SECRET,
  registerOnSP, signInToGateway, handleOnboarding, activateIntegration,
  spApiAttest, latestProfileId,
} from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const CUSTOMERS_PROFILE = latestProfileId('customers');
const KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const SCOPE = { contact_type: 'customer' };
const BOUNDS = { profile: CUSTOMERS_PROFILE, read_access: 'unlimited', export_access: 'none', write_daily_max: 20, delete_daily_max: 0, setup_daily_max: 0 };

async function reviewMandate(request: APIRequestContext, apiKey: string, did: string): Promise<void> {
  const intent = 'Approval panel e2e: review new customers.';
  const boundsHash = computeBoundsHash(BOUNDS, KEY_ORDER);
  const scopeHash = computeScopeHash(SCOPE, Object.keys(SCOPE));
  const att = await spApiAttest(request, apiKey, {
    profile_id: CUSTOMERS_PROFILE, domain: 'owner', did,
    bounds: BOUNDS, bounds_hash: boundsHash, scope_hash: scopeHash,
    gate_content_hashes: hashGateContent({ intent }),
    execution_context_hash: 'sha256:' + 'e'.repeat(64),
    commitment_mode: 'review', title: 'Customer review',
  });
  expect(att.status).toBe('active');
  const res = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
    body: JSON.stringify({ authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: SCOPE, path: CUSTOMERS_PROFILE, gateContent: { intent } }),
  });
  expect(res.ok, await res.text()).toBe(true);
}

/** The agent proposes a contact (review mode: it waits for the person). */
async function propose(name: string): Promise<void> {
  const client = new Client({ name: 'approval-panel-agent', version: '1.0.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  try {
    const res = await client.callTool({
      name: 'crm__create_contact',
      arguments: { name, email: `${name.toLowerCase().replace(/\W+/g, '.')}@panel.example`, type: 'customer', contact_type: 'customer' },
    });
    const body = ((res.content as Array<{ text?: string }>) ?? [])[0]?.text ?? '';
    expect(res.isError, body).toBeFalsy();
    expect(body).toMatch(/Awaiting commitment/);
  } finally {
    await client.close();
  }
}

async function contactExists(name: string): Promise<boolean> {
  const client = new Client({ name: 'approval-panel-reader', version: '1.0.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  try {
    const res = await client.callTool({ name: 'crm__find_contacts', arguments: { query: name } });
    return JSON.stringify(res.content).includes(name);
  } finally {
    await client.close();
  }
}

async function autoOpenSetting(page: Page, apiKey: string): Promise<boolean> {
  const res = await page.request.get(`${GW_URL}/api/gateway-settings`, { headers: { 'x-api-key': apiKey } });
  expect(res.ok()).toBe(true);
  return ((await res.json()) as { openApprovalsAutomatically: boolean }).openApprovalsAutomatically;
}

test.describe.serial('Approval panel (real stack, simulation gateway)', () => {
  let apiKey: string;
  let page: Page;
  test.beforeAll(async ({ browser }) => { page = await browser.newPage(); });
  test.afterAll(async () => { await page?.close(); });

  test('setup: a review mandate, the person on the Dashboard', async ({ request }) => {
    test.setTimeout(180_000);
    apiKey = await registerOnSP(page, 'Approval Panel');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    const did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'CRM');
    await reviewMandate(request, apiKey, did);
    await page.click('.sidebar-item:has-text("Dashboard")');
    await expect(page.locator('.page-title')).toHaveText('Dashboard');
    // The default: approvals open by themselves.
    expect(await autoOpenSetting(page, apiKey)).toBe(true);
  });

  test('P1: an approval arriving while the person is on the Dashboard opens the panel by itself; it is decided from there', async () => {
    test.setTimeout(120_000);
    const panel = page.getByTestId('approval-panel');
    await expect(panel).toHaveAttribute('aria-hidden', 'true');
    await propose('Panel Paula');

    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });
    const card = panel.getByTestId('approval-card');
    await expect(card).toHaveCount(1);
    await expect(card.getByTestId('approval-summary')).toHaveText('Create contact Panel Paula', { timeout: 30_000 });
    await expect(page).toHaveURL(/\/$|\/dashboard/); // still the Dashboard underneath

    await card.locator('button:has-text("Approve")').click();
    await expect(page.getByTestId('decision-stamp')).toContainText('Approved', { timeout: 30_000 });
    // Nothing else waits: the panel closes by itself.
    await expect(panel).toHaveAttribute('aria-hidden', 'true', { timeout: 15_000 });
    await expect(async () => { expect(await contactExists('Panel Paula')).toBe(true); }).toPass({ timeout: 45_000 });
  });

  test('P2: "Don\'t open automatically" leaves only the strip; "Open automatically again" brings the panel back', async () => {
    test.setTimeout(180_000);
    const panel = page.getByTestId('approval-panel');
    await propose('Panel Quentin');
    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });

    // Switch it off from the panel.
    // (A wide window has the button in the header; a narrow one, in the "More" menu.)
    const direct = page.getByTestId('approval-auto-toggle');
    if (!(await direct.isVisible().catch(() => false))) await page.getByTestId('approval-head-menu').click();
    await page.getByTestId('approval-auto-toggle').click();
    await expect(page.getByTestId('approval-strip')).toBeVisible({ timeout: 15_000 });
    await expect(panel).toHaveAttribute('aria-hidden', 'true');
    await expect(async () => { expect(await autoOpenSetting(page, apiKey)).toBe(false); }).toPass({ timeout: 15_000 });

    // A new approval only raises the count - the panel stays shut.
    await propose('Panel Rosa');
    await expect(page.getByTestId('approval-strip-open')).toContainText('2', { timeout: 45_000 });
    await expect(panel).toHaveAttribute('aria-hidden', 'true');

    // Back on, from the strip menu.
    await page.getByTestId('approval-strip-menu').click();
    await page.getByTestId('approval-strip-toggle').click();
    await expect(async () => { expect(await autoOpenSetting(page, apiKey)).toBe(true); }).toPass({ timeout: 15_000 });

    // The next approval opens the panel again.
    await propose('Panel Stefan');
    await expect(panel).toHaveAttribute('aria-hidden', 'false', { timeout: 45_000 });
    await expect(page.getByTestId('approval-position')).toContainText('of', { timeout: 15_000 });
  });
});
