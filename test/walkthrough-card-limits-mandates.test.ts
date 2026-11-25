/**
 * Walkthrough 2026-11-11 (maintainer), three problems, on the real stack (Authority
 * Server + the gateway's control plane AND MCP server + the published crm
 * connector), in a real browser:
 *
 * 1. An update's approval card showed the contact as it is ("Name: Maria",
 *    revision 1, every field) under "Runs exactly as shown" — not the change.
 *    Now: the changed field old → new, the unchanged fields folded.
 * 2. The CRM mandate card listed "Team limit per day … used" three times with no
 *    way to tell write, delete and test-data loads apart, and "0 of 0 used" for
 *    the ones that are not allowed. Now each reads by its own name.
 * 3. A mandate approved from a Setup proposal did not show under Mandates at
 *    once: the page waited for an event that never came.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { chromium, type Browser, type Page } from '@playwright/test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import {
  ControlPlaneClient, MANIFESTS_DIR, PROFILES_DIR, newSecret, startControlPlane, startMcpServer, textOf, type StackOptions,
} from '../src/helpers/gateway-stack.js';
import { openFirstApprovalInPanel } from '../src/helpers/gateway-ui.js';

const AS_PORT = 19850;
const CP_PORT = 19851;
const MCP_PORT = 19852;
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const MCP_URL = `http://localhost:${MCP_PORT}`;
const SHOTS = process.env.HAP_E2E_SHOTS_DIR;

const P = 'github.com/humanagencyprotocol/hap-profiles';
const CUSTOMERS = `${P}/customers@0.10`;
const DELEGATION = `${P}/delegation@0.4`;
const MANIFEST = join(MANIFESTS_DIR, 'crm.json');
const manifest = existsSync(MANIFEST) ? JSON.parse(readFileSync(MANIFEST, 'utf8')) : null;
const available = !!manifest?.toolGating?.overrides?.update_contact?.preview
  && existsSync(join(PROFILES_DIR, 'delegation', '0.4.profile.json'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-walkthrough-e-'));
const secret = newSecret();
const stack: StackOptions = {
  dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret, asUrl: AS_URL,
  extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_SIMULATION: '1' },
};
const cp = new ControlPlaneClient(CP_URL);
const mcpInternal = new GatewayClient(MCP_URL, secret);

let user: { apiKey: string; user: { id: string; did: string } };
let groupId: string;
let agent: Client;
let browser: Browser;

async function call(tool: string, args: Record<string, unknown>) {
  const r = await agent.callTool({ name: tool, arguments: args });
  return { denied: r.isError === true, text: textOf(r) };
}

async function pending(): Promise<Array<{ id: string; tool: string }>> {
  const res = await fetch(`${AS_URL}/api/proposals?domain=owner`, { headers: { 'X-API-Key': user.apiKey } });
  return (((await res.json()) as { proposals?: Array<{ id: string; tool: string; status: string }> }).proposals ?? [])
    .filter((p) => p.status === 'pending');
}

async function grant(profileId: string, keys: string[], bounds: Record<string, string | number>, scopeKeys: string[], scope: Record<string, string>, intent: string) {
  const full = { profile: profileId, ...bounds };
  const boundsHash = computeBoundsHash(full, keys);
  const scopeHash = computeScopeHash(scope, scopeKeys);
  const gate = { intent };
  const att = await sp.submitMandate(user.apiKey, {
    profile_id: profileId, profile_hash: profileHashFor(profileId, PROFILES_DIR), group_id: groupId,
    bounds: full, bounds_hash: boundsHash, scope_hash: scopeHash,
    domain: 'owner', did: user.user.did, commitment_mode: 'review',
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ intent }),
  });
  await mcpInternal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: scope }, profileId, gate);
}

async function rejectPending() {
  for (const p of await pending()) {
    const r = await cp.authed(user.apiKey, 'POST', `/api/proposals/${p.id}/resolve`, { action: 'reject', domain: 'owner' });
    expect(r.ok, await r.text()).toBe(true);
  }
}

/** A signed-in page (in-app navigation only: the API key lives in the page's memory). */
async function signedIn(): Promise<Page> {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto(`${CP_URL}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[type="password"]').fill(user.apiKey);
  await page.locator('button:has-text("Sign In")').click();
  await page.waitForURL((u) => !u.toString().includes('/login'), { timeout: 45_000 });
  return page;
}

async function openApprovals(page: Page) {
  await page.locator('.sidebar a[href="/approvals"]').click();
  await page.waitForURL('**/approvals');
  await openFirstApprovalInPanel(page);
  await page.waitForFunction(() => {
    const el = document.querySelector('[data-testid="approval-preview"]');
    return !!el && el.getAttribute('data-preview-status') !== 'loading';
  }, null, { timeout: 30_000 });
}

async function openMandates(page: Page) {
  await page.locator('.sidebar a[href="/mandates"]').click();
  await page.waitForURL('**/mandates');
  await page.getByTestId('mandate-card').first().waitFor({ timeout: 30_000 });
}

describe.skipIf(!available)('walkthrough 2026-11-11: update card, limit names, Mandates after approval (real stack + browser)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
    await pm.startSP(AS_PORT);
    user = await sp.register('Walkthrough E', `walkthrough-e-${Date.now()}@test.local`);
    groupId = await sp.getPersonalGroupId(user.apiKey);
    await startControlPlane(pm, stack, 'cp');
    await startMcpServer(pm, stack, 'mcp');
    const login = await cp.login(user.apiKey);
    expect(login.status, JSON.stringify(login.body)).toBe(200);

    await mcpInternal.addIntegration({
      id: 'crm', name: manifest.name, command: manifest.mcp.command, args: manifest.mcp.args, envKeys: {},
      profile: manifest.profile, enabled: true, toolGating: manifest.toolGating, npmPackage: manifest.npmPackage,
    } as Parameters<GatewayClient['addIntegration']>[0]);
    await mcpInternal.waitForIntegration('crm');

    // CRM in review: writes 20 a day, deletes and test-data loads not allowed.
    await grant(CUSTOMERS, ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'],
      { read_access: 'unlimited', export_access: 'none', write_daily_max: 20, delete_daily_max: 0, setup_daily_max: 0 },
      ['contact_type'], { contact_type: 'customer' }, 'Walkthrough E: change customer records after my approval.');
    // Delegation: the AI may propose Sales mandates, review only.
    await grant(DELEGATION, ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'],
      { read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 5 },
      ['allowed_profiles', 'allowed_modes'], { allowed_profiles: 'sales', allowed_modes: 'review' }, 'Walkthrough E: the AI may propose Sales mandates.');

    await new Promise((r) => setTimeout(r, 2_000));
    agent = new Client({ name: 'walkthrough-e-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
    if (SHOTS) mkdirSync(SHOTS, { recursive: true });
  }, 400_000);

  afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 60_000);

  let contactId = '';

  it('setup: a contact "Maria" exists at revision 1 (created through an approved proposal)', async () => {
    const c = await call('crm__create_contact', { name: 'Maria', type: 'customer', company: 'Example' });
    expect(c.denied, c.text).toBe(false);
    const id = c.text.match(/Proposal ID: ([a-f0-9-]+)/)?.[1];
    expect(id, c.text).toBeTruthy();
    const r = await cp.authed(user.apiKey, 'POST', `/api/proposals/${id}/resolve`, { action: 'commit', domain: 'owner' });
    expect(r.ok, await r.text()).toBe(true);
    const until = Date.now() + 30_000;
    while (!contactId && Date.now() < until) {
      const f = await call('crm__find_contacts', { query: 'Maria' });
      contactId = f.text.match(/"id":\s*"([^"]+)"/)?.[1] ?? '';
      if (!contactId) await new Promise((res) => setTimeout(res, 1_000));
    }
    expect(contactId).toBeTruthy();
  }, 90_000);

  it('problem 1: the update card shows Name Maria → Maria Berger, not the record as it is', async () => {
    const u = await call('crm__update_contact', { id: contactId, revision: 1, name: 'Maria Berger', contact_type: 'customer' });
    expect(u.text).toContain('Awaiting commitment');

    const page = await signedIn();
    try {
      await openApprovals(page);
      const card = page.getByTestId('approval-panel').locator('[data-testid="approval-card"]').first();
      const tile = card.getByTestId('sealed-values');
      await tile.getByTestId('change-table').waitFor({ timeout: 20_000 });
      expect(await tile.getByTestId('change-table').count()).toBe(1);
      const rows = tile.getByTestId('change-row');
      expect(await rows.count()).toBe(1);
      const row = (await rows.first().innerText()).replace(/\s+/g, ' ');
      expect(row).toMatch(/Name Maria Maria Berger/);
      expect(await tile.locator('.compare-now').first().innerText()).toBe('Maria');
      expect(await tile.locator('.compare-new').first().innerText()).toBe('Maria Berger');
      // The value being replaced is struck through (maintainer, 2026-11-11); the new one is not.
      const deco = (sel: string) => tile.locator(sel).first().evaluate((el) => getComputedStyle(el).textDecorationLine);
      expect(await deco('.compare-now')).toContain('line-through');
      expect(await deco('.compare-new')).not.toContain('line-through');
      const tileText = await tile.innerText();
      expect(tileText).toMatch(/What will be changed in CRM/i); // the heading is set in capitals by CSS
      expect(await tile.locator('.av3-sealed-h').innerText()).toBe('You approve this change');
      expect(tileText).toMatch(/You approve revision 1; if it changes, CRM refuses it\./);
      // Unchanged fields are folded, not listed as if they were the change.
      const unchanged = tile.getByTestId('change-unchanged');
      expect(await unchanged.getAttribute('open')).toBeNull();
      expect(await unchanged.innerText()).toMatch(/Unchanged in CRM/);
      if (SHOTS) await card.screenshot({ path: join(SHOTS, 'update-card.png') });
    } finally {
      await page.close();
    }
  }, 120_000);

  it('problem 2: the CRM mandate card names each limit by its own name and shows the number of a 0 limit', async () => {
    await rejectPending(); // an open approval panel would cover the list
    const page = await signedIn();
    try {
      await openMandates(page);
      const card = page.getByTestId('mandate-card').filter({ hasText: /customers/i }).first();
      await card.locator('.ob-head').click();
      const limits = card.getByTestId('mandate-limits');
      await limits.waitFor({ timeout: 20_000 });
      // The labels come from the profile, which the card loads after it opens.
      await limits.getByText(/Daily write limit/).first().waitFor({ timeout: 20_000 });
      // The figures follow once the tickets are read (when the system can prove them).
      // Each row's figures arrive on their own read; wait for all three.
      await limits.getByText(/of 20 used/).first().waitFor({ timeout: 15_000 });
      const until = Date.now() + 15_000;
      while (await limits.getByText('0 of 0 used', { exact: true }).count() < 2 && Date.now() < until) await page.waitForTimeout(250);
      const text = await limits.innerText();
      if (process.env.HAP_E2E_SHOW_CARD) console.error('[walkthrough E] limits:\n' + text);
      // Each limit by its own name (personal workspace: no "(team)"), the window said once.
      expect(text).toMatch(/^Daily write limit$/m);
      expect(text).toMatch(/^Daily delete limit$/m);
      expect(text).toMatch(/^Test-data loads per day$/m);
      expect(text).not.toMatch(/Limit per day|not allowed/);
      // A limit of 0 shows its number.
      expect(text).toMatch(/Daily delete limit\n0 of 0 used(\n|$)/);
      expect(text).toMatch(/Test-data loads per day\n0 of 0 used(\n|$)/);
      if (SHOTS) await card.screenshot({ path: join(SHOTS, 'mandate-limits.png') });
    } finally {
      await page.close();
    }
  }, 120_000);

  it('problem 3: a mandate signed from a Setup proposal shows under Mandates at once, without a reload', async () => {
    await rejectPending(); // the Setup proposal is the only one waiting
    const r = await call('setup__create_mandate', {
      profile: 'sales',
      limits: { read_access: 'unlimited', value_max: 1000, discount_max: 5, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 },
      scope: { currency: 'EUR' }, mode: 'review', duration_hours: 720,
      title: 'Walkthrough quotes', intent: 'Why — answer quote requests the same day.',
    });
    expect(r.denied, r.text).toBe(false);

    const [proposal] = await pending();
    expect(proposal?.tool).toBe('setup__create_mandate');

    const watching = await signedIn();
    try {
      await openMandates(watching);
      // Only the Mandates list counts — the open approval panel names the proposal too.
      const listed = watching.getByTestId('mandate-card').filter({ hasText: 'Walkthrough quotes' });
      expect(await listed.count()).toBe(0);

      // Signed through the gateway's /api proxy — the request the card's "Sign mandate" button sends.
      const signedAt = Date.now();
      const res = await cp.authed(user.apiKey, 'POST', `/api/proposals/${proposal.id}/resolve`, { action: 'commit', domain: 'owner' });
      expect(res.ok, await res.text()).toBe(true);

      // Backend truth, read again by the page: no reload, no navigation.
      await listed.first().waitFor({ timeout: 15_000 });
      const seconds = (Date.now() - signedAt) / 1000;
      console.error(`[walkthrough E] new mandate under Mandates after ${seconds.toFixed(1)} s`);
      if (SHOTS) await watching.screenshot({ path: join(SHOTS, 'mandates-after-approval.png'), fullPage: true });
    } finally {
      await watching.close();
    }
  }, 180_000);
});
