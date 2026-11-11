/**
 * Andreas 2026-11-11: outside simulation, a limit only test-data tools use is
 * not shown. The Customers profile's test-data limit applies only to `setup`,
 * which only the CRM's simulation-only tools serve. On a production gateway
 * (no simulation; the CRM connector live, "On this computer") in a real
 * browser:
 *   - the Customers mandate card lists its write and delete limits, not the
 *     test-data one;
 *   - the mandate form does not show that control either, and the mandate it
 *     signs still carries the profile's value for it (display only).
 * (In simulation it shows as before: walkthrough-card-limits-mandates.test.ts.)
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { chromium, type Browser, type Page } from '@playwright/test';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import { ControlPlaneClient, PROFILES_DIR, GW_DIR, newSecret, startControlPlane, startMcpServer, type StackOptions } from '../src/helpers/gateway-stack.js';

const AS_PORT = 19858;
const CP_PORT = 19859;
const MCP_PORT = 19860;
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const SHOTS = process.env.HAP_E2E_SHOTS_DIR;

const CUSTOMERS = 'github.com/humanagencyprotocol/hap-profiles/customers@0.11';
const PROFILE_DOC = existsSync(join(PROFILES_DIR, 'customers', '0.11.profile.json'))
  ? JSON.parse(readFileSync(join(PROFILES_DIR, 'customers', '0.11.profile.json'), 'utf8'))
  : null;
/** Only meaningful against a gateway that has the rule. */
const available = !!PROFILE_DOC && existsSync(join(GW_DIR, 'apps', 'ui', 'src', 'lib', 'simulation-only-limits.ts'));
/** The profile's own name for the limit that only `setup` uses — read, never typed in. */
const SETUP_KEY = PROFILE_DOC
  ? Object.entries(PROFILE_DOC.boundsSchema.fields as Record<string, { appliesTo?: string[] }>).find(([, f]) => f.appliesTo?.length === 1 && f.appliesTo[0] === 'setup')?.[0]
  : undefined;
const SETUP_NAME: string | undefined = SETUP_KEY ? PROFILE_DOC.boundsSchema.fields[SETUP_KEY].displayName : undefined;

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-prod-limits-'));
const secret = newSecret();
// NOT simulation mode — the whole point.
const stack: StackOptions = { dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret, asUrl: AS_URL, extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' } };
const cp = new ControlPlaneClient(CP_URL);
const mcpInternal = new GatewayClient(`http://localhost:${MCP_PORT}`, secret);

let user: { apiKey: string; user: { id: string; did: string } };
let groupId: string;
let browser: Browser;

/** The text once it satisfies `ok` (the page settles: the gateway's mode and the profile load after the first render). */
async function settled(read: () => Promise<string>, ok: (t: string) => boolean, ms = 15_000): Promise<string> {
  const until = Date.now() + ms;
  let t = await read();
  while (!ok(t) && Date.now() < until) { await new Promise((r) => setTimeout(r, 250)); t = await read(); }
  return t;
}

async function signedIn(): Promise<Page> {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto(`${CP_URL}/login`, { waitUntil: 'networkidle' });
  await page.locator('input[type="password"]').fill(user.apiKey);
  await page.locator('button:has-text("Sign In")').click();
  await page.waitForURL((u) => !u.toString().includes('/login'), { timeout: 45_000 });
  return page;
}

async function mandatesMine(): Promise<Array<{ authorizationId?: string; authorization_id?: string; profileId?: string; profile_id?: string; bounds?: Record<string, unknown> }>> {
  const res = await fetch(`${AS_URL}/api/mandates/mine?status=active`, { headers: { 'X-API-Key': user.apiKey } });
  return ((await res.json()) as { mandates?: [] }).mandates ?? [];
}

describe.skipIf(!available)('production gateway hides limits only test-data tools use (real AS + gateway + crm-mcp live/local + browser)', () => {
  beforeAll(async () => {
    expect(SETUP_NAME, 'the Customers profile declares a limit that only setup uses').toBeTruthy();
    pm.buildGateway();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
    await pm.startSP(AS_PORT);
    user = await sp.register('Prod Limits', `prod-limits-${Date.now()}@test.local`);
    groupId = await sp.getPersonalGroupId(user.apiKey);
    await startControlPlane(pm, stack, 'cp');
    await startMcpServer(pm, stack, 'mcp');
    expect((await cp.login(user.apiKey)).status).toBe(200);
    const health = await (await fetch(`${CP_URL}/health`)).json() as { simulation?: boolean };
    expect(health.simulation, 'the gateway runs outside simulation').not.toBe(true);

    // The person's own CRM on this computer, saved the way the gateway UI saves it.
    const put = await cp.authed(user.apiKey, 'PUT', '/vault/credentials/crm', { mode: 'live', liveAdapter: 'local' });
    expect(put.status, await put.text()).toBe(200);
    const act = await cp.authed(user.apiKey, 'POST', '/mcp/integrations/crm/activate');
    expect(act.status, await act.text()).toBe(200);
    await mcpInternal.waitForIntegration('crm');

    // A Customers mandate signed with every limit, the test-data one included.
    const bounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 20, delete_daily_max: 0, [SETUP_KEY!]: 0 };
    const boundsHash = computeBoundsHash(bounds, PROFILE_DOC.boundsSchema.keyOrder);
    const scope = { contact_type: 'customer' };
    const scopeHash = computeScopeHash(scope, PROFILE_DOC.scopeSchema.keyOrder);
    const gate = { intent: 'Production limits e2e: customer records, each change approved.' };
    const att = await sp.submitMandate(user.apiKey, {
      profile_id: CUSTOMERS, profile_hash: profileHashFor(CUSTOMERS, PROFILES_DIR), group_id: groupId, bounds,
      bounds_hash: boundsHash, scope_hash: scopeHash, domain: 'owner', did: user.user.did, commitment_mode: 'review',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ intent: gate.intent }),
    });
    await mcpInternal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: scope }, CUSTOMERS, gate);
    if (SHOTS) mkdirSync(SHOTS, { recursive: true });
  }, 400_000);

  afterAll(async () => {
    if (browser) await browser.close().catch(() => {});
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 60_000);

  it('the mandate card lists write and delete, not the test-data limit', async () => {
    const page = await signedIn();
    try {
      await page.locator('.sidebar a[href="/mandates"]').click();
      await page.waitForURL('**/mandates');
      const card = page.getByTestId('mandate-card').filter({ hasText: /customers/i }).first();
      await card.waitFor({ timeout: 30_000 });
      await card.locator('.ob-head').click();
      const limits = card.getByTestId('mandate-limits');
      await limits.getByText(/Daily write limit/).first().waitFor({ timeout: 20_000 });
      const text = await settled(() => limits.innerText(), (t) => /Daily delete limit/.test(t) && !t.includes(SETUP_NAME!));
      if (process.env.HAP_E2E_SHOW_CARD) console.error('[prod limits] card limits:\n' + text);
      expect(text).toMatch(/Daily write limit/);
      expect(text).toMatch(/Daily delete limit/);
      expect(text).not.toContain(SETUP_NAME!);
      if (SHOTS) await card.screenshot({ path: join(SHOTS, 'production-crm-mandate.png') });
    } finally {
      await page.close();
    }
  }, 120_000);

  it('the form leaves the control out, and the mandate it signs still carries the value', async () => {
    const page = await signedIn();
    const before = new Set((await mandatesMine()).map((m) => m.authorizationId ?? m.authorization_id));
    try {
      await page.locator('.sidebar a[href="/mandates"]').click();
      await page.waitForURL('**/mandates');
      await page.locator('button:has-text("New mandate")').click();
      await page.waitForSelector('.profile-grid', { timeout: 15_000 });
      await page.locator('.profile-grid .card', { hasText: /CRM|Customers/ }).first().locator('button:has-text("Give a mandate")').click();
      await page.waitForURL((u) => u.toString().includes('/mandates/new/intent'), { timeout: 15_000 });
      await page.getByText('Daily write limit').first().waitFor({ timeout: 20_000 });
      const form = await settled(() => page.locator('body').innerText(), (t) => t.includes('Daily delete limit') && !t.includes(SETUP_NAME!));
      expect(form).toContain('Daily delete limit');
      expect(form).not.toContain(SETUP_NAME!);
      if (SHOTS) await page.screenshot({ path: join(SHOTS, 'production-crm-form.png'), fullPage: true });

      // Finish: scope, limits as seeded, intent, review, sign.
      // The scope is a row of chips; choose the one the mandate is for.
      await page.getByText('customer', { exact: true }).first().click();
      for (const plus of await page.locator('.stepper-increment').all()) await plus.click();
      await page.locator('button:has-text("Next")').click();
      await page.waitForSelector('.intent-textarea', { timeout: 15_000 });
      await page.fill('.intent-textarea', 'Production limits e2e: signed through the form.');
      await page.locator('button:has-text("Continue to Review")').click();
      await page.waitForURL((u) => u.toString().includes('/mandates/new/sign'), { timeout: 15_000 });
      // The review step lists the limits too; it settles once the mode and the profile are known.
      const review = await settled(() => page.locator('body').innerText(), (t) => t.includes('write_daily_max') && !t.includes(SETUP_KEY!));
      if (SHOTS) await page.screenshot({ path: join(SHOTS, 'production-crm-review.png'), fullPage: true });
      expect(review).not.toContain(SETUP_KEY!);
      await page.locator('button', { hasText: 'Review Each Action' }).click();
      await page.locator('input[placeholder*="e.g."]').fill('Form mandate');
      if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
      await page.locator('button', { hasText: /^Sign mandate/ }).last().click();
      await page.waitForURL((u) => u.toString().includes('/mandates') && !u.toString().includes('/new/'), { timeout: 20_000 });
    } catch (err) {
      if (SHOTS) await page.screenshot({ path: join(SHOTS, 'production-crm-form-failure.png'), fullPage: true }).catch(() => {});
      throw err;
    } finally {
      await page.close();
    }
    const created = (await mandatesMine()).find((m) => !before.has(m.authorizationId ?? m.authorization_id));
    expect(created, 'the form signed a new mandate').toBeTruthy();
    // The bounds the Authority Server holds for it (its own list, as the Mandates page reads it).
    const signed = (created!.bounds ?? {}) as Record<string, unknown>;
    if (process.env.HAP_E2E_SHOW_CARD) console.error('[prod limits] signed bounds: ' + JSON.stringify(signed));
    expect(Number(signed[SETUP_KEY!]), 'the hidden limit is still signed, with the profile default').toBe(Number(PROFILE_DOC.boundsSchema.fields[SETUP_KEY!].default ?? 0));
  }, 180_000);
});
