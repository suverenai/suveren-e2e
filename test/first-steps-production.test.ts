/**
 * Two things a person meets first, on a PRODUCTION gateway (no simulation), in a real browser:
 *
 * 1. The first-steps card ("Get started") leads a person who has no mandate, in production too
 *    (gateway 4e17fe4). Until now only proven in simulation mode (first-run-card.test.ts).
 * 2. The mandate form never picks a duration for the person (gateway 783225e): Sign stays
 *    disabled and says "Choose how long this mandate should last." until a duration is chosen;
 *    a duration chosen upstream — the AI's proposal (Edit before signing) or a mandate being
 *    copied — arrives pre-selected.
 *
 * Real stack: Authority Server, the gateway's control plane serving the built UI, the MCP server.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { chromium, type Browser, type Page } from '@playwright/test';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { ControlPlaneClient, PROFILES_DIR, newSecret, startControlPlane, startMcpServer, textOf, type StackOptions } from '../src/helpers/gateway-stack.js';
import { localProfilesForAs } from '../src/helpers/local-profiles.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import { openFirstApprovalInPanel } from '../src/helpers/gateway-ui.js';

const AS_PORT = 18890;
const CP_PORT = 18891;
const MCP_PORT = 18892;
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const DELEGATION = `${P}/delegation@0.6`;
const available = existsSync(join(PROFILES_DIR, 'delegation', '0.6.profile.json'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-first-steps-prod-'));
const secret = newSecret();
// Production: no SUVEREN_SIMULATION.
const stack: StackOptions = {
  dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret, asUrl: AS_URL,
  extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
};
const cp = new ControlPlaneClient(CP_URL);
const mcpInternal = new GatewayClient(`http://localhost:${MCP_PORT}`, secret);

let browser: Browser;
let page: Page;
let user: Awaited<ReturnType<SPClient['register']>>;

/** Into a page inside the app (a full page load drops the in-memory API key). */
async function go(href: string, until: RegExp) {
  await page.locator(`.sidebar a[href="${href}"]`).first().dispatchEvent('click');
  await page.waitForURL(until);
}

/** The preset the Duration field shows as chosen, or the custom value; '' when nothing is chosen. */
async function chosenDuration(): Promise<string> {
  return page.evaluate(() => {
    const label = [...document.querySelectorAll('.field-label')].find((l) => l.textContent?.includes('Duration'));
    const field = label?.parentElement;
    if (!field) return 'no duration field';
    const picked = [...field.querySelectorAll('button')].find((b) => getComputedStyle(b).borderTopWidth === '2px');
    if (picked) return picked.textContent?.trim() ?? '';
    const custom = field.querySelector('input[type="number"]') as HTMLInputElement | null;
    return custom?.value ? `custom ${custom.value} ${(field.querySelector('select') as HTMLSelectElement | null)?.value ?? ''}` : '';
  });
}

const signButton = () => page.locator('button', { hasText: /^Sign mandate/ });

/** From the Scope & Limits step (or Intent) to the Sign step. */
async function toSignStep() {
  const next = page.locator('button:has-text("Next")').first();
  await next.or(page.locator('textarea.intent-textarea')).first().waitFor({ timeout: 15_000 });
  if (await next.isVisible().catch(() => false)) await next.click();
  try {
    await page.locator('textarea.intent-textarea').waitFor({ timeout: 10_000 });
  } catch (err) {
    const buttons = await page.locator('button').evaluateAll((bs) => bs.map((b) => `${(b as HTMLButtonElement).innerText.trim()}${(b as HTMLButtonElement).disabled ? ' [disabled]' : ''}`).join(' | '));
    const selects = await page.locator('select').evaluateAll((ss) => ss.map((x) => (x as HTMLSelectElement).value).join(','));
    throw new Error(`no intent step at ${page.url()}: buttons ${buttons}; selects ${selects}\n${err}`);
  }
  if (!(await page.locator('textarea.intent-textarea').inputValue()).trim()) {
    await page.locator('textarea.intent-textarea').fill('Why — answer customers the same day.');
  }
  await page.locator('button:has-text("Continue to Review")').click();
  await page.waitForURL(/\/mandates\/new\/sign/, { timeout: 15_000 });
  await signButton().waitFor({ timeout: 15_000 });
}

async function signDelegation(): Promise<string> {
  const groupId = await sp.getPersonalGroupId(user.apiKey);
  const bounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 5 };
  const scope = { allowed_profiles: 'email', allowed_modes: 'review' };
  const boundsHash = computeBoundsHash(bounds, ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max']);
  const contextHash = computeScopeHash(scope, ['allowed_profiles', 'allowed_modes']);
  const gate = { intent: 'E2E: my AI prepares my mandates; I approve each one.' };
  const att = await sp.submitMandate(user.apiKey, {
    profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: groupId, bounds, bounds_hash: boundsHash, scope_hash: contextHash,
    domain: 'owner', did: user.user.did, commitment_mode: 'review',
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ g: 1 }),
  });
  await mcpInternal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, DELEGATION, gate);
  return att.authorization_id;
}

describe.skipIf(!available)('first steps and the mandate duration on a production gateway (real stack + browser)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
    const profiles = localProfilesForAs(PROFILES_DIR);
    await pm.startSP(AS_PORT, { cwd: profiles.cwd, env: profiles.env });
    user = await sp.register('First Steps Prod', `first-steps-prod-${Date.now()}@test.local`);
    await startControlPlane(pm, stack);
    await startMcpServer(pm, stack);
    expect((await cp.login(user.apiKey)).status).toBe(200);

    page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    await page.goto(`${CP_URL}/login`, { waitUntil: 'networkidle' });
    await page.locator('input[type="password"]').fill(user.apiKey);
    await page.locator('button:has-text("Sign In")').click();
    await page.waitForURL((u) => !u.toString().includes('/login'), { timeout: 45_000 });
  }, 300_000);

  afterAll(async () => {
    await browser?.close();
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 30_000);

  it('no mandate, production: the "Get started" card leads, and the stats wait', async () => {
    const health = await cp.health();
    expect(JSON.stringify(health)).not.toMatch(/"simulation":\s*true/);
    await go('/mandates', /\/mandates/);
    await go('/', /\/$/);
    await page.getByText('Get started', { exact: true }).waitFor({ timeout: 20_000 });
    await page.locator('text=Copy this into your AI:').waitFor();
    const body = await page.locator('body').innerText();
    expect(body).toContain(`MCP server at http://localhost:${MCP_PORT}/mcp`);
    expect(body).not.toContain('Needs your attention');
    expect(await page.getByTestId('core-cols').count()).toBe(0);
  });

  it('the form: Sign stays disabled and says why until a duration is chosen', async () => {
    await page.locator('button:has-text("Give your AI its first mandate")').click();
    const give = page.locator('a:has-text("Give the first mandate")');
    await give.waitFor({ timeout: 5_000 });
    await give.click();
    await page.waitForURL(/\/mandates/, { timeout: 15_000 });
    await page.waitForURL(/\/mandates\/new\/intent/, { timeout: 15_000 });
    // Scope & Limits of the Delegation mandate: one area, one mode, read access.
    await page.getByText('email', { exact: true }).first().click();
    await page.getByText('review', { exact: true }).first().click();
    await page.locator('select').first().selectOption('unlimited');
    await toSignStep();

    await page.locator('input[placeholder*="e.g."]').fill('Setup');
    expect(await chosenDuration()).toBe('');
    await page.getByTestId('duration-needed').waitFor({ timeout: 10_000 });
    expect(await page.getByTestId('duration-needed').innerText()).toBe('Choose how long this mandate should last.');
    expect(await signButton().isDisabled()).toBe(true);

    await page.locator('button', { hasText: /^30 days$/ }).click();
    expect(await chosenDuration()).toBe('30 days');
    expect(await page.getByTestId('duration-needed').count()).toBe(0);
    expect(await signButton().isDisabled()).toBe(false);

    // Without a title Sign is disabled again, whatever the duration.
    await page.locator('input[placeholder*="e.g."]').fill('');
    expect(await signButton().isDisabled()).toBe(true);
  }, 120_000);

  it('the AI\'s proposal: Edit before signing arrives with its duration pre-selected', async () => {
    await signDelegation();
    await new Promise((r) => setTimeout(r, 1_500));
    const agent = new Client({ name: 'E2E Agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
    const r = await agent.callTool({
      name: 'setup__create_mandate',
      arguments: {
        profile: 'email', mode: 'review', duration_hours: 168, title: 'Customer replies',
        intent: 'Answer customer emails the same day.',
        limits: { read_access: 'unlimited', recipient_max: 1, send_daily_max: 5, setup_daily_max: 0 },
        scope: { allowed_recipients: 'customer@example.com' },
      },
    });
    await agent.close();
    expect(r.isError, textOf(r)).not.toBe(true);

    await go('/approvals', /\/approvals/);
    await openFirstApprovalInPanel(page);
    const edit = page.getByTestId('edit-before-signing').first();
    await edit.waitFor({ timeout: 20_000 });
    await edit.click();
    await page.waitForURL(/\/mandates\/new\//, { timeout: 15_000 });
    await toSignStep();
    expect(await chosenDuration()).toBe('7 days');
    expect(await page.getByTestId('duration-needed').count()).toBe(0);
    if (!(await page.locator('input[placeholder*="e.g."]').inputValue()).trim()) await page.locator('input[placeholder*="e.g."]').fill('Customer replies');
    expect(await signButton().isDisabled()).toBe(false);
  }, 120_000);

  it('a mandate being copied: its own duration is pre-selected', async () => {
    await go('/mandates', /\/mandates/);
    // Open the Setup mandate signed above; Copy is in its open card.
    const head = page.getByTestId('mandate-card').locator('button.ob-head').first();
    await head.waitFor({ timeout: 20_000 });
    if ((await head.getAttribute('aria-expanded')) !== 'true') await head.click();
    const copy = page.locator('button.ob-btn', { hasText: /^Copy$/ }).first();
    await copy.waitFor({ timeout: 20_000 });
    await copy.click();
    await page.waitForURL(/\/mandates\/new\//, { timeout: 15_000 });
    await toSignStep();
    // The Setup mandate above was signed for one day (the Authority Server's default when none is sent).
    expect(await chosenDuration()).toBe('24 hours');
    expect(await page.getByTestId('duration-needed').count()).toBe(0);
  }, 120_000);
});
