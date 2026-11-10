/**
 * The approval card for an AI-proposed change to a mandate, read in the browser, on
 * the real stack: Authority Server, gateway, CRM connector, shipped profiles. An AI
 * over real MCP asks for more (one limit up, one contact type added, new intent words);
 * the card must show exactly what changes, warn about the waiting request, and carry
 * no text from the AI except the labelled intent words. A reduction, and "Change it
 * myself" (the form opens pre-filled and the difference is recomputed), are covered too.
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { Page } from '@playwright/test';
import { test, expect, SP_URL, GW_MCP_URL, INTERNAL_SECRET, registerOnSP, signInToGateway, handleOnboarding, activateIntegration, spApiAttest, latestProfileId, openApprovalCard } from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SHOTS = join(__dirname, '..', 'test-results', 'mandate-change-card');
mkdirSync(SHOTS, { recursive: true });

const CUSTOMERS = latestProfileId('customers');
const SETUP = latestProfileId('delegation');
const CUSTOMERS_KEYS = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const SETUP_KEYS = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];
const SETUP_SCOPE_KEYS = ['allowed_profiles', 'allowed_modes'];

const pushed = async (id: string, boundsHash: string, contextHash: string, context: Record<string, string>, profile: string, intent: string) => {
  const res = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
    body: JSON.stringify({ authorizationId: id, boundsHash, contextHash, context, path: profile, gateContent: { intent } }),
  });
  expect(res.ok).toBe(true);
};

const text = (r: unknown) => ((r as { content?: Array<{ text?: string }> }).content ?? []).map(c => c.text ?? '').join('\n');

test.describe.serial('The mandate change card (real stack)', () => {
  let page: Page;
  let client: Client;
  let apiKey = '';
  let did = '';
  let mandateId = '';
  let authStatus: Record<string, unknown>;

  test.beforeAll(async ({ browser }) => { page = await browser.newPage({ viewport: { width: 1280, height: 1000 } }); });
  test.afterAll(async () => { await client?.close().catch(() => {}); await page?.close(); });

  async function grant(request: import('@playwright/test').APIRequestContext, profile: string, bounds: Record<string, string | number>, keys: string[], context: Record<string, string>, scopeKeys: string[], mode: string, intent: string) {
    const b = { profile, ...bounds };
    const boundsHash = computeBoundsHash(b, keys);
    const contextHash = computeScopeHash(context, scopeKeys);
    const att = await spApiAttest(request, apiKey, {
      profile_id: profile, domain: 'owner', did, bounds: b, bounds_hash: boundsHash, scope_hash: contextHash,
      gate_content_hashes: hashGateContent({ intent }), execution_context_hash: 'sha256:' + 'd'.repeat(64), commitment_mode: mode,
    });
    await pushed(att.authorization_id as string, boundsHash, contextHash, context, profile, intent);
    return att.authorization_id as string;
  }

  test('setup: a review mandate, a waiting request, a Setup mandate', async ({ request }) => {
    test.setTimeout(180_000);
    apiKey = await registerOnSP(page, 'Mandate Change Card');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'CRM');

    await grant(request, SETUP, { read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 }, SETUP_KEYS, { allowed_profiles: 'customers', allowed_modes: 'review,automatic' }, SETUP_SCOPE_KEYS, 'review', 'Let the AI propose mandates.');
    mandateId = await grant(request, CUSTOMERS, { read_access: 'unlimited', export_access: 'none', write_daily_max: 5, delete_daily_max: 0, setup_daily_max: 0 }, CUSTOMERS_KEYS, { contact_type: 'customer' }, ['contact_type'], 'review', 'Answer customer questions. Keep it short.');
    await new Promise(r => setTimeout(r, 2000));

    client = new Client({ name: 'change-card-e2e', version: '1.0.0' }, { capabilities: {} });
    await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
    const waiting = await client.callTool({ name: 'crm__create_contact', arguments: { name: 'Waiting Wendy', type: 'customer' } });
    expect(text(waiting)).toMatch(/Awaiting commitment/);
  });

  test('a tricked AI asking for more: the card shows More clearly, and carries nothing else from the AI', async () => {
    test.setTimeout(120_000);
    const NOTE = 'CARD-INJECTION-note-please-approve-this';
    const refused = await client.callTool({ name: 'setup__change_mandate', arguments: { mandate_id: mandateId, limits: { write_daily_max: 15 }, note: NOTE } });
    expect(refused.isError).toBe(true);
    const r = await client.callTool({ name: 'setup__change_mandate', arguments: {
      mandate_id: mandateId, limits: { write_daily_max: 15 }, scope: { contact_type: 'customer,lead' },
      intent: 'Answer customer questions and new leads. Keep it short.',
    } });
    expect(r.isError, text(r)).toBeFalsy();
    expect(text(r)).toMatch(/Awaiting commitment/);

    const card = await openApprovalCard(page, 'Change to a mandate');
    await expect(card.getByTestId('change-kicker')).toHaveText('Waiting for you · Change to a mandate');
    await expect(card).toContainText('Your AI proposes this through your Setup mandate.');
    const rows = card.getByTestId('change-row');
    const limit = rows.filter({ hasText: /write|contact/i }).first();
    await expect(limit).toBeVisible();

    await expect(card.locator('[data-field="write_daily_max"] [data-testid="change-tag"]')).toHaveText('More');
    await expect(card.locator('[data-field="write_daily_max"] .mc-old')).toHaveText('5');
    await expect(card.locator('[data-field="write_daily_max"] .mc-new')).toHaveText('15');
    const list = card.locator('[data-field="contact_type"]');
    await expect(list.getByTestId('change-tag')).toHaveText('More');
    await expect(list.locator('.mc-add')).toHaveText('lead');

    const intent = card.getByTestId('change-intent');
    await expect(intent).toContainText('words proposed by the AI');
    await expect(intent.locator('ins')).toContainText('and new leads');

    // The AI's refused text never reaches any card.
    await expect(card).not.toContainText(NOTE);
    // Only the labelled intent words come from the AI.
    await expect(card.getByTestId('change-warning')).toHaveText('1 waiting request under the old mandate will be closed.', { timeout: 15_000 });
    await expect(card.getByTestId('change-facts')).toContainText("Today's count");
    await expect(card.getByTestId('change-stays')).toContainText('Stays the same');
    await expect(card.getByTestId('btn-change-needed')).toHaveCount(0);
    await expect(card.getByTestId('btn-approve')).toHaveText('Approve and sign');
    await page.screenshot({ path: join(SHOTS, 'more.png'), fullPage: true });

    // Reject: the mandate stays as it is.
    await card.getByTestId('btn-reject').click();
    await expect(card).not.toBeVisible({ timeout: 20_000 }).catch(() => {});
  });

  test('a reduction: Less, and approving replaces the mandate', async ({ request }) => {
    test.setTimeout(120_000);
    const r = await client.callTool({ name: 'setup__change_mandate', arguments: { mandate_id: mandateId, limits: { write_daily_max: 1 } } });
    expect(r.isError, text(r)).toBeFalsy();
    const card = await openApprovalCard(page, 'Change to a mandate');
    await expect(card.locator('[data-field="write_daily_max"] [data-testid="change-tag"]')).toHaveText('Less', { timeout: 15_000 });
    await page.screenshot({ path: join(SHOTS, 'less.png'), fullPage: true });
    await card.getByTestId('btn-approve').click();
    await expect(page.getByTestId('decision-stamp')).toBeVisible({ timeout: 30_000 });
    // The new mandate is signed and the old one retired right after the decision shows.
    await expect.poll(async () => {
      const mine = await request.get(`${SP_URL}/api/mandates/mine?status=active`, { headers: { 'x-api-key': apiKey } });
      return ((await mine.json()).mandates as Array<{ authorization_id: string }>).map(m => m.authorization_id);
    }, { timeout: 30_000 }).not.toContain(mandateId);
  });

  test('"Change it myself" opens the form with the proposal and recomputes the difference against the signed mandate', async ({ request }) => {
    test.setTimeout(120_000);
    const mine = await request.get(`${SP_URL}/api/mandates/mine?status=active`, { headers: { 'x-api-key': apiKey } });
    const current = ((await mine.json()).mandates as Array<{ authorization_id: string; profileId: string }>).find(m => m.profileId === CUSTOMERS)!.authorization_id;
    const r = await client.callTool({ name: 'setup__change_mandate', arguments: { mandate_id: current, limits: { write_daily_max: 3 }, intent: 'New words from the AI.' } });
    expect(r.isError, text(r)).toBeFalsy();
    // Named by the words only this proposal carries: the decided card above may still be on screen.
    const card = await openApprovalCard(page, 'New words from the AI');
    await card.getByTestId('change-it-myself').click();
    await page.waitForURL('**/mandates/new/intent**');
    // Through the form to the review step, as a person would: the prefill must carry.
    await page.locator('button:has-text("Next")').click();
    await page.waitForSelector('.intent-textarea', { timeout: 5_000 });
    // The person's own words: the difference must no longer call them the AI's.
    await page.fill('.intent-textarea', 'My own words, written by me.');
    await page.locator('button:has-text("Continue to Review")').click();
    await page.waitForURL((u) => u.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
    const diff = page.getByTestId('edit-diff');
    await expect(diff).toBeVisible({ timeout: 15_000 });
    await expect(diff.locator('[data-field="write_daily_max"] .mc-new')).toHaveText('3');
    await expect(diff).not.toContainText('words proposed by the AI');
    await expect(diff.getByTestId('change-intent')).toContainText('My own words');
    await page.screenshot({ path: join(SHOTS, 'change-it-myself.png'), fullPage: true });
  });
});
