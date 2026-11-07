/**
 * Gateway PR #188 — the ticket card shows the sealed email body.
 *
 * Before the fix an email ticket listed only the recipients under "Sealed in
 * the ticket"; the body, which is part of what the ticket commits to, was
 * missing. Real stack, no mocks: Authority Server + gateway + the practice
 * mailbox connector (mail, simulation gateway), over the browser.
 *
 * An AI sends one email under an automatic email mandate (so a ticket is
 * issued pre-flight and the send really happens). The owner then opens that
 * ticket on Tickets: "Sealed in the ticket" must show the recipient AND the
 * body text, and "Matches the fingerprint in the signed ticket".
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { Page } from '@playwright/test';
import {
  test, expect,
  SP_URL, GW_MCP_URL, INTERNAL_SECRET,
  registerOnSP, signInToGateway, handleOnboarding, activateIntegration,
  spApiAttest, latestProfileId,
} from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = join(__dirname, '..', 'test-results', 'ticket-card-email-body');
mkdirSync(SCREENSHOT_DIR, { recursive: true });

const EMAIL_PROFILE = latestProfileId('email');
const EMAIL_KEY_ORDER = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];

const TO = 'kunde@ticket-body.example';
const SUBJECT = 'Ihre Anfrage zum Ersatzteil';
const BODY = 'TICKET-BODY-MARKER Guten Tag, das Ersatzteil ist ab Montag lieferbar. Freundliche Grüße';

test.describe.serial('Ticket card shows the sealed email body (real stack, gateway #188)', () => {
  let page: Page;
  test.beforeAll(async ({ browser }) => { page = await browser.newPage(); });
  test.afterAll(async () => { await page?.close(); });

  test('setup: the AI sends one email under an automatic email mandate', async ({ request }) => {
    test.setTimeout(180_000);
    const apiKey = await registerOnSP(page, 'Ticket Email Body');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    expect(sess.ok()).toBe(true);
    const did = (await sess.json()).user.did as string;

    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'Email (simulation)');

    const bounds = { profile: EMAIL_PROFILE, read_access: 'unlimited', recipient_max: 1, send_daily_max: 10, read_max_age_days: 30, setup_daily_max: 0 };
    const intent = 'Ticket email body e2e: send the customer a reply.';
    const boundsHash = computeBoundsHash(bounds, EMAIL_KEY_ORDER);
    const scopeHash = computeScopeHash({}, []);
    const att = await spApiAttest(request, apiKey, {
      profile_id: EMAIL_PROFILE, domain: 'owner', did,
      bounds, bounds_hash: boundsHash, scope_hash: scopeHash,
      gate_content_hashes: hashGateContent({ intent }),
      execution_context_hash: 'sha256:' + 'd'.repeat(64),
      commitment_mode: 'automatic',
    });
    expect(att.status).toBe('active');
    const push = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
      body: JSON.stringify({
        authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: {},
        path: EMAIL_PROFILE, gateContent: { intent },
      }),
    });
    expect(push.ok).toBe(true);

    const client = new Client({ name: 'ticket-body-e2e-agent', version: '1.0.0' }, { capabilities: {} });
    await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
    try {
      const res = await client.callTool({ name: 'mail__send_message', arguments: { to: [TO], subject: SUBJECT, body: BODY } });
      const out = ((res.content as Array<{ text?: string }>) ?? []).map(c => c.text ?? '').join('\n');
      expect(res.isError, out).toBeFalsy();
    } finally { await client.close(); }
  });

  test('the ticket shows To AND Body under "Sealed in the ticket", and matches the fingerprint', async () => {
    test.setTimeout(90_000);
    await page.click('.sidebar-item:has-text("Tickets")');
    await page.waitForURL('**/tickets**');
    const card = page.locator('.ticket-obj-card', { hasText: TO });
    await expect(card).toHaveCount(1, { timeout: 30_000 });
    // The only ticket opens by itself; open it only if it is still a closed row.
    const head = card.locator('.ticket-obj-head');
    if ((await head.getAttribute('aria-expanded')) !== 'true') await head.click();
    await expect(head).toHaveAttribute('aria-expanded', 'true');

    const sent = card.getByTestId('ticket-what-was-done');
    await expect(sent).toHaveAttribute('data-bound', 'sealed', { timeout: 30_000 });
    await expect(sent).toContainText(/sealed in the ticket/i);
    await expect(sent).toContainText(TO);
    await expect(sent).toContainText('TICKET-BODY-MARKER');
    await expect(sent).toContainText('das Ersatzteil ist ab Montag lieferbar');
    await expect(sent).toContainText('Matches the fingerprint in the signed ticket');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'ticket-email-body.png'), fullPage: true });
  });
});
