/**
 * Verification footer — happy-path E2E (gateway + the `mail` connector's practice mailbox).
 *
 * Proves the full Level-1 loop end to end:
 *   1. A gated email send through the gateway gets a "Verified by Suveren" footer
 *      injected into its body (Category-A profile).
 *   2. The footer carries a /t/<ticketId> link.
 *   3. That ticket verifies on the AS: GET /api/as/public-receipt/:id →
 *      signatureValid:true, redacted.
 *
 * Runs on a simulation gateway with the connector's test mailbox, so it needs no account and runs in CI:
 * the footer is added by the gateway and does not depend on where the mail goes. The message is read back
 * from the connector's Sent folder. The same on a real Gmail account — thread, subject, body and footer as
 * Gmail stored them — is the Rehearsal's scenario A17.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';
import { addMailConnector, callText, startMailGateway } from '../src/helpers/mail-connector.js';

const SP_PORT = 16110;
const GW_PORT = 16040;
const SP_URL = `http://localhost:${SP_PORT}`;
const GW_URL = `http://localhost:${GW_PORT}`;

const PROFILE_ID = PROFILE_V07.email;
const EXEC_PATH = 'email-send';
const ROOT = join(import.meta.dirname, '..', '..');
const PROFILES_DIR = join(ROOT, 'hap-profiles');

// Email profile → verb "Sent"; ASCII "--" separator (mojibake-immune);
// "Ticket:" label (gateway 0.36.0, v0.7 vocabulary) — the ticket is the precondition proof, not a "Verify" CTA.
const FOOTER_MARKER = '-- Sent by an AI agent via Suveren. Ticket:';
const RECEIPT_LINK = /https?:\/\/[^\s"]+\/t\/([0-9a-fA-F-]{36})/;

const TEST_RECIPIENT = 'customer@example.com';
const TEST_DOMAIN = 'example.com';
// read_max_age_days: the readback of the sent message needs a read window (fail-closed without one).
const BOUNDS = { profile: PROFILE_ID, read_access: 'unlimited', recipient_max: 5, send_daily_max: 10, read_max_age_days: 30, setup_daily_max: 0 };
const BOUNDS_KEY_ORDER = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const CONTEXT = { allowed_recipients: TEST_RECIPIENT, allowed_domains: TEST_DOMAIN };
const GATE_CONTENT = { intent: 'E2E: verification-footer test — bounded automated email sending.' };

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);
const gw = new GatewayClient(GW_URL);
let userApiKey = '';
let userDid = '';
let personalGroupId = '';
let mcpClient: Client | null = null;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function submitEmailAttestation(): Promise<string> {
  const boundsHash = computeBoundsHash(BOUNDS, BOUNDS_KEY_ORDER);
  const contextHash = computeScopeHash(CONTEXT, ['allowed_recipients', 'allowed_domains']);
  const result = await sp.submitMandate(userApiKey, {
    profile_id: PROFILE_ID,
    profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
    group_id: personalGroupId,
    bounds: BOUNDS,
    bounds_hash: boundsHash,
    scope_hash: contextHash,
    domain: 'communications',
    did: userDid,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent(GATE_CONTENT),
    execution_context_hash: hashExecutionContext({ recipient_count: 1, allowed_recipients: TEST_RECIPIENT, allowed_domains: TEST_DOMAIN }),
  });
  await gw.pushGateContent({ authorizationId: result.authorization_id, boundsHash: result.bounds_hash, contextHash, context: CONTEXT }, EXEC_PATH, GATE_CONTENT);
  return result.authorization_id;
}

/** The body of the just-sent message, read back from the connector's Sent folder by subject. */
async function findSentBody(subject: string): Promise<string> {
  const { text: listText } = await callText(mcpClient!, 'mail__list_messages', { folder: 'sent' });
  const id = (JSON.parse(listText) as Array<{ id: string; subject: string }>).find((m) => m.subject === subject)?.id;
  if (!id) return '';
  const { text } = await callText(mcpClient!, 'mail__get_message', { id });
  return (JSON.parse(text) as { body: string }).body;
}

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);
  const user = await sp.register('Footer E2E', `footer-e2e-${Date.now()}@test.local`);
  userApiKey = user.apiKey;
  userDid = user.user.did;
  personalGroupId = await sp.getPersonalGroupId(userApiKey);
  await startMailGateway(pm, { port: GW_PORT, spUrl: SP_URL, spApiKey: userApiKey, profilesDir: PROFILES_DIR });
  await gw.configure({ sessionCookie: 'footer-e2e-test', apiKey: userApiKey });
  await addMailConnector(gw);
  await submitEmailAttestation();
  const transport = new SSEClientTransport(new URL(`${GW_URL}/sse`));
  mcpClient = new Client({ name: 'hap-footer-e2e', version: '0.1.0' }, { capabilities: {} });
  await mcpClient.connect(transport);
  await sleep(1_000);
}, 180_000);

afterAll(async () => {
  if (mcpClient) { try { await mcpClient.close(); } catch { /* ignore */ } }
  await pm.killAll();
}, 30_000);

describe('verification footer — happy path', () => {
  it('injects a verify link into the sent body, and that receipt verifies on the AS', async () => {
    const subject = `HAP Footer E2E — ${Date.now()}`;
    const send = await mcpClient!.callTool({
      name: 'mail__send_message',
      arguments: { to: [TEST_RECIPIENT], subject, body: 'Automated footer e2e — ignore.' },
    });
    expect(send.isError).toBeFalsy();

    const body = await findSentBody(subject);
    expect(body).toContain(FOOTER_MARKER);
    expect(body.startsWith('Automated footer e2e — ignore.')).toBe(true); // the AI's text first, the footer after it

    const m = body.match(RECEIPT_LINK);
    expect(m).not.toBeNull();
    const receiptId = m![1];

    const res = await fetch(`${SP_URL}/api/as/public-receipt/${receiptId}`);
    expect(res.status).toBe(200);
    const view = (await res.json()) as Record<string, unknown>;
    expect(view.signatureValid).toBe(true);
    expect(view.profileId).toBe(PROFILE_ID);
    // redaction holds end-to-end
    for (const f of ['userId', 'cumulativeState', 'limits', 'executionContext', 'signature']) {
      expect(view[f]).toBeUndefined();
    }
  }, 120_000);
});
