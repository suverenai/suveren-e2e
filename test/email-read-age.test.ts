/**
 * Email read-age enforcement — Gateway E2E, on the `mail` connector's practice mailbox
 * (simulation gateway, the SHIPPED mail.json manifest).
 *
 * Asserts that the read-age window (here the signed bound `read_max_age_days`) is ENFORCED
 * on email reads, list view and single message alike:
 *   - list_messages: the gateway sets `received_after` (the manifest's ageFloorArg) to now minus
 *     the window, so a message older than the window is NOT LISTED. An explicit, older value from
 *     the AI is replaced, junk is replaced, a tighter value is kept (it only ever narrows);
 *   - get_message: a message older than the window is BLOCKED, content withheld.
 *
 * Before gateway 0.43.0 the same was proven against a real Gmail account (an injected
 * `newer_than:{days}d` query ceiling, hostile-query cases). The mail connector has no query
 * argument, so those cases do not exist any more: the floor is an argument the gateway overwrites,
 * never a fragment it combines with the AI's own text. Gmail as the data source (same connector,
 * live mode) is proven against a real test account in the Rehearsal (scenarios A3, A14, A16, A17)
 * and by email-mcp's own tests (received_after for both adapters, test/gmail-live.test.ts).
 *
 * `load_simulation` ignores a package's own `received_at` (every message lands within the hour
 * before the load), so an old message is made by backdating it in the connector's own SQLite file
 * (`${dataDir}/email.db`) — the real connector, the real schema.
 *
 * Run: npx vitest run test/email-read-age.test.ts
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';
import { addMailConnector, callText, practicePackage, startMailGateway } from '../src/helpers/mail-connector.js';

const SP_PORT = 17270;
const GW_PORT = 17271;
const SP_URL = `http://localhost:${SP_PORT}`;
const GW_URL = `http://localhost:${GW_PORT}`;

const PROFILE_ID = PROFILE_V07.email;
const ROOT = join(import.meta.dirname, '..', '..');
const PROFILES_DIR = join(ROOT, 'hap-profiles');

const DAY = 86_400_000;
const READ_MAX_AGE_DAYS = 30;
// v0.7: read_daily_max is gone (replaced by read_access); read_access and setup_daily_max are required.
const BOUNDS_KEY_ORDER = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const BOUNDS = {
  profile: PROFILE_ID,
  read_access: 'unlimited',
  recipient_max: 5,
  send_daily_max: 10,
  read_max_age_days: READ_MAX_AGE_DAYS,
  setup_daily_max: 5, // load_simulation is a setup action: it needs a setup allowance
};
// Unscoped (no recipient scope): these tests are about AGE, not coverage.
const CONTEXT: Record<string, string> = {};

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);
const gw = new GatewayClient(GW_URL);
let mcpClient: Client;
const ids: Record<string, string> = {};

function setReceivedAt(messageId: string, iso: string): void {
  execFileSync('sqlite3', [join(pm.getDataDir(), 'email.db'), `UPDATE messages SET received_at = '${iso}' WHERE id = '${messageId}';`]);
}

async function listIds(args: Record<string, unknown> = {}): Promise<string[]> {
  const { text, isError } = await callText(mcpClient, 'mail__list_messages', args);
  expect(isError, text).toBe(false);
  return (JSON.parse(text) as Array<{ id: string }>).map((m) => m.id);
}

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);

  const user = await sp.register('Email Read-Age E2E', `email-readage-${Date.now()}@test.local`);
  const apiKey = user.apiKey;
  const groupId = await sp.getPersonalGroupId(apiKey);

  await startMailGateway(pm, { port: GW_PORT, spUrl: SP_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
  await gw.configure({ sessionCookie: 'email-readage-e2e', apiKey });

  const boundsHash = computeBoundsHash(BOUNDS, BOUNDS_KEY_ORDER);
  const contextHash = computeScopeHash(CONTEXT, []);
  const gateContent = { intent: 'Read recent mail within a 30-day window for E2E.' };
  const att = await sp.submitMandate(apiKey, {
    profile_id: PROFILE_ID,
    profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
    group_id: groupId,
    bounds: BOUNDS,
    bounds_hash: boundsHash,
    scope_hash: contextHash,
    domain: 'communications',
    did: user.user.did,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent(gateContent),
    execution_context_hash: hashExecutionContext({ recipient_count: 1, ...CONTEXT }),
  });
  await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: CONTEXT }, PROFILE_ID, gateContent);

  // No local window: the signed bound (30 days) is what governs.
  await addMailConnector(gw);

  mcpClient = new Client({ name: 'hap-email-readage-e2e', version: '0.1.0' }, { capabilities: {} });
  await mcpClient.connect(new SSEClientTransport(new URL(`${GW_URL}/sse`)));

  const load = await mcpClient.callTool({
    name: 'mail__load_simulation',
    arguments: { package: practicePackage('Read Age Co', [
      { id: 'recent', subject: 'Recent question' },
      { id: 'old', subject: 'Old question' },
    ]) },
  });
  expect(load.isError, JSON.stringify(load.content)).not.toBe(true);
  for (const m of JSON.parse((await callText(mcpClient, 'mail__list_messages', {})).text) as Array<{ id: string; subject: string }>) {
    ids[m.subject === 'Recent question' ? 'recent' : 'old'] = m.id;
  }
  expect(ids.recent && ids.old).toBeTruthy();
  setReceivedAt(ids.recent, new Date(Date.now() - 2 * DAY).toISOString());
  setReceivedAt(ids.old, new Date(Date.now() - 40 * DAY).toISOString());
}, 240_000);

afterAll(async () => {
  if (mcpClient) { try { await mcpClient.close(); } catch { /* ignore */ } }
  await pm.killAll();
}, 30_000);

describe('Email read-age enforcement — list_messages', () => {
  it('a message older than the window is not listed; one inside it is', async () => {
    expect(await listIds()).toEqual([ids.recent]);
  });

  it('an explicit received_after far older than the window is replaced — the old message still does not come back', async () => {
    expect(await listIds({ received_after: '2015-01-01T00:00:00Z' })).toEqual([ids.recent]);
  });

  it('an unparseable received_after is replaced, not forwarded', async () => {
    expect(await listIds({ received_after: 'whenever you like' })).toEqual([ids.recent]);
  });

  it('a tighter received_after than the window is kept — it only ever narrows', async () => {
    // The recent message is 2 days old; asking for the last day leaves nothing.
    expect(await listIds({ received_after: new Date(Date.now() - DAY).toISOString() })).toEqual([]);
    expect(await listIds({ received_after: new Date(Date.now() - 3 * DAY).toISOString() })).toEqual([ids.recent]);
  });

  it('the sent folder is bounded the same way', async () => {
    // Nothing was sent: an empty list, not an error — the floor is applied to every folder.
    const { text, isError } = await callText(mcpClient, 'mail__list_messages', { folder: 'sent' });
    expect(isError, text).toBe(false);
    expect(JSON.parse(text)).toEqual([]);
  });
});

describe('Email read-age enforcement — get_message', () => {
  it('a message inside the window is readable', async () => {
    const { text, isError } = await callText(mcpClient, 'mail__get_message', { id: ids.recent });
    expect(isError, text).toBe(false);
    expect(JSON.parse(text).id).toBe(ids.recent);
  });

  it('a message older than the window is blocked, content withheld', async () => {
    const { text, isError } = await callText(mcpClient, 'mail__get_message', { id: ids.old });
    expect(isError).toBe(true);
    expect(text.toLowerCase()).toContain('older than');
    expect(text).not.toMatch(/"body"|"snippet"/);
  });
});
