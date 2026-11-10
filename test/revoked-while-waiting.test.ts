/**
 * Revoked while a proposal waits — Gateway + Authority Server, real servers.
 *
 * A proposal rides on a mandate. If the mandate is revoked while the proposal
 * waits, it can never run. The person must not be asked to approve it, and the
 * AI must not keep saying PENDING:
 *   - the AI asks about the proposal: "the mandate was revoked after this
 *     proposal; a new one is needed; do not ask the person to approve again";
 *   - the Authority Server closes the proposal as refused with the reason as
 *     soon as a commit or approve is refused for that reason;
 *   - afterwards list-authorizations can say the last mandate was revoked.
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

const PROFILE_ID = PROFILE_V07.customers;
const PROFILES_DIR = join(import.meta.dirname, '..', '..', 'hap-profiles');
const BOUNDS_KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const CONTEXT_KEY_ORDER = ['contact_type'];
const SP_PORT = 17970;
const SP_URL = `http://localhost:${SP_PORT}`;

const CRM_INTEGRATION = {
  id: 'crm', name: 'CRM', command: 'npx', args: ['-y', '@humanagencyp/crm-mcp@1.4.1'], envKeys: {}, profile: 'customers', enabled: true,
  toolGating: {
    default: { executionMapping: {}, staticExecution: { contact_type: 'customer' } },
    overrides: {
      create_contact: { executionMapping: { type: 'contact_type' }, staticExecution: { action_type: 'write' } },
      find_contacts: { category: 'read' }, get_timeline: { category: 'read' }, get_pipeline: { category: 'read' }, list_tasks: { category: 'read' }, export_crm: { category: 'read' },
    },
  },
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const textOf = (r: unknown): string => ((r as { content?: Array<{ text?: string }> }).content ?? []).map((c) => c.text ?? '').join('\n');
const WANT = /can no longer be approved: the mandate was revoked after this proposal, so it will never run\. Nothing ran\. A new mandate is needed; tell the person so, and do not ask them to approve this proposal again\./;

const pm = new ProcessManager();
const gwPm = new ProcessManager();
const sp = new SPClient(SP_URL);
let client: Client;
let apiKey = '';
let authId = '';
let proposalId = '';

async function asProposal(id: string): Promise<Record<string, any>> {
  const res = await fetch(`${SP_URL}/api/proposals/${id}`, { headers: { 'X-API-Key': apiKey } });
  expect(res.ok).toBe(true);
  return ((await res.json()) as { proposal: Record<string, any> }).proposal;
}
const ask = async () => textOf(await client.callTool({ name: 'check-pending-commitments', arguments: { proposal_id: proposalId } }));

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);
  const user = await sp.register('Revoked Waiting', `revoked-waiting-${Date.now()}@test.local`);
  apiKey = user.apiKey;
  const groupId = await sp.getPersonalGroupId(apiKey);
  const gwPort = 17971;
  await gwPm.startGateway({ simulation: true, port: gwPort, cpPort: 17972, spUrl: SP_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
  const gw = new GatewayClient(`http://localhost:${gwPort}`);
  await gw.configure({ sessionCookie: 'revoked-waiting', apiKey });

  const bounds = { profile: PROFILE_ID, read_access: 'unlimited', export_access: 'none', write_daily_max: 10, delete_daily_max: 5, setup_daily_max: 0 };
  const boundsHash = computeBoundsHash(bounds, BOUNDS_KEY_ORDER);
  const context = { contact_type: 'customer' };
  const contextHash = computeScopeHash(context, CONTEXT_KEY_ORDER);
  const gateContent = { intent: 'Review new customers.' };
  const att = await sp.submitMandate(apiKey, {
    profile_id: PROFILE_ID, profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR), group_id: groupId,
    bounds, bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: user.user.did, commitment_mode: 'review',
    gate_content_hashes: hashGateContent(gateContent),
    execution_context_hash: hashExecutionContext({ contact_type: 'customer', write_count_daily: 10 }),
  });
  authId = att.authorization_id;
  await gw.pushGateContent({ authorizationId: authId, boundsHash, contextHash, context }, PROFILE_ID, gateContent);
  await sleep(500);
  expect((await gw.addIntegration(CRM_INTEGRATION)).ok).toBe(true);
  await gw.waitForIntegration('crm');
  await sleep(2_000);
  client = new Client({ name: 'revoked-waiting', version: '0.1.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`http://localhost:${gwPort}/sse`)));

  const r = textOf(await client.callTool({ name: 'crm__create_contact', arguments: { name: 'Waiting Wendy', type: 'customer' } }));
  expect(r).toMatch(/Awaiting commitment/i);
  proposalId = r.match(/Proposal ID: ([a-f0-9]+)/)![1];
}, 300_000);

afterAll(async () => {
  try { await client?.close(); } catch { /* ignore */ }
  await gwPm.killAll();
  await pm.killAll();
}, 60_000);

describe('revoked while a proposal waits', () => {
  it('before revocation the AI hears PENDING, and the proposal carries no end', async () => {
    expect(await ask()).toMatch(/is PENDING/);
    expect((await asProposal(proposalId)).mandateEnded).toBeUndefined();
  });

  it('after revocation the AI is told it can never be approved, not PENDING', async () => {
    await sp.revokeAuthorization(apiKey, authId);
    const p = await asProposal(proposalId);
    expect(p.status).toBe('pending');
    expect(p.mandateEnded).toBe('revoked');
    const text = await ask();
    expect(text).toMatch(WANT);
    expect(text).not.toMatch(/PENDING/);
  });

  it('list-authorizations says the last mandate was revoked', async () => {
    // Ask with the area name; the check above dropped the dead mandate from the gateway's cache.
    const text = textOf(await client.callTool({ name: 'list-authorizations', arguments: { domain: 'customers' } }));
    expect(text).toContain('The last one was revoked.');
    expect(text).not.toContain('(revoked or expired)');
  });

  it('a commit is refused and the Authority Server closes the proposal with the reason', async () => {
    const res = await fetch(`${SP_URL}/api/proposals/${proposalId}/resolve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify({ action: 'commit', domain: 'owner' }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { errors: Array<{ code: string }> };
    expect(body.errors[0].code).toBe('MANDATE_REVOKED');

    const p = await asProposal(proposalId);
    expect(p.status).toBe('refused');
    expect(p.refusal.code).toBe('MANDATE_REVOKED');
    expect(p.mandateEnded).toBeUndefined();
  });

  it('the AI still gets the same words: not "was approved"', async () => {
    const text = await ask();
    expect(text).toMatch(WANT);
    expect(text).not.toMatch(/was approved, but/);
  });
});
