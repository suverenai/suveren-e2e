/**
 * Two things found on 2026-11-09, on the real stack (Authority Server + whole
 * gateway, no mocks), both in a TEAM.
 *
 * (a) Grantors, not approvers, decide who may give a mandate. A team whose
 *     profile config names the person as a GRANTOR and has NO approvers must
 *     let `setup__create_mandate` propose, and the mandate must be created after
 *     approval. The ceremony still read `approvers`, so it answered
 *     "<profile> is not enabled in <team>" (control-plane mandate-ceremony.ts).
 *
 * (b) A limit that fills up after the proposal. The facts of the refusal stay on
 *     the proposal record (`refusal.field` / `expected` / `actual`), so a card
 *     can say "3 of 2" without parsing English, and the mandate summary's
 *     `cumulative_usage` is the TEAM-wide count: what a colleague used counts.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { ControlPlaneClient, newSecret, startControlPlane, startMcpServer, textOf, PROFILES_DIR, type StackOptions } from '../src/helpers/gateway-stack.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

// 19980–19989 belong to this file.
const AS_PORT = 19980;
const AS_URL = `http://localhost:${AS_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const DELEGATION = `${P}/delegation@0.3`;
const SALES = `${P}/sales@0.4`;
const CUSTOMERS = PROFILE_V07.customers;
const available = existsSync(join(PROFILES_DIR, 'delegation', '0.3.profile.json'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
type Account = { apiKey: string; user: { id: string; did: string } };

async function as(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A team of three: Tom (admin), Bernd and Carla (members). */
async function makeTeam(label: string): Promise<{ tom: Account; bernd: Account; carla: Account; teamId: string }> {
  const stamp = `${label}-${Date.now()}`;
  const tom = await sp.register(`Tom ${label}`, `tom-${stamp}@test.local`);
  const bernd = await sp.register(`Bernd ${label}`, `bernd-${stamp}@test.local`);
  const carla = await sp.register(`Carla ${label}`, `carla-${stamp}@test.local`);
  await as('PUT', '/api/users/me/pubkey', tom.apiKey, { pubkey: randomBytes(32).toString('base64') });
  const team = await sp.createGroup(tom.apiKey, `Team ${label}`);
  const code = team.inviteCode ?? team.group.inviteCode;
  await sp.joinGroup(bernd.apiKey, code, tom.apiKey);
  await sp.joinGroup(carla.apiKey, code, tom.apiKey);
  return { tom, bernd, carla, teamId: team.group.id };
}

afterAll(async () => { await pm.killAll(); }, 30_000); // the one Authority Server, after both groups

// ── (a) grantors without approvers ────────────────────────────────────────────

describe.skipIf(!available)('(a) a team with grantors and no approvers: the AI can propose a mandate', () => {
  const stack: StackOptions = {
    dataDir: mkdtempSync(join(tmpdir(), 'hap-e2e-grantors-')), ports: { cp: 19981, mcp: 19982 }, secret: newSecret(), asUrl: AS_URL,
    extraEnv: { SUVEREN_SIMULATION: '1', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
  };
  const cp = new ControlPlaneClient(`http://localhost:${stack.ports.cp}`);
  const mcpInternal = new GatewayClient(`http://localhost:${stack.ports.mcp}`, stack.secret);
  let bernd: Account;
  let agent: Client;

  const pending = async () => (await as('GET', `/api/proposals?domain=${encodeURIComponent(bernd.user.id)}`, bernd.apiKey)).body.proposals ?? [];
  const mandates = async (): Promise<string[]> => {
    const res = await fetch(`http://localhost:${stack.ports.mcp}/internal/gate-content`, { headers: { 'X-Internal-Secret': stack.secret } });
    return (((await res.json()) as { entries?: Array<{ authorizationId: string }> }).entries ?? []).map((e) => e.authorizationId);
  };

  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    const t = await makeTeam('grantors');
    bernd = t.bernd;
    // Bernd signs his own delegation mandate (approvers, as before). "sales" is the case:
    // grantors name Bernd, NO approvers.
    await sp.setProfileConfig(t.tom.apiKey, t.teamId, DELEGATION, { approvers: [bernd.user.id] });
    const cfg = await as('PUT', `/api/groups/${t.teamId}/profile-config/${encodeURIComponent(SALES)}`, t.tom.apiKey, { approvers: [], grantors: [bernd.user.id] });
    expect(cfg.status, JSON.stringify(cfg.body)).toBeLessThan(300);

    await startControlPlane(pm, stack, 'cp-grantors');
    await startMcpServer(pm, stack, 'mcp-grantors');
    expect((await cp.login(bernd.apiKey)).status).toBe(200);

    const bounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 5 };
    const boundsHash = computeBoundsHash(bounds, ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max']);
    const contextHash = computeScopeHash({}, []);
    const gate = { intent: 'E2E: let the AI propose mandates for the test.' };
    const att = await sp.submitMandate(bernd.apiKey, {
      profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: t.teamId, bounds, bounds_hash: boundsHash, scope_hash: contextHash,
      domain: bernd.user.id, did: bernd.user.did, commitment_mode: 'review',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: 'delegation' }),
    });
    await mcpInternal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: {} }, DELEGATION, gate);
    await sleep(1_500);
    agent = new Client({ name: 'setup-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${stack.ports.mcp}/sse`)));
  }, 180_000);

  afterAll(async () => {
    await agent?.close().catch(() => {});
    await pm.stopProcess('mcp-grantors').catch(() => {});
    await pm.stopProcess('cp-grantors').catch(() => {});
    rmSync(stack.dataDir, { recursive: true, force: true });
  }, 60_000);

  it('setup__create_mandate proposes (not "not enabled"), and after approval the mandate exists', async () => {
    const SALES_LIMITS = {
      read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000,
      quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0,
    };
    const r = await agent.callTool({
      name: 'setup__create_mandate',
      arguments: { profile: 'sales', limits: SALES_LIMITS, scope: { currency: 'EUR' }, intent: 'Why — team quotes.', mode: 'review', duration_hours: 24, title: 'Grantor quotes (AI)' },
    });
    const text = textOf(r);
    expect(text).not.toMatch(/not enabled/);
    expect(r.isError, text).not.toBe(true);
    expect(text).toMatch(/Awaiting commitment/);

    const p = (await pending()).find((x: { status: string }) => x.status === 'pending');
    expect(p, 'no pending proposal').toBeTruthy();
    const before = new Set(await mandates());
    const res = await as('POST', `/api/proposals/${p.id}/resolve`, bernd.apiKey, { action: 'commit', domain: bernd.user.id });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    let created: string[] = [];
    for (let i = 0; i < 50 && !created.length; i++) {
      await sleep(500);
      created = (await mandates()).filter((id) => !before.has(id));
    }
    expect(created, 'no mandate appeared on the gateway after approval').toHaveLength(1);
    const summary = await sp.getAuthorizationSummary(bernd.apiKey, created[0]);
    expect(summary.body).toMatchObject({ created_by: bernd.user.id, profile_id: SALES, commitment_mode: 'review' });
  }, 90_000);
});

// ── (b) a refusal after approval, in a team where a colleague used part of the limit ──

const CRM_INTEGRATION = {
  id: 'crm', name: 'CRM', command: 'npx', args: ['-y', '@humanagencyp/crm-mcp@1.6.0'], envKeys: {}, profile: 'customers', enabled: true,
  toolGating: {
    default: { executionMapping: {}, staticExecution: { contact_type: 'customer' } },
    overrides: {
      create_contact: { executionMapping: { type: 'contact_type' }, staticExecution: { action_type: 'write' } },
      find_contacts: { category: 'read' },
    },
  },
};
const BOUNDS_KEYS = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];

describe.skipIf(!available)('(b) the limit fills up after the proposal: the facts stay on the proposal, the count is the team\'s', () => {
  const gwPm = new ProcessManager();
  let bernd: Account;
  let carla: Account;
  let teamId: string;
  let reviewId: string;
  let client: Client;
  let gw: GatewayClient;

  async function grant(who: Account, mode: 'automatic' | 'review', limit: number, contactType: string): Promise<string> {
    const bounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: limit, delete_daily_max: 5, setup_daily_max: 0 };
    const boundsHash = computeBoundsHash(bounds, BOUNDS_KEYS);
    const context = { contact_type: contactType };
    const contextHash = computeScopeHash(context, ['contact_type']);
    const gate = { intent: `E2E ${mode} ${contactType}` };
    const att = await sp.submitMandate(who.apiKey, {
      profile_id: CUSTOMERS, profile_hash: profileHashFor(CUSTOMERS, PROFILES_DIR), group_id: teamId, bounds, bounds_hash: boundsHash, scope_hash: contextHash,
      domain: who.user.id, did: who.user.did, commitment_mode: mode,
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ contact_type: contactType, write_count_daily: limit }),
    });
    if (who === bernd) await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context }, CUSTOMERS, gate);
    return att.authorization_id;
  }

  beforeAll(async () => {
    const t = await makeTeam('refusal');
    bernd = t.bernd; carla = t.carla; teamId = t.teamId;
    await sp.setProfileConfig(t.tom.apiKey, teamId, CUSTOMERS, { approvers: [bernd.user.id, carla.user.id] });
    await gwPm.startGateway({ simulation: true, port: 19983, cpPort: 19984, spUrl: AS_URL, spApiKey: bernd.apiKey, profilesDir: PROFILES_DIR });
    gw = new GatewayClient('http://localhost:19983');
    await gw.configure({ sessionCookie: 'grantors-b', apiKey: bernd.apiKey });
    // Bernd's review mandate (two a day) and Carla's automatic one on a scope the AI never calls with:
    // Carla is the colleague whose use counts against the team's day.
    reviewId = await grant(bernd, 'review', 2, 'customer');
    await sleep(500);
    expect((await gw.addIntegration(CRM_INTEGRATION)).ok).toBe(true);
    await gw.waitForIntegration('crm');
    await sleep(2_000);
    client = new Client({ name: 'grantors-b', version: '1.0.0' }, { capabilities: {} });
    await client.connect(new SSEClientTransport(new URL('http://localhost:19983/sse')));
  }, 240_000);

  afterAll(async () => {
    await client?.close().catch(() => {});
    await gwPm.killAll();
  }, 60_000);

  it('a colleague\'s tickets count, the refusal keeps field / expected / actual, and cumulative_usage is the team count', async () => {
    const carlaId = await grant(carla, 'automatic', 50, 'partner');

    const text = textOf(await client.callTool({ name: 'crm__create_contact', arguments: { name: 'Team Late', type: 'customer' } }));
    expect(text).toMatch(/Awaiting commitment/);
    const proposalId = text.match(/Proposal ID: ([a-f0-9]+)/)![1];

    // Carla uses the whole day of the team (2 of 2) after the proposal exists.
    for (let i = 0; i < 2; i++) {
      const t = await sp.postTicket(carla.apiKey, {
        authorizationId: carlaId, profileId: CUSTOMERS, action: 'crm__create_contact', actionType: 'write',
        executionContext: { contact_type: 'partner', action_type: 'write' },
      });
      expect(t.status).toBe(201);
    }

    // The team count is visible to Bernd on his own mandate, from Carla's tickets.
    const sum = await as('GET', `/api/authorizations/${reviewId}`, bernd.apiKey);
    expect(sum.body.cumulative_usage).toContainEqual({ field: 'write_daily_max', action_type: 'write', kind: 'cumulative_count', window: 'daily', used: 2, limit: 2 });

    // Bernd approves; the gateway asks for the ticket and the server refuses it.
    const r = await as('POST', `/api/proposals/${proposalId}/resolve`, bernd.apiKey, { action: 'commit', domain: bernd.user.id });
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    let proposal: Record<string, any> = {};
    for (let i = 0; i < 40; i++) {
      await sleep(1_000);
      proposal = (await as('GET', `/api/proposals/${proposalId}`, bernd.apiKey)).body.proposal;
      if (proposal.status !== 'committed') break;
    }
    expect(proposal.status).toBe('refused');
    expect(proposal.refusal).toMatchObject({
      code: 'CUMULATIVE_LIMIT_EXCEEDED', field: 'write_daily_max', expected: 2, actual: 3,
      message: 'Cumulative daily count (3) exceeds write_daily_max=2',
    });
  }, 120_000);
});
