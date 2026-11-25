/**
 * The AI proposes a change to a mandate; the person approves; the gateway replaces it —
 * and the web page signs through the same code. Real Authority Server, real gateway
 * (control plane + MCP server), real CRM connector, shipped profiles. No mocks. The one
 * stand-in is a small network relay in front of the real Authority Server, which only
 * lets the revoke of the old mandate fail so "a failed revoke is told" can be proven.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, request as httpRequest, type Server } from 'node:http';
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
import { profileHashFor, newestProfileId } from '../src/helpers/profiles.js';

const AS_PORT = 18560;
const RELAY_PORT = 18561;
const ANNA = { cp: 18562, mcp: 18563 };
const TEAM = { cp: 18564, mcp: 18565 };
const AS_URL = `http://localhost:${AS_PORT}`;
const RELAY_URL = `http://localhost:${RELAY_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
// What an AI proposal and the page use by default: the newest version in the loaded profiles (customers@0.12 from DEC-106 on),
// never a pinned number — a pinned 0.11 made the AI's mandate (0.12) and the expected one differ.
const CUSTOMERS = newestProfileId('customers', PROFILES_DIR);
const RECORDS = `${P}/records@0.6`;
const DELEGATION = `${P}/delegation@0.6`;
const EMAIL = `${P}/email@0.9`;
const EMAIL_KEYS = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const EMAIL_BOUNDS = { read_access: 'unlimited', recipient_max: 1, send_daily_max: 50, read_max_age_days: 30, setup_daily_max: 0 };
const available = existsSync(join(PROFILES_DIR, 'customers', '0.11.profile.json')) && existsSync(join(PROFILES_DIR, 'delegation', '0.6.profile.json'));

const BOUNDS_KEYS = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const RECORDS_KEYS = ['profile', 'read_access', 'write_daily_max', 'delete_access', 'archive_access'];
const DELEGATION_KEYS = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];

const CRM_INTEGRATION = {
  id: 'crm', name: 'CRM', command: 'npx', args: ['-y', '@humanagencyp/crm-mcp@1.6.0'], envKeys: {}, profile: 'customers', enabled: true,
  toolGating: {
    default: { executionMapping: {}, staticExecution: { contact_type: 'customer' } },
    overrides: {
      create_contact: { executionMapping: { type: 'contact_type' }, staticExecution: { action_type: 'write' } },
      find_contacts: { category: 'read' }, get_timeline: { category: 'read' }, get_pipeline: { category: 'read' }, list_tasks: { category: 'read' }, export_crm: { category: 'read' },
    },
  },
};

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);

// The relay: everything is forwarded to the real Authority Server, except a revoke while `failRevokeOf` names it.
let failRevokeOf: string | null = null;
/** Every revoke the relay refused, by authorization id: the test waits for the refusal itself, not for a side effect. */
const refusedRevokes: string[] = [];
let relay: Server;
async function startRelay(): Promise<void> {
  relay = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (failRevokeOf && req.url?.includes(`/authorizations/${failRevokeOf}/revoke`)) {
        refusedRevokes.push(failRevokeOf);
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'database connection lost' }));
        return;
      }
      const out = httpRequest({ port: AS_PORT, host: 'localhost', path: req.url, method: req.method, headers: req.headers }, (r) => {
        res.writeHead(r.statusCode ?? 502, r.headers);
        r.pipe(res);
      });
      out.on('error', () => { res.writeHead(502); res.end(); });
      out.end(Buffer.concat(chunks));
    });
  });
  await new Promise<void>((r) => relay.listen(RELAY_PORT, r));
}

type Account = { apiKey: string; user: { id: string; did: string } };
interface World {
  name: string; stack: StackOptions; cp: ControlPlaneClient; mcp: GatewayClient; agent: Client; owner: Account; domain: string; groupId: string;
}

function newStack(name: string, ports: { cp: number; mcp: number }, asUrl: string): StackOptions {
  return {
    dataDir: mkdtempSync(join(tmpdir(), `hap-e2e-change-${name}-`)), ports, secret: newSecret(), asUrl,
    extraEnv: { SUVEREN_SIMULATION: '1', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
  };
}

async function as(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}

async function grant(w: World, profile: string, keys: string[], bounds: Record<string, string | number>, context: Record<string, string>, contextKeys: string[], mode: 'review' | 'automatic', intent: string): Promise<string> {
  const b = { profile, ...bounds };
  const boundsHash = computeBoundsHash(b, keys);
  const contextHash = computeScopeHash(context, contextKeys);
  const gate = { intent };
  const att = await sp.submitMandate(w.owner.apiKey, {
    profile_id: profile, profile_hash: profileHashFor(profile, PROFILES_DIR), group_id: w.groupId, bounds: b, bounds_hash: boundsHash, scope_hash: contextHash,
    domain: w.domain, did: w.owner.user.did, commitment_mode: mode,
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: profile }),
  });
  await w.mcp.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context }, profile, gate);
  return att.authorization_id;
}

const grantCustomers = (w: World, writeDailyMax: number, mode: 'review' | 'automatic', contact: string, intent = 'Why — handle new contacts.') =>
  grant(w, CUSTOMERS, BOUNDS_KEYS, { read_access: 'unlimited', export_access: 'none', write_daily_max: writeDailyMax, delete_daily_max: 0, setup_daily_max: 0 }, { contact_type: contact }, ['contact_type'], mode, intent);

async function startWorld(name: string, ports: { cp: number; mcp: number }, owner: Account, groupId: string, domain: string, asUrl = AS_URL): Promise<World> {
  const stack = newStack(name, ports, asUrl);
  await startControlPlane(pm, stack, `cp-${name}`);
  await startMcpServer(pm, stack, `mcp-${name}`);
  const cp = new ControlPlaneClient(`http://localhost:${ports.cp}`);
  const login = await cp.login(owner.apiKey);
  expect(login.status, JSON.stringify(login.body)).toBe(200);
  const mcp = new GatewayClient(`http://localhost:${ports.mcp}`, stack.secret);
  const w: World = { name, stack, cp, mcp, agent: undefined as unknown as Client, owner, domain, groupId };
  await grant(w, DELEGATION, DELEGATION_KEYS, { read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 },
    { allowed_profiles: 'customers', allowed_modes: 'review,automatic' }, ['allowed_profiles', 'allowed_modes'], 'review', 'Why — let the AI propose mandates.');
  expect((await mcp.addIntegration(CRM_INTEGRATION)).ok).toBe(true);
  await mcp.waitForIntegration('crm');
  await new Promise((r) => setTimeout(r, 1500));
  w.agent = new Client({ name: `agent-${name}`, version: '1.0.0' }, { capabilities: {} });
  await w.agent.connect(new SSEClientTransport(new URL(`http://localhost:${ports.mcp}/sse`)));
  return w;
}

async function stopWorld(w: World | undefined) {
  if (!w) return;
  await w.agent?.close().catch(() => {});
  await pm.stopProcess(`mcp-${w.name}`).catch(() => {});
  await pm.stopProcess(`cp-${w.name}`).catch(() => {});
  rmSync(w.stack.dataDir, { recursive: true, force: true });
}

async function change(w: World, args: Record<string, unknown>) {
  const r = await w.agent.callTool({ name: 'setup__change_mandate', arguments: args });
  return { denied: r.isError === true, text: textOf(r) };
}

const proposalIdOf = (t: string) => t.match(/Proposal ID: ([a-f0-9-]+)/)![1];

async function resolve(w: World, proposalId: string, action: 'commit' | 'reject') {
  const r = await as('POST', `/api/proposals/${proposalId}/resolve`, w.owner.apiKey, { action, domain: w.domain });
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
}

/** Wait until `pred` holds or the deadline passes; the gateway acts on the commit by itself. */
async function until<T>(read: () => Promise<T>, pred: (v: T) => boolean, ms = 25_000): Promise<T> {
  const end = Date.now() + ms;
  let last = await read();
  while (!pred(last) && Date.now() < end) {
    await new Promise((r) => setTimeout(r, 400));
    last = await read();
  }
  return last;
}

async function activeIds(owner: Account): Promise<string[]> {
  const r = await as('GET', '/api/mandates/mine?status=active', owner.apiKey);
  return (r.body.mandates ?? []).map((m: { authorization_id: string }) => m.authorization_id);
}

/** Approve a proposed change and wait for the old mandate to be gone and a new one to appear. */
async function approveChange(w: World, proposalId: string, oldId: string): Promise<string> {
  const before = await activeIds(w.owner);
  await resolve(w, proposalId, 'commit');
  const after = await until(() => activeIds(w.owner), (ids) => !ids.includes(oldId) && ids.some((id) => !before.includes(id)));
  expect(after, 'the old mandate should be revoked').not.toContain(oldId);
  const created = after.filter((id) => !before.includes(id));
  expect(created, 'exactly one new mandate').toHaveLength(1);
  return created[0];
}

async function usage(owner: Account, id: string, field: string): Promise<number | undefined> {
  const r = await as('GET', `/api/authorizations/${id}`, owner.apiKey);
  return (r.body.cumulative_usage ?? []).find((u: { field: string }) => u.field === field)?.used;
}

const noAddress = (text: string) => { expect(text).not.toMatch(/localhost|127\.0\.0\.1|https?:\/\//i); };

describe.skipIf(!available)('a change to a mandate, proposed by the AI (real stack)', () => {
  let w: World;
  let other: Account;
  let otherGroup: string;

  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    await startRelay();
    const anna = await sp.register('Anna Change', `anna-change-${Date.now()}@test.local`) as unknown as Account;
    other = await sp.register('Olaf Other', `olaf-change-${Date.now()}@test.local`) as unknown as Account;
    otherGroup = await sp.getPersonalGroupId(other.apiKey);
    w = await startWorld('anna', ANNA, anna, await sp.getPersonalGroupId(anna.apiKey), 'owner', RELAY_URL);
  }, 300_000);

  afterAll(async () => {
    await stopWorld(w);
    await new Promise((r) => relay?.close(r));
    await pm.killAll();
  }, 30_000);

  it('the tool is offered, list-authorizations shows the mandate id, no reply carries a gateway address', async () => {
    const tools = (await w.agent.listTools()).tools;
    const tool = tools.find((t) => t.name === 'setup__change_mandate');
    expect(tool, 'tool not listed').toBeTruthy();
    expect(tools.map((t) => t.name)).not.toContain('setup__describe_mandate_change');
    noAddress(tool!.description ?? '');
    const id = await grantCustomers(w, 3, 'automatic', 'customer');
    const list = textOf(await w.agent.callTool({ name: 'list-authorizations', arguments: { domain: 'customers' } }));
    expect(list).toContain(id);
  }, 60_000);

  it('the Setup mandate itself can never be changed', async () => {
    const setup = (await w.agent.callTool({ name: 'list-authorizations', arguments: { domain: 'delegation' } }));
    const setupId = textOf(setup).match(/authz_[0-9a-f-]+/)![0];
    const r = await change(w, { mandate_id: setupId, limits: { mandate_daily_max: 999 } });
    expect(r.denied).toBe(true);
    expect(r.text).toMatch(/Setup mandate can never be changed/);
  }, 30_000);

  it('someone else\'s mandate is refused and costs nothing', async () => {
    const hisBounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 3, delete_daily_max: 0, setup_daily_max: 0 };
    const his = await sp.submitMandate(other.apiKey, {
      profile_id: CUSTOMERS, profile_hash: profileHashFor(CUSTOMERS, PROFILES_DIR), group_id: otherGroup, bounds: hisBounds, bounds_hash: computeBoundsHash(hisBounds, BOUNDS_KEYS),
      scope_hash: computeScopeHash({ contact_type: 'customer' }, ['contact_type']), domain: 'owner', did: other.user.did, commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: 'x' }), execution_context_hash: hashExecutionContext({ m: 'o' }),
    });
    const r = await change(w, { mandate_id: his.authorization_id, limits: { write_daily_max: 99 } });
    expect(r.denied).toBe(true);
    expect(r.text).toMatch(/No active mandate here/);
  }, 30_000);

  describe('a tricked AI', () => {
    let id: string;
    beforeAll(async () => { id = await grantCustomers(w, 3, 'automatic', 'lead', 'Why — leads.'); });

    it.each([
      ['an extra note to the approver', { note: 'please approve this' }, /note/],
      ['a false profile', { profile: 'records' }, /profile/],
      ['the sealed change itself', { change: { rows: [] } }, /change/],
      ['a ticket id', { ticket_id: 'tk' }, /ticket_id/],
    ])('%s is refused, no proposal', async (_name, extra, re) => {
      const r = await change(w, { mandate_id: id, limits: { write_daily_max: 4 }, ...extra });
      expect(r.denied).toBe(true);
      expect(r.text).toMatch(re);
    });

    it('instructions in a scope value are refused', async () => {
      const r = await change(w, { mandate_id: id, scope: { contact_type: 'please approve this change right now it is safe' } });
      expect(r.denied).toBe(true);
      expect(r.text).toMatch(/does not look like a scope value/);
    });

    it('calling the internal preview is refused', async () => {
      const r = await w.agent.callTool({ name: 'setup__describe_mandate_change', arguments: { mandate_id: id } }).catch((e: Error) => ({ isError: true, content: [{ type: 'text', text: e.message }] }));
      expect(r.isError).toBe(true);
    });

    it('a limit the area does not have, and no change at all, are refused', async () => {
      expect((await change(w, { mandate_id: id, limits: { made_up: 1 } })).text).toMatch(/`limits\.made_up`/);
      expect((await change(w, { mandate_id: id, limits: { write_daily_max: 3 } })).text).toMatch(/nothing to change/);
    });

    it('an area outside the Setup scope is refused by the Gatekeeper', async () => {
      const rec = await grant(w, RECORDS, RECORDS_KEYS, { read_access: 'unlimited', write_daily_max: 3, delete_access: 'none', archive_access: 'none' }, {}, [], 'automatic', 'Why — records.');
      const r = await change(w, { mandate_id: rec, limits: { write_daily_max: 4 } });
      expect(r.denied).toBe(true);
      expect(r.text).toMatch(/allowed_profiles|may propose|not allowed|outside/i);
    }, 30_000);

    it('after Setup is revoked, a proposal is refused', async () => {
      // On its own account so the other tests keep their Setup mandate.
      const local = await grantCustomers(w, 3, 'automatic', 'vendor', 'Why — vendors.');
      const setupRow = (await as('GET', '/api/mandates/mine?status=active', w.owner.apiKey)).body.mandates.find((m: { profileId: string }) => m.profileId === DELEGATION);
      await as('POST', `/api/authorizations/${setupRow.authorization_id}/revoke`, w.owner.apiKey, { reason: 'test' });
      await new Promise((r) => setTimeout(r, 800));
      const r = await change(w, { mandate_id: local, limits: { write_daily_max: 4 } });
      expect(r.denied).toBe(true);
      expect(r.text).toMatch(/Setup/);
      // Give Setup back for the rest of the file.
      await grant(w, DELEGATION, DELEGATION_KEYS, { read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 },
        { allowed_profiles: 'customers', allowed_modes: 'review,automatic' }, ['allowed_profiles', 'allowed_modes'], 'review', 'Why — let the AI propose mandates.');
      await new Promise((r) => setTimeout(r, 800));
    }, 30_000);
  });

  describe('approved and rejected', () => {
    let oldId: string;
    beforeAll(async () => { oldId = await grantCustomers(w, 3, 'automatic', 'partner', 'Why — partners. Keep it short.'); });

    it('raising a limit: today\'s count carries over on the same version, the new limit holds', async () => {
      for (let i = 0; i < 2; i++) {
        const t = await sp.postTicket(w.owner.apiKey, {
          authorizationId: oldId, profileId: CUSTOMERS, action: 'crm__create_contact', actionType: 'write',
          executionContext: { contact_type: 'partner', action_type: 'write' },
        });
        expect(t.status, JSON.stringify(t.body)).toBe(201);
      }
      expect(await usage(w.owner, oldId, 'write_daily_max')).toBe(2);
      const r = await change(w, { mandate_id: oldId, limits: { write_daily_max: 6 } });
      expect(r.denied, r.text).toBe(false);
      expect(r.text).toMatch(/Awaiting commitment/);
      noAddress(r.text);
      const proposalId = proposalIdOf(r.text);

      // Nothing has changed until a person decides.
      expect(await activeIds(w.owner)).toContain(oldId);

      const newId = await approveChange(w, proposalId, oldId);
      const summary = await sp.getAuthorizationSummary(w.owner.apiKey, newId);
      expect(summary.body).toMatchObject({ created_by: w.owner.user.id, profile_id: CUSTOMERS, commitment_mode: 'automatic' });
      expect(summary.body.replaces).toBe(oldId);
      const expectedBounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 6, delete_daily_max: 0, setup_daily_max: 0 };
      expect(summary.body.bounds_hash).toBe(computeBoundsHash(expectedBounds, BOUNDS_KEYS));

      // Same version: the count stays at 2 and the new limit is 6.
      expect(await usage(w.owner, newId, 'write_daily_max')).toBe(2);
      const t = await sp.postTicket(w.owner.apiKey, { authorizationId: newId, profileId: CUSTOMERS, action: 'crm__create_contact', actionType: 'write', executionContext: { contact_type: 'partner', action_type: 'write' } });
      expect(t.status, JSON.stringify(t.body)).toBe(201);
      for (let i = 0; i < 3; i++) {
        const more = await sp.postTicket(w.owner.apiKey, { authorizationId: newId, profileId: CUSTOMERS, action: 'crm__create_contact', actionType: 'write', executionContext: { contact_type: 'partner', action_type: 'write' } });
        expect(more.status, JSON.stringify(more.body)).toBe(201);
      }
      const over = await sp.postTicket(w.owner.apiKey, { authorizationId: newId, profileId: CUSTOMERS, action: 'crm__create_contact', actionType: 'write', executionContext: { contact_type: 'partner', action_type: 'write' } });
      expect(over.status).toBe(403);
      expect(JSON.stringify(over.body)).toMatch(/CUMULATIVE_LIMIT_EXCEEDED/);
    }, 120_000);

    it('the end date stays unless a new one is proposed', async () => {
      const id = await grantCustomers(w, 3, 'automatic', 'customer,lead', 'Why — keep the date.');
      const r = await change(w, { mandate_id: id, intent: 'Why — keep the date, with new words.' });
      const newId = await approveChange(w, proposalIdOf(r.text), id);
      const atts = async (x: string) => (await as('GET', `/api/mandates?authorization_id=${x}`, w.owner.apiKey)).body.mandates[0].expires_at;
      expect(Math.abs((await atts(newId)) - (await atts(id)))).toBeLessThan(30);
    }, 90_000);

    it('a reduction also waits for the person, and only then takes effect', async () => {
      const id = await grantCustomers(w, 9, 'automatic', 'customer,partner', 'Why — reduce.');
      const r = await change(w, { mandate_id: id, limits: { write_daily_max: 1 } });
      expect(r.denied, r.text).toBe(false);
      expect(r.text).toMatch(/Awaiting commitment/);
      expect(await activeIds(w.owner)).toContain(id);
      const newId = await approveChange(w, proposalIdOf(r.text), id);
      const expected = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 1, delete_daily_max: 0, setup_daily_max: 0 };
      expect((await sp.getAuthorizationSummary(w.owner.apiKey, newId)).body.bounds_hash).toBe(computeBoundsHash(expected, BOUNDS_KEYS));
    }, 90_000);

    it('a rejected change changes nothing', async () => {
      const id = await grantCustomers(w, 3, 'automatic', 'lead,customer', 'Why — reject me.');
      const r = await change(w, { mandate_id: id, limits: { write_daily_max: 9 } });
      await resolve(w, proposalIdOf(r.text), 'reject');
      await new Promise((r2) => setTimeout(r2, 4000));
      expect(await activeIds(w.owner)).toContain(id);
    }, 60_000);

    it('waiting requests under the old mandate close when it is replaced', async () => {
      // Only one mandate may cover the call, or it runs automatically under another.
      for (const m of (await as('GET', '/api/mandates/mine?status=active', w.owner.apiKey)).body.mandates as Array<{ authorization_id: string; profileId: string }>) {
        if (m.profileId === CUSTOMERS) await as('POST', `/api/authorizations/${m.authorization_id}/revoke`, w.owner.apiKey, {});
      }
      await fetch(`http://localhost:${ANNA.cp}/resync-gates`, { method: 'POST', headers: { 'X-API-Key': w.owner.apiKey } });
      const id = await grantCustomers(w, 50, 'review', 'lead,customer,partner', 'Why — waiting.');
      await new Promise((r) => setTimeout(r, 2000));
      const asked = textOf(await w.agent.callTool({ name: 'crm__create_contact', arguments: { name: 'Waiting Wendy', type: 'customer' } }));
      expect(asked).toMatch(/Awaiting commitment/);
      const waiting = proposalIdOf(asked);
      const r = await change(w, { mandate_id: id, limits: { write_daily_max: 40 } });
      expect(r.denied, r.text).toBe(false);
      const newId = await approveChange(w, proposalIdOf(r.text), id);
      expect(newId).toBeTruthy();
      const p = (await as('GET', `/api/proposals/${waiting}`, w.owner.apiKey)).body.proposal;
      expect(p.mandateEnded).toBe('revoked');
      const commit = await as('POST', `/api/proposals/${waiting}/resolve`, w.owner.apiKey, { action: 'commit', domain: w.domain });
      expect(commit.status).toBeGreaterThanOrEqual(400);
      expect(JSON.stringify(commit.body)).toMatch(/revoked/i);
    }, 120_000);

    it('a failed revoke: the old mandate is no longer used on this gateway at once, the AI is told the change is in place, and the gateway ends the old one on the AS by itself', async () => {
      // Narrow the scope: `vendor` is allowed by the old mandate only.
      const id = await grantCustomers(w, 3, 'automatic', 'vendor,lead', 'Why — revoke fails.');
      const r = await change(w, { mandate_id: id, scope: { contact_type: 'lead' } });
      expect(r.denied, r.text).toBe(false);
      failRevokeOf = id;
      const proposalId = proposalIdOf(r.text);
      const before = await activeIds(w.owner);
      await resolve(w, proposalId, 'commit');
      // The gateway revokes the old mandate only after the new one is issued AND delivered. Keep the revoke
      // failing until the relay has actually refused it.
      const refused = await until(async () => refusedRevokes.includes(id), (v) => v);
      expect(refused, 'the gateway never sent the revoke of the old mandate').toBe(true);
      // The AS still holds both: the new mandate was delivered, the revoke of the old one failed.
      const after = await until(() => activeIds(w.owner), (ids) => ids.some((x) => !before.includes(x)));
      expect(after).toContain(id);
      expect(after.filter((x) => !before.includes(x))).toHaveLength(1);

      // The AI is told the change happened — not that it failed.
      const told = await until(
        async () => textOf(await w.agent.callTool({ name: 'check-pending-commitments', arguments: { proposal_id: proposalId } })),
        (t) => /The change is in place/.test(t),
      );
      expect(told).toContain('The change is in place. The old mandate is no longer used on this computer. It will be ended on suveren.ai as soon as possible.');
      expect(told).not.toMatch(/still live with its old limits|nothing was done/i);
      noAddress(told);

      // A call only the OLD mandate allows is refused on this gateway, although the AS still serves it.
      const vendor = await w.agent.callTool({ name: 'crm__create_contact', arguments: { name: 'Vera Vendor', type: 'vendor' } });
      expect(vendor.isError, textOf(vendor)).toBe(true);
      expect(textOf(vendor)).not.toMatch(/Awaiting commitment/);
      // A call the NEW mandate allows still runs.
      const lead = await w.agent.callTool({ name: 'crm__create_contact', arguments: { name: 'Lena Lead', type: 'lead' } });
      expect(lead.isError, textOf(lead)).not.toBe(true);

      // The page's list knows it is replaced (for its quiet line).
      const replaced = await fetch(`http://localhost:${ANNA.cp}/api/replaced-mandates`, { headers: { 'X-API-Key': w.owner.apiKey } });
      expect(replaced.status).toBe(200);
      expect(((await replaced.json()) as { entries: Array<{ authorizationId: string }> }).entries.map((e) => e.authorizationId)).toContain(id);

      // The AS accepts revokes again: the gateway's retry ends the old mandate there by itself.
      failRevokeOf = null;
      const ended = await until(() => activeIds(w.owner), (ids) => !ids.includes(id), 200_000);
      expect(ended, 'the gateway never retried the revoke').not.toContain(id);
      const cleared = await until(
        async () => ((await (await fetch(`http://localhost:${ANNA.cp}/api/replaced-mandates`, { headers: { 'X-API-Key': w.owner.apiKey } })).json()) as { entries: unknown[] }).entries.length,
        (n) => n === 0,
      );
      expect(cleared).toBe(0);
    }, 300_000);
  });

  describe('a list whose empty value allows nothing: what the AI may attach', () => {
    const SAVED = { connector: 'files', kind: 'file', id: 'not-saved-yet' };
    type Row = { field: string; tag: string; added?: string[]; removed?: string[]; emptyMeans?: string; format?: string };

    /** An email mandate; `sources` undefined leaves the attachment list out entirely. */
    async function grantEmail(to: string, sources: string | undefined): Promise<string> {
      const scope: Record<string, string> = { allowed_recipients: to, allowed_domains: to.split('@')[1] };
      if (sources !== undefined) scope.allowed_attachment_sources = sources;
      return grant(w, EMAIL, EMAIL_KEYS, EMAIL_BOUNDS, scope, Object.keys(scope), 'automatic', `Why — email ${to}.`);
    }

    /** The sealed differences, as the approval card reads them (decrypted on this gateway when needed). */
    async function sealedRows(proposalId: string): Promise<Row[]> {
      const p = (await as('GET', `/api/proposals/${proposalId}`, w.owner.apiKey)).body.proposal;
      let args = p.toolArgs;
      if (!args) {
        const res = await w.cp.authed(w.owner.apiKey, 'POST', '/api/decrypt-proposal-content', p.content);
        const dec = await res.json() as { plaintext?: string };
        expect(res.status, JSON.stringify(dec)).toBe(200);
        args = JSON.parse(dec.plaintext!);
      }
      return args.change.rows as Row[];
    }

    /** The gateway's own facts for the card: what the page reads under "From your gateway". */
    async function cardFacts(proposalId: string) {
      const res = await w.cp.authed(w.owner.apiKey, 'GET', `/proposal-status/${proposalId}/preview`);
      const body = await res.json() as { status: string; body?: { structured?: { refused?: Array<{ field: string; values?: string[]; ts: number }> } } };
      expect(res.status, JSON.stringify(body)).toBe(200);
      return body.body?.structured;
    }

    beforeAll(async () => {
      // The practice mailbox, from its shipped manifest; Setup may now propose email mandates too.
      const on = await w.cp.authed(w.owner.apiKey, 'POST', '/mcp/integrations/mail/activate');
      expect(on.status, await on.text()).toBe(200);
      await w.mcp.waitForIntegration('mail');
      await grant(w, DELEGATION, DELEGATION_KEYS, { read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 },
        { allowed_profiles: 'customers,email', allowed_modes: 'review,automatic' }, ['allowed_profiles', 'allowed_modes'], 'review', 'Why — email too.');
      await w.agent.close().catch(() => {});
      w.agent = new Client({ name: 'agent-anna-mail', version: '1.0.0' }, { capabilities: {} });
      await w.agent.connect(new SSEClientTransport(new URL(`http://localhost:${ANNA.mcp}/sse`)));
    }, 180_000);

    it('adding Saved files is More, and the card names the refusal it would have allowed; once signed, the gateway lets the source through', async () => {
      const id = await grantEmail('kunde@attach.example', undefined);
      await new Promise((r) => setTimeout(r, 1500));
      const send = { to: ['kunde@attach.example'], subject: 'Unterlagen', body: 'Im Anhang.', attachments: [SAVED] };
      const refused = await w.agent.callTool({ name: 'mail__send_message', arguments: send });
      expect(refused.isError, textOf(refused)).toBe(true);
      expect(textOf(refused)).toMatch(/no Email mandate lets .* attach Saved files/);

      const r = await change(w, { mandate_id: id, scope: { allowed_attachment_sources: 'files:file' } });
      expect(r.denied, r.text).toBe(false);
      const proposalId = proposalIdOf(r.text);
      const row = (await sealedRows(proposalId)).find((x) => x.field === 'allowed_attachment_sources');
      expect(row).toMatchObject({ tag: 'More', added: ['files:file'], removed: [], emptyMeans: 'nothing', format: 'connector:kind' });

      const facts = await cardFacts(proposalId);
      expect(facts?.refused, JSON.stringify(facts)).toEqual([expect.objectContaining({ field: 'allowed_attachment_sources', values: ['files:file'] })]);
      expect(Date.now() - facts!.refused![0].ts).toBeLessThan(120_000);

      // Signed: the source is no longer refused by the mandate (the file itself does not exist).
      await approveChange(w, proposalId, id);
      await new Promise((r2) => setTimeout(r2, 1500));
      const after = await w.agent.callTool({ name: 'mail__send_message', arguments: send });
      expect(textOf(after)).not.toMatch(/no Email mandate lets/);
      expect(textOf(after)).toMatch(/could not resolve attachment|not-saved-yet/);
    }, 150_000);

    it('removing a source is Less, also when the list ends up empty', async () => {
      const id = await grantEmail('kunde@less.example', 'erp:invoice-pdf,files:file');
      const one = await change(w, { mandate_id: id, scope: { allowed_attachment_sources: 'files:file' } });
      expect(one.denied, one.text).toBe(false);
      expect((await sealedRows(proposalIdOf(one.text))).find((x) => x.field === 'allowed_attachment_sources'))
        .toMatchObject({ tag: 'Less', added: [], removed: ['erp:invoice-pdf'] });
      await resolve(w, proposalIdOf(one.text), 'reject');

      const none = await change(w, { mandate_id: id, scope: { allowed_attachment_sources: '' } });
      expect(none.denied, none.text).toBe(false);
      expect((await sealedRows(proposalIdOf(none.text))).find((x) => x.field === 'allowed_attachment_sources'))
        .toMatchObject({ tag: 'Less', removed: ['erp:invoice-pdf', 'files:file'] });
      await resolve(w, proposalIdOf(none.text), 'reject');
    }, 90_000);

    it('a recipients change behaves as before: adding one is More; an empty list allows anyone, so emptying it is More', async () => {
      const id = await grantEmail('anna@rcpt.example', 'files:file');
      const add = await change(w, { mandate_id: id, scope: { allowed_recipients: 'anna@rcpt.example,bob@rcpt.example' } });
      expect(add.denied, add.text).toBe(false);
      expect((await sealedRows(proposalIdOf(add.text))).find((x) => x.field === 'allowed_recipients'))
        .toMatchObject({ tag: 'More', added: ['bob@rcpt.example'], removed: [], emptyMeans: 'anything' });
      await resolve(w, proposalIdOf(add.text), 'reject');

      const open = await change(w, { mandate_id: id, scope: { allowed_recipients: '' } });
      expect(open.denied, open.text).toBe(false);
      expect((await sealedRows(proposalIdOf(open.text))).find((x) => x.field === 'allowed_recipients'))
        .toMatchObject({ tag: 'More', removed: ['anna@rcpt.example'] });
      await resolve(w, proposalIdOf(open.text), 'reject');
    }, 90_000);
  });

  describe('the web page signs through the same code', () => {
    it('a mandate signed on the page and one created by the AI carry the same hashes, mode and owner', async () => {
      const limits = { read_access: 'unlimited', export_access: 'none', write_daily_max: 7, delete_daily_max: 0, setup_daily_max: 0 };
      const web = await fetch(`http://localhost:${ANNA.cp}/api/mandate/sign`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': w.owner.apiKey },
        body: JSON.stringify({ team: 'personal', profile: CUSTOMERS, limits, scope: { contact_type: 'customer' }, intent: 'Why — the same.', mode: 'review', ttlSeconds: 3600, title: 'Web', discloseIdentity: false }),
      });
      const webBody = await web.json() as { authorizationId: string };
      expect(web.status, JSON.stringify(webBody)).toBe(200);
      const made = await w.agent.callTool({ name: 'setup__create_mandate', arguments: { profile: 'customers', limits, scope: { contact_type: 'customer' }, intent: 'Why — the same.', mode: 'review', duration_hours: 1, title: 'AI' } });
      expect(textOf(made)).toMatch(/Awaiting commitment/);
      const before = await activeIds(w.owner);
      await resolve(w, proposalIdOf(textOf(made)), 'commit');
      const after = await until(() => activeIds(w.owner), (ids) => ids.some((x) => !before.includes(x)));
      const aiId = after.find((x) => !before.includes(x))!;
      const [a, b] = await Promise.all([sp.getAuthorizationSummary(w.owner.apiKey, webBody.authorizationId), sp.getAuthorizationSummary(w.owner.apiKey, aiId)]);
      expect(b.body.bounds_hash).toBe(a.body.bounds_hash);
      expect(b.body.profile_id).toBe(a.body.profile_id);
      expect(b.body.commitment_mode).toBe(a.body.commitment_mode);
      expect(b.body.created_by).toBe(a.body.created_by);
    }, 90_000);

    it('the Authority Server refuses a replacement of another person\'s mandate', async () => {
      const hisBounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 3, delete_daily_max: 0, setup_daily_max: 0 };
      const his = await sp.submitMandate(other.apiKey, {
        profile_id: CUSTOMERS, profile_hash: profileHashFor(CUSTOMERS, PROFILES_DIR), group_id: otherGroup, bounds: hisBounds, bounds_hash: computeBoundsHash(hisBounds, BOUNDS_KEYS),
        scope_hash: computeScopeHash({ contact_type: 'customer' }, ['contact_type']), domain: 'owner', did: other.user.did, commitment_mode: 'automatic',
        gate_content_hashes: hashGateContent({ intent: 'y' }), execution_context_hash: hashExecutionContext({ m: 'o' }),
      });
      const res = await fetch(`http://localhost:${ANNA.cp}/api/mandate/sign`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': w.owner.apiKey },
        body: JSON.stringify({ team: 'personal', profile: CUSTOMERS, limits: { read_access: 'unlimited', export_access: 'none', write_daily_max: 1, delete_daily_max: 0, setup_daily_max: 0 }, scope: { contact_type: 'customer' }, intent: 'Why.', mode: 'review', ttlSeconds: 3600, title: 'Replace', replaces: his.authorization_id }),
      });
      expect(res.status).toBe(422);
      expect(await res.text()).toMatch(/Only the person who gave a mandate can replace it/);
      // And his mandate is untouched.
      expect(await activeIds(other)).toContain(his.authorization_id);
    }, 60_000);
  });

  describe('team', () => {
    let tom: Account;
    let bernd: Account;
    let team: World;
    let berndId: string;

    beforeAll(async () => {
      tom = await sp.register('Tom Change', `tom-change-${Date.now()}@test.local`) as unknown as Account;
      bernd = await sp.register('Bernd Change', `bernd-change-${Date.now()}@test.local`) as unknown as Account;
      await as('PUT', '/api/users/me/pubkey', tom.apiKey, { pubkey: randomBytes(32).toString('base64') });
      const t = await sp.createGroup(tom.apiKey, 'Sales Vienna');
      await sp.joinGroup(bernd.apiKey, t.inviteCode ?? t.group.inviteCode, tom.apiKey);
      await sp.setProfileConfig(tom.apiKey, t.group.id, DELEGATION, { approvers: [bernd.user.id] });
      await sp.setProfileConfig(tom.apiKey, t.group.id, CUSTOMERS, { approvers: [tom.user.id, bernd.user.id] });
      team = await startWorld('team', TEAM, bernd, t.group.id, bernd.user.id);
      berndId = await grantCustomers(team, 3, 'review', 'customer');
      await new Promise((r) => setTimeout(r, 1500));
    }, 180_000);

    afterAll(async () => { await stopWorld(team); }, 30_000);

    it('team: a mandate signed on the page encrypts its intent for the approvers', async () => {
      const res = await fetch(`http://localhost:${TEAM.cp}/api/mandate/sign`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': bernd.apiKey },
        body: JSON.stringify({ team: team.groupId, profile: CUSTOMERS, limits: { read_access: 'unlimited', export_access: 'none', write_daily_max: 5, delete_daily_max: 0, setup_daily_max: 0 }, scope: { contact_type: 'lead' }, intent: 'Why — team web.', mode: 'review', ttlSeconds: 3600, title: 'Team web' }),
      });
      const body = await res.json() as { authorizationId: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      for (const who of [tom, bernd]) {
        const intent = await as('GET', `/api/authorizations/${body.authorizationId}/intent`, who.apiKey);
        expect(intent.status, JSON.stringify(intent.body)).toBe(200);
        expect(intent.body.encryptedKey).toMatchObject({ ct: expect.any(String) });
      }
    }, 60_000);

    it('a person the team does not allow to give this mandate cannot have it changed', async () => {
      await sp.setProfileConfig(tom.apiKey, team.groupId, CUSTOMERS, { approvers: [tom.user.id] });
      const r = await change(team, { mandate_id: berndId, limits: { write_daily_max: 1 } });
      expect(r.denied).toBe(true);
      expect(r.text).toMatch(/approvers in "Sales Vienna"/);
      await sp.setProfileConfig(tom.apiKey, team.groupId, CUSTOMERS, { approvers: [tom.user.id, bernd.user.id] });
    }, 30_000);
  });
});
