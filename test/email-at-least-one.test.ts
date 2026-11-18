/**
 * "An email mandate must name who it may write to" — email@0.10 declares
 * `scopeSchema.atLeastOne: [{ fields: [allowed_recipients, allowed_domains], requiredFor: [send] }]`.
 * Scope never reaches the Authority Server, so the gateway enforces it. On the real
 * stack in simulation mode: Authority Server (serving the local hap-profiles, incl.
 * email@0.10), the whole gateway (control plane + MCP server), the published
 * email-mcp with its practice mailbox. Nothing is mocked.
 *
 * What must hold (Andreas, 2026-11-11, doc/email-recipients-required-proposal.md):
 *  - the AI's proposal of an Email mandate that allows sending with neither field is
 *    refused at the call with the decided sentence, no proposal; with a domain it
 *    becomes a proposal, is created under email@0.10 (the newest version is the
 *    default) and sends inside its domain;
 *  - a read-only 0.10 mandate (send limit 0) needs neither field;
 *  - change_mandate removing the last recipient while sending stays allowed is refused;
 *  - a 0.10 mandate signed directly against the Authority Server with neither field
 *    (the AS cannot see scope, so it accepts it) is refused at send by the Gatekeeper
 *    with the decided sentence: nothing sent, no ticket;
 *  - an email@0.9 mandate with neither field (an open one) still sends: the rule
 *    applies only to versions that declare it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { ControlPlaneClient, newSecret, startControlPlane, startMcpServer, textOf, PROFILES_DIR, type StackOptions } from '../src/helpers/gateway-stack.js';
import { profileHashFor, newestProfileId } from '../src/helpers/profiles.js';
import { e2ePort } from '../src/helpers/ports.js';

// 18700–18709 belong to this file.
const AS_PORT = e2ePort(18700);
const PORTS = { cp: e2ePort(18701), mcp: e2ePort(18702) };
const AS_URL = `http://localhost:${AS_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const EMAIL_10 = `${P}/email@0.10`;
const EMAIL_09 = `${P}/email@0.9`;
/** The default an AI proposal is created under: the newest Email version (0.10 or later — the rule holds from 0.10 on). */
const EMAIL_DEFAULT = newestProfileId('email', PROFILES_DIR);
const DELEGATION = `${P}/delegation@0.6`;
const available = existsSync(join(PROFILES_DIR, 'email', '0.10.profile.json')) && existsSync(join(PROFILES_DIR, 'delegation', '0.6.profile.json'));
if (!available) console.warn('[EMAIL AT-LEAST-ONE E2E] SKIPPED — needs hap-profiles email@0.10 and delegation@0.6.');

const EMAIL_KEYS = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const EMAIL_SCOPE_KEYS = ['allowed_recipients', 'allowed_domains', 'allowed_attachment_sources'];
const DELEGATION_KEYS = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];

const BUILD_REFUSAL = 'An Email mandate that allows sending must name at least one allowed recipient or domain. Ask the person who the AI may write to.';
const SEND_REFUSAL = 'This mandate names no allowed recipient or domain, so it cannot send. The person gives a new Email mandate that says who the AI may write to.';

const DOMAIN = 'kunde-gmbh.example';
const LIMITS = { read_access: 'unlimited', recipient_max: 1, send_daily_max: 5, setup_daily_max: 0 };

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);

type Account = { apiKey: string; user: { id: string; did: string } };
let owner: Account;
let groupId: string;
let stack: StackOptions;
let cp: ControlPlaneClient;
let mcp: GatewayClient;
let agent: Client;
let mailbox: Client;

async function as(method: string, path: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': owner.apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}

/** Signed straight against the Authority Server, as another surface could: the AS never sees the scope. */
async function grant(profile: string, keys: string[], bounds: Record<string, string | number>, scope: Record<string, string>, scopeKeys: string[], mode: 'review' | 'automatic', intent: string): Promise<string> {
  const b = { profile, ...bounds };
  const boundsHash = computeBoundsHash(b, keys);
  const contextHash = computeScopeHash(scope, scopeKeys);
  const gate = { intent };
  const att = await sp.submitMandate(owner.apiKey, {
    profile_id: profile, profile_hash: profileHashFor(profile, PROFILES_DIR), group_id: groupId, bounds: b, bounds_hash: boundsHash, scope_hash: contextHash,
    domain: 'owner', did: owner.user.did, commitment_mode: mode,
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: profile }),
  });
  await mcp.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, profile, gate);
  return att.authorization_id;
}

/** Revoke on the AS, then let the gateway drop it now (as the Mandates page does), not at its next sync. */
async function revoke(id: string) {
  await as('POST', `/api/authorizations/${id}/revoke`, { reason: 'test' });
  const res = await cp.authed(owner.apiKey, 'POST', '/resync-gates');
  expect(res.status, await res.text()).toBeLessThan(300);
  await new Promise((r) => setTimeout(r, 800));
}

async function activeEmail(): Promise<Array<{ authorization_id: string; profileId?: string; profile_id?: string }>> {
  const rows = (await as('GET', '/api/mandates/mine?status=active')).body.mandates ?? [];
  return rows.filter((m: { profileId?: string; profile_id?: string }) => (m.profileId ?? m.profile_id ?? '').includes('/email@'));
}

async function pendingCount(): Promise<number> {
  return ((await as('GET', '/api/proposals?domain=owner')).body.proposals ?? []).filter((p: { status: string }) => p.status === 'pending').length;
}

async function tool(name: string, args: Record<string, unknown>) {
  const r = await agent.callTool({ name, arguments: args });
  return { denied: r.isError === true, text: textOf(r) };
}

/** Approve a proposal and wait for the new email mandate on the AS. */
async function approveNewEmail(text: string): Promise<{ authorization_id: string; profileId?: string; profile_id?: string }> {
  const proposalId = text.match(/Proposal ID: ([a-f0-9-]+)/)![1];
  const before = new Set((await activeEmail()).map((m) => m.authorization_id));
  const r = await as('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner' });
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
  const until = Date.now() + 25_000;
  while (Date.now() < until) {
    const created = (await activeEmail()).filter((m) => !before.has(m.authorization_id));
    if (created.length) { await new Promise((res) => setTimeout(res, 800)); return created[0]; }
    await new Promise((res) => setTimeout(res, 500));
  }
  throw new Error('no mandate appeared after approval');
}

async function sentCount(): Promise<number> {
  const r = await mailbox.callTool({ name: 'list_messages', arguments: { folder: 'sent' } });
  const list = JSON.parse(((r.content as Array<{ text?: string }>)?.[0]?.text ?? '[]'));
  return (Array.isArray(list) ? list : list.messages ?? []).length;
}

async function ticketsFor(id: string): Promise<number> {
  const { tickets } = await sp.getMyTicketsPage(owner.apiKey, { limit: 100 });
  return tickets.filter((t) => JSON.stringify(t).includes(id)).length;
}

const send = (to: string) => tool('mail__send_message', { to: [to], subject: 'Termin', body: 'Guten Tag, ein Test der Suveren-E2E-Suite.' });

describe.skipIf(!available)('an Email mandate must name who it may write to (real stack, simulation)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    owner = await sp.register('Erika AtLeastOne', `erika-alo-${Date.now()}@test.local`) as unknown as Account;
    groupId = await sp.getPersonalGroupId(owner.apiKey);
    stack = {
      dataDir: mkdtempSync(join(tmpdir(), 'hap-e2e-at-least-one-')), ports: PORTS, secret: newSecret(), asUrl: AS_URL,
      extraEnv: { SUVEREN_SIMULATION: '1', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
    };
    await startControlPlane(pm, stack, 'cp-alo');
    await startMcpServer(pm, stack, 'mcp-alo');
    cp = new ControlPlaneClient(`http://localhost:${PORTS.cp}`);
    expect((await cp.login(owner.apiKey)).status).toBe(200);
    mcp = new GatewayClient(`http://localhost:${PORTS.mcp}`, stack.secret);

    const act = await cp.authed(owner.apiKey, 'POST', '/mcp/integrations/mail/activate');
    expect(act.status, await act.text()).toBe(200);
    await mcp.waitForIntegration('mail');

    await grant(DELEGATION, DELEGATION_KEYS, { read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 },
      { allowed_profiles: 'email', allowed_modes: 'review,automatic' }, ['allowed_profiles', 'allowed_modes'], 'review', 'E2E: let the AI propose Email mandates.');

    const mailBin = join(stack.dataDir, 'integrations', 'node_modules', '@humanagencyp', 'email-mcp', 'dist', 'index.js');
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'DATABASE_URL') env[k] = v;
    mailbox = new Client({ name: 'operator-mailbox', version: '1.0.0' }, { capabilities: {} });
    await mailbox.connect(new StdioClientTransport({ command: process.execPath, args: [mailBin], env: { ...env, HAP_DATA_DIR: stack.dataDir } }));

    await new Promise((r) => setTimeout(r, 1_500));
    agent = new Client({ name: 'alo-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${PORTS.mcp}/sse`)));
  }, 300_000);

  afterAll(async () => {
    for (const c of [agent, mailbox]) if (c) await c.close().catch(() => {});
    await pm.stopProcess('mcp-alo').catch(() => {});
    await pm.stopProcess('cp-alo').catch(() => {});
    await pm.killAll();
    if (stack) rmSync(stack.dataDir, { recursive: true, force: true });
  }, 30_000);

  it('the AI is told before it proposes: the area\'s field list names the rule', async () => {
    const r = await tool('list-authorizations', { domain: 'email' });
    expect(r.text).toContain('scope rule: when the limits allow send, set at least one of allowed_recipients, allowed_domains (ask the person who the AI may write to)');
  });

  it('a proposal that allows sending with neither field is refused at the call with the decided sentence; no proposal', async () => {
    const before = await pendingCount();
    const r = await tool('setup__create_mandate', { profile: 'email', limits: LIMITS, scope: {}, intent: 'Why — reply to customers.', mode: 'automatic', duration_hours: 2, title: 'Replies' });
    expect(r.denied).toBe(true);
    expect(r.text).toContain(BUILD_REFUSAL);
    expect(await pendingCount()).toBe(before);
  });

  it('a read-only mandate (send limit 0) needs neither field', async () => {
    const r = await tool('setup__create_mandate', { profile: 'email', limits: { ...LIMITS, send_daily_max: 0 }, scope: {}, intent: 'Why — read the mailbox only.', mode: 'automatic', duration_hours: 2, title: 'Read only' });
    expect(r.denied, r.text).toBe(false);
    const m = await approveNewEmail(r.text);
    expect(m.profileId ?? m.profile_id).toBe(EMAIL_DEFAULT);
    await revoke(m.authorization_id);
  });

  let domainMandate = '';
  it('with a domain it becomes a proposal, is created under the newest Email version (the default) and sends inside the domain', async () => {
    const r = await tool('setup__create_mandate', { profile: 'email', limits: LIMITS, scope: { allowed_domains: DOMAIN }, intent: 'Why — reply to the customer.', mode: 'automatic', duration_hours: 2, title: 'Customer replies' });
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toMatch(/Awaiting commitment/);
    const m = await approveNewEmail(r.text);
    expect(m.profileId ?? m.profile_id).toBe(EMAIL_DEFAULT);
    domainMandate = m.authorization_id;

    const sent = await sentCount();
    const s = await send(`buchhaltung@${DOMAIN}`);
    expect(s.denied, s.text).toBe(false);
    expect(await sentCount()).toBe(sent + 1);
  }, 60_000);

  it('change_mandate removing the last recipient while sending stays allowed is refused with the decided sentence', async () => {
    const before = await pendingCount();
    const r = await tool('setup__change_mandate', { mandate_id: domainMandate, scope: { allowed_domains: '' } });
    expect(r.denied).toBe(true);
    expect(r.text).toContain(BUILD_REFUSAL);
    expect(await pendingCount()).toBe(before);
    await revoke(domainMandate);
  }, 30_000);

  it('a 0.10 mandate signed directly with neither field: the Gatekeeper refuses at send — nothing sent, no ticket, recorded under Blocked', async () => {
    const id = await grant(EMAIL_10, EMAIL_KEYS, { ...LIMITS, read_max_age_days: 30 }, {}, EMAIL_SCOPE_KEYS, 'automatic', 'E2E: a mandate signed elsewhere, naming no one.');
    expect((await activeEmail()).map((m) => m.authorization_id)).toEqual([id]);
    await new Promise((r) => setTimeout(r, 800));
    const sent = await sentCount();
    const s = await send('jemand@irgendwo.example');
    expect(s.denied).toBe(true);
    // The gateway may append its own "mandates changed" note after the refusal.
    expect(s.text.startsWith(`${SEND_REFUSAL} Nothing ran.`), s.text).toBe(true);
    expect(await sentCount()).toBe(sent);
    expect(await ticketsFor(id)).toBe(0);
    const blocked = await cp.authed(owner.apiKey, 'GET', '/denials');
    expect(blocked.status).toBe(200);
    expect(JSON.stringify(await blocked.json())).toContain(SEND_REFUSAL);
    await revoke(id);
  }, 60_000);

  it('an email@0.9 mandate with neither field (an open one) still sends', async () => {
    const id = await grant(EMAIL_09, EMAIL_KEYS, { ...LIMITS, read_max_age_days: 30 }, {}, EMAIL_SCOPE_KEYS, 'automatic', 'E2E: an open 0.9 mandate from before.');
    await new Promise((r) => setTimeout(r, 800));
    const sent = await sentCount();
    const s = await send('jemand@irgendwo.example');
    expect(s.denied, s.text).toBe(false);
    expect(await sentCount()).toBe(sent + 1);
    expect(await ticketsFor(id)).toBe(1);
    await revoke(id);
  }, 60_000);
});
