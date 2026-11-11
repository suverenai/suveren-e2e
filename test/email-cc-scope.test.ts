/**
 * Every recipient of an email is counted and checked — `cc` as well as `to`.
 *
 * The mail manifest used to map only `to` to the recipient count and the
 * recipient/domain scope, so under an automatic Email mandate an AI could send
 * to any address through `cc`. On the real stack in simulation mode: Authority
 * Server (serving the local hap-profiles, incl. email@0.10), the whole gateway
 * (control plane + MCP server), the published email-mcp with its practice
 * mailbox. Nothing is mocked.
 *
 * What must hold:
 *  - allowed_domains example.com: `to` inside and `cc` outside is refused —
 *    nothing sent, no ticket;
 *  - all recipients inside: sent, the cc reaches the message, and the ticket's
 *    recipient_count is to + cc;
 *  - recipient_max counts to + cc: one `to` and two `cc` under a limit of 2 is
 *    refused;
 *  - allowed_recipients: a `cc` address not on the list is refused;
 *  - the connector has no bcc argument; one passed anyway is refused before any
 *    ticket;
 *  - an entry that holds more than one address ("x@evil.example,a@example.com",
 *    "x@evil.example <a@example.com>") is refused by the gate — nothing sent, no
 *    ticket.
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
import { profileHashFor } from '../src/helpers/profiles.js';

// 18710–18719 belong to this file.
const AS_PORT = 18710;
const PORTS = { cp: 18711, mcp: 18712 };
const AS_URL = `http://localhost:${AS_PORT}`;
const EMAIL_10 = 'github.com/humanagencyprotocol/hap-profiles/email@0.10';
const available = existsSync(join(PROFILES_DIR, 'email', '0.10.profile.json'));
if (!available) console.warn('[EMAIL CC SCOPE E2E] SKIPPED — needs hap-profiles email@0.10.');

const EMAIL_KEYS = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const EMAIL_SCOPE_KEYS = ['allowed_recipients', 'allowed_domains', 'allowed_attachment_sources'];
const LIMITS = { read_access: 'unlimited', recipient_max: 2, send_daily_max: 10, setup_daily_max: 0, read_max_age_days: 30 };

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

/** An automatic Email mandate signed straight against the Authority Server, its scope pushed to the gateway. */
async function grant(scope: Record<string, string>, intent: string): Promise<string> {
  const b = { profile: EMAIL_10, ...LIMITS };
  const boundsHash = computeBoundsHash(b, EMAIL_KEYS);
  const contextHash = computeScopeHash(scope, EMAIL_SCOPE_KEYS);
  const gate = { intent };
  const att = await sp.submitMandate(owner.apiKey, {
    profile_id: EMAIL_10, profile_hash: profileHashFor(EMAIL_10, PROFILES_DIR), group_id: groupId, bounds: b, bounds_hash: boundsHash, scope_hash: contextHash,
    domain: 'owner', did: owner.user.did, commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: EMAIL_10 }),
  });
  await mcp.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, EMAIL_10, gate);
  await new Promise((r) => setTimeout(r, 800));
  return att.authorization_id;
}

async function revoke(id: string) {
  const res = await fetch(`${AS_URL}/api/authorizations/${id}/revoke`, {
    method: 'POST', headers: { 'X-API-Key': owner.apiKey, 'Content-Type': 'application/json' }, body: JSON.stringify({ reason: 'test' }),
  });
  expect(res.status).toBeLessThan(300);
  const r = await cp.authed(owner.apiKey, 'POST', '/resync-gates');
  expect(r.status, await r.text()).toBeLessThan(300);
  await new Promise((res2) => setTimeout(res2, 800));
}

/** Sent messages, newest first (list_messages). */
async function sent(): Promise<Array<{ id: string; to?: string[]; subject?: string }>> {
  const r = await mailbox.callTool({ name: 'list_messages', arguments: { folder: 'sent' } });
  const list = JSON.parse(((r.content as Array<{ text?: string }>)?.[0]?.text ?? '[]'));
  return Array.isArray(list) ? list : list.messages ?? [];
}

async function ticketsFor(id: string): Promise<Array<Record<string, unknown>>> {
  const { tickets } = await sp.getMyTicketsPage(owner.apiKey, { limit: 100 });
  return tickets.filter((t) => JSON.stringify(t).includes(id));
}

/** The first value under `key` anywhere in a ticket record (its signed execution context sits a level or two down). */
function find(obj: unknown, key: string): unknown {
  if (!obj || typeof obj !== 'object') return undefined;
  if (key in (obj as Record<string, unknown>)) return (obj as Record<string, unknown>)[key];
  for (const v of Object.values(obj as Record<string, unknown>)) {
    const hit = find(typeof v === 'string' && v.startsWith('{') ? (() => { try { return JSON.parse(v); } catch { return undefined; } })() : v, key);
    if (hit !== undefined) return hit;
  }
  return undefined;
}

async function send(args: Record<string, unknown>) {
  const r = await agent.callTool({ name: 'mail__send_message', arguments: { subject: 'Termin', body: 'Guten Tag, ein Test der Suveren-E2E-Suite.', ...args } });
  return { denied: r.isError === true, text: textOf(r) };
}

describe.skipIf(!available)('every recipient of an email is counted and checked, cc too (real stack, simulation)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    owner = await sp.register('Erika Cc', `erika-cc-${Date.now()}@test.local`) as unknown as Account;
    groupId = await sp.getPersonalGroupId(owner.apiKey);
    stack = {
      dataDir: mkdtempSync(join(tmpdir(), 'hap-e2e-cc-scope-')), ports: PORTS, secret: newSecret(), asUrl: AS_URL,
      extraEnv: { SUVEREN_SIMULATION: '1', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
    };
    await startControlPlane(pm, stack, 'cp-cc');
    await startMcpServer(pm, stack, 'mcp-cc');
    cp = new ControlPlaneClient(`http://localhost:${PORTS.cp}`);
    expect((await cp.login(owner.apiKey)).status).toBe(200);
    mcp = new GatewayClient(`http://localhost:${PORTS.mcp}`, stack.secret);

    const act = await cp.authed(owner.apiKey, 'POST', '/mcp/integrations/mail/activate');
    expect(act.status, await act.text()).toBe(200);
    await mcp.waitForIntegration('mail');

    const mailBin = join(stack.dataDir, 'integrations', 'node_modules', '@humanagencyp', 'email-mcp', 'dist', 'index.js');
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'DATABASE_URL') env[k] = v;
    mailbox = new Client({ name: 'operator-mailbox', version: '1.0.0' }, { capabilities: {} });
    await mailbox.connect(new StdioClientTransport({ command: process.execPath, args: [mailBin], env: { ...env, HAP_DATA_DIR: stack.dataDir } }));

    await new Promise((r) => setTimeout(r, 1_500));
    agent = new Client({ name: 'cc-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${PORTS.mcp}/sse`)));
  }, 300_000);

  afterAll(async () => {
    for (const c of [agent, mailbox]) if (c) await c.close().catch(() => {});
    await pm.stopProcess('mcp-cc').catch(() => {});
    await pm.stopProcess('cp-cc').catch(() => {});
    await pm.killAll();
    if (stack) rmSync(stack.dataDir, { recursive: true, force: true });
  }, 30_000);

  describe('allowed_domains example.com', () => {
    let id = '';
    beforeAll(async () => { id = await grant({ allowed_domains: 'example.com' }, 'E2E: write to example.com only.'); }, 60_000);
    afterAll(async () => { if (id) await revoke(id); }, 30_000);

    it('to inside and cc outside is refused: nothing sent, no ticket', async () => {
      const before = (await sent()).length;
      const r = await send({ to: ['kunde@example.com'], cc: ['fremd@outside.example'] });
      expect(r.denied, r.text).toBe(true);
      expect(r.text).toMatch(/allowed_domains|domain/i);
      expect((await sent()).length).toBe(before);
      expect(await ticketsFor(id)).toHaveLength(0);
    }, 60_000);

    it('all recipients inside: sent with the cc, and the ticket counts to + cc', async () => {
      const before = (await sent()).length;
      const r = await send({ to: ['kunde@example.com'], cc: ['buchhaltung@example.com'] });
      expect(r.denied, r.text).toBe(false);
      const list = await sent();
      expect(list.length).toBe(before + 1);
      // The list shows `to` only; the message itself carries the cc.
      const newest = list[0];
      const got = await mailbox.callTool({ name: 'get_message', arguments: { id: newest.id } });
      const msg = JSON.parse(((got.content as Array<{ text?: string }>)?.[0]?.text ?? '{}'));
      expect(msg.cc, JSON.stringify(msg)).toEqual(['buchhaltung@example.com']);
      const tickets = await ticketsFor(id);
      expect(tickets).toHaveLength(1);
      expect(Number(find(tickets[0], 'recipient_count')), JSON.stringify(tickets[0])).toBe(2);
    }, 60_000);

    it('recipient_max counts to + cc: one to and two cc under a limit of 2 is refused, nothing sent', async () => {
      const before = (await sent()).length;
      const ticketsBefore = (await ticketsFor(id)).length;
      const r = await send({ to: ['kunde@example.com'], cc: ['a@example.com', 'b@example.com'] });
      expect(r.denied, r.text).toBe(true);
      expect(r.text).toMatch(/recipient/i);
      expect((await sent()).length).toBe(before);
      expect(await ticketsFor(id)).toHaveLength(ticketsBefore);
    }, 60_000);

    // One entry, two addresses: `join` would split it on the comma and
    // `join_domains` read only the text after the last "@" — so it would count
    // as one recipient in example.com. The gate refuses it itself, whatever the
    // connector's own format check does later.
    for (const [label, args] of [
      ['a to entry holding two addresses', { to: ['x@evil.example,kunde@example.com'] }],
      ['a cc entry with a display-name form', { to: ['kunde@example.com'], cc: ['x@evil.example <kunde@example.com>'] }],
    ] as const) {
      it(`${label} is refused at the gate: nothing sent, no ticket`, async () => {
        const before = (await sent()).length;
        const ticketsBefore = (await ticketsFor(id)).length;
        const r = await send(args);
        expect(r.denied, r.text).toBe(true);
        expect((await sent()).length).toBe(before);
        expect(await ticketsFor(id), 'a ticket was issued for it').toHaveLength(ticketsBefore);
        expect(r.text).toContain('is not one email address. Give one plain address per entry');
      }, 60_000);
    }

    it('a bcc (the connector has none) is refused before any ticket', async () => {
      const before = (await sent()).length;
      const ticketsBefore = (await ticketsFor(id)).length;
      const r = await send({ to: ['kunde@example.com'], bcc: ['fremd@outside.example'] });
      expect(r.denied, r.text).toBe(true);
      expect((await sent()).length).toBe(before);
      expect(await ticketsFor(id)).toHaveLength(ticketsBefore);
    }, 60_000);
  });

  describe('allowed_recipients one address', () => {
    let id = '';
    beforeAll(async () => { id = await grant({ allowed_recipients: 'kunde@example.com' }, 'E2E: write to one customer only.'); }, 60_000);
    afterAll(async () => { if (id) await revoke(id); }, 30_000);

    it('a cc not on the list is refused: nothing sent, no ticket', async () => {
      const before = (await sent()).length;
      const r = await send({ to: ['kunde@example.com'], cc: ['chef@example.com'] });
      expect(r.denied, r.text).toBe(true);
      expect((await sent()).length).toBe(before);
      expect(await ticketsFor(id)).toHaveLength(0);
    }, 60_000);
  });
});
