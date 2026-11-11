/**
 * An AI app that loads the tool list ONCE, when the chat starts, and never again — as ChatGPT
 * Desktop does (Andreas, 2026-11-10: it ignores `tools/list_changed`; he had to restart it twice).
 * Tools that appear later — the Setup tools once Setup is signed, a connector that starts after
 * the chat — must still be reachable, through `call-tool`, with every check a direct call has.
 *
 * Real stack: Authority Server, the whole gateway (control plane + MCP server), the shipped `mail`
 * connector (email-mcp) in its test-mailbox mode. The suite has no Gmail account and email-mcp's
 * Gmail endpoints are fixed, so there is no Gmail stand-in: the mail connector is started AFTER the
 * chat began instead, which is what puts its tools out of a fixed list. Gmail as the data source is
 * proven in the Rehearsal. A gateway is either in simulation or in production; the test mailbox
 * runs on a simulation gateway.
 *
 * The flow, without the client ever listing tools again:
 *   empty gateway → chat starts → Setup is signed → the note names the new tools →
 *   the AI proposes an Email mandate through call-tool → the person approves →
 *   the mail connector starts → the note names its tools with their arguments; the app builds its
 *   send from that list alone → the send through call-tool is refused like a direct call (no Email
 *   mandate yet), never for its arguments; an internal tool and bad arguments are refused (the
 *   refusal names the arguments) → the Email mandate is approved → the same send becomes a
 *   proposal → approved → it runs, and the Authority Server holds its ticket.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { ToolListChangedNotificationSchema } from '@modelcontextprotocol/sdk/types.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient, PROFILES_DIR, newSecret, startControlPlane, startMcpServer, textOf, type StackOptions } from '../src/helpers/gateway-stack.js';
import { computeBoundsHash, computeScopeHash, hashGateContent, hashExecutionContext } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import { addMailConnector } from '../src/helpers/mail-connector.js';

const AS_PORT = 18880;
const CP_PORT = 18881;
const MCP_PORT = 18882;
const AS_URL = `http://localhost:${AS_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const DELEGATION = `${P}/delegation@0.6`;
const available = existsSync(join(PROFILES_DIR, 'delegation', '0.6.profile.json'));
const RECIPIENT = 'customer@example.com';

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-fixed-list-'));
const stack: StackOptions = {
  dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret: newSecret(), asUrl: AS_URL,
  extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_SIMULATION: '1' },
};
const cp = new ControlPlaneClient(`http://localhost:${CP_PORT}`);
const internal = new GatewayClient(`http://localhost:${MCP_PORT}`, stack.secret);
let owner: { apiKey: string; user: { id: string; did: string } };

/**
 * The app: it lists tools once, at the start, and from then on calls only what that list held.
 * Calling any other name, or listing again, fails the test — that is what ChatGPT does.
 */
class FixedListApp {
  readonly client = new Client({ name: 'fixed-list-app', version: '1.0.0' }, { capabilities: {} });
  names: string[] = [];
  listChanged = 0;
  async start(): Promise<void> {
    this.client.setNotificationHandler(ToolListChangedNotificationSchema, async () => { this.listChanged++; });
    await this.client.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
    this.names = (await this.client.listTools()).tools.map((t) => t.name);
    this.client.listTools = () => { throw new Error('this app never lists tools again'); };
  }
  async call(name: string, args: Record<string, unknown>): Promise<{ denied: boolean; text: string; all: string }> {
    if (!this.names.includes(name)) throw new Error(`"${name}" is not in the list this app loaded at the start`);
    const r = await this.client.callTool({ name, arguments: args });
    const all = ((r.content ?? []) as Array<{ text?: string }>).map((c) => c.text ?? '').join('\n');
    return { denied: r.isError === true, text: textOf(r), all };
  }
  through(tool: string, args: Record<string, unknown>) {
    return this.call('call-tool', { tool, arguments: args });
  }
}
const app = new FixedListApp();

async function as(method: string, path: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': owner.apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}

async function gatewayMandates(): Promise<Record<string, string>> {
  const res = await fetch(`http://localhost:${MCP_PORT}/internal/gate-content`, { headers: { 'X-Internal-Secret': stack.secret } });
  const entries = ((await res.json()) as { entries?: Array<{ authorizationId: string; profileId: string }> }).entries ?? [];
  return Object.fromEntries(entries.map((e) => [e.authorizationId, e.profileId]));
}

async function denials(): Promise<Array<{ tool: string; kind?: string; detail: string }>> {
  const res = await cp.authed(owner.apiKey, 'GET', '/denials');
  return ((await res.json()) as { records?: Array<{ tool: string; kind?: string; detail: string }> }).records ?? [];
}

/**
 * The person approves on their own device, as the approval card does: the gateway decrypts the
 * sealed content (checking it against its fingerprint), and the decision carries that fingerprint.
 */
async function approveAsTheCard(proposalId: string, expectText: string): Promise<void> {
  const p = ((await as('GET', '/api/proposals?domain=owner')).body.proposals ?? []).find((x: { id: string }) => x.id === proposalId);
  expect(p, `proposal ${proposalId} not listed`).toBeTruthy();
  const content = p.content as { ciphertext: string; keys?: unknown; encrypted_keys?: unknown; hash: string };
  const opened = await cp.authed(owner.apiKey, 'POST', '/api/decrypt-proposal-content', content);
  const body = await opened.json() as { plaintext?: string };
  expect(opened.status, JSON.stringify(body)).toBe(200);
  expect(body.plaintext).toContain(expectText);
  const res = await as('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner', proposalContentHash: content.hash });
  expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
}

const proposalIdOf = (text: string) => text.match(/Proposal ID: ([a-f0-9-]+)/)?.[1];

/** The person approves in the Authority Server; returns once the gateway holds the new mandate. */
async function approveMandate(proposalId: string): Promise<string> {
  const before = new Set(Object.keys(await gatewayMandates()));
  const res = await as('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner' });
  expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
  const until = Date.now() + 30_000;
  while (Date.now() < until) {
    const created = Object.keys(await gatewayMandates()).find((id) => !before.has(id));
    if (created) return created;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('no mandate appeared after approval');
}

describe.skipIf(!available)('an app that never re-lists tools reaches every tool through call-tool (real stack)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    owner = await sp.register('Fixed List Owner', `fixed-list-${Date.now()}@test.local`);
    await startControlPlane(pm, stack);
    await startMcpServer(pm, stack);
    const login = await cp.login(owner.apiKey);
    expect(login.status, JSON.stringify(login.body)).toBe(200);
  }, 300_000);

  afterAll(async () => {
    await app.client.close().catch(() => {});
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 30_000);

  it('the chat starts on an empty gateway: call-tool is listed, the Setup and mail tools are not', async () => {
    await app.start();
    expect(app.names).toContain('call-tool');
    expect(app.names).toContain('list-authorizations');
    expect(app.names).not.toContain('setup__create_mandate');
    expect(app.names.some((n) => n.startsWith('mail__'))).toBe(false);
  });

  it('Setup is signed mid-chat: the next answer names the new Setup tools and how to reach them, once', async () => {
    const groupId = await sp.getPersonalGroupId(owner.apiKey);
    const bounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 5 };
    const keys = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];
    const scope = { allowed_profiles: 'email', allowed_modes: 'review' };
    const boundsHash = computeBoundsHash(bounds, keys);
    const contextHash = computeScopeHash(scope, ['allowed_profiles', 'allowed_modes']);
    const gate = { intent: 'E2E: the AI prepares my mandates; I approve each one.' };
    const att = await sp.submitMandate(owner.apiKey, {
      profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: groupId, bounds,
      bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: owner.user.did, commitment_mode: 'review',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: 'delegation-0.6' }),
    });
    await internal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, DELEGATION, gate);
    await new Promise((r) => setTimeout(r, 1_500));

    const r = await app.call('list-authorizations', {});
    expect(r.all).toMatch(/\[Suveren gateway\][^\n]*\n\nNew tools since this chat started: [^\n]*setup__create_mandate\(profile, [^)]*\)/);
    expect(r.all).toMatch(/New tools since this chat started: [^\n]*\. If they are not in your tool list, call them through call-tool\.$/m);
    // The internal preview tools are never named.
    expect(r.all).not.toContain('describe_mandate_proposal');
    // The gateway did announce the change; this app ignored it, like ChatGPT.
    expect(app.listChanged).toBeGreaterThan(0);
    expect(app.names).not.toContain('setup__create_mandate');
  });

  let emailProposal = '';

  it('the AI prepares an Email mandate through call-tool; it waits for the person', async () => {
    const r = await app.through('setup__create_mandate', {
      profile: 'email',
      limits: { read_access: 'unlimited', recipient_max: 1, send_daily_max: 5, setup_daily_max: 0 },
      scope: { allowed_recipients: RECIPIENT },
      mode: 'review', duration_hours: 720, title: 'Customer replies',
      intent: 'Answer customer emails the same day.',
    });
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toContain('Awaiting commitment');
    emailProposal = proposalIdOf(r.text) ?? '';
    expect(emailProposal).not.toBe('');
  }, 60_000);

  it('the mail connector starts after the chat began: the note names its tools', async () => {
    await addMailConnector(internal, { readAgeDays: 30 });
    await new Promise((r) => setTimeout(r, 1_000));
    const r = await app.call('list-authorizations', { domain: 'email' });
    expect(r.all).toMatch(/New tools since this chat started: [^\n]*mail__send_message\(/);
    // The hint is said once per chat, not again.
    expect(r.all).not.toContain('call them through call-tool');
    // The app builds its send from the note alone: the required arguments, by name.
    const sig = r.all.match(/mail__send_message\(([^)]*)\)/)?.[1];
    expect(sig, r.all).toBeTruthy();
    const args = sig!.split(', ').filter(Boolean);
    const required = args.filter((a) => !a.endsWith('?'));
    // A list argument is marked `[]`: the one type real AIs got wrong without it.
    expect(required).toEqual(['to[]', 'subject', 'body']);
    // No other types and no descriptions in it.
    expect(sig).not.toMatch(/[:{]/);
    // Plain values by name, as a person would say them; the app makes a list only where the note says `[]`.
    const values: Record<string, string> = { to: RECIPIENT, subject: 'Your question', body: 'Thank you, we will answer tomorrow. (Sent by an AI.)' };
    SEND = Object.fromEntries(required.map((a) => (a.endsWith('[]') ? [a.slice(0, -2), [values[a.slice(0, -2)]]] : [a, values[a]])));
    // The area's answer names the exact tool name and how to reach it.
    expect(r.text).toContain('If a tool named here is not in your tool list, call it through call-tool(tool: "<exact name>", arguments: {...}).');
    expect(app.names.some((n) => n.startsWith('mail__'))).toBe(false);
  }, 180_000);

  /** Built from the argument list in the note (above), not known to the app in advance. */
  let SEND: Record<string, unknown> = {};
  let sendAttempts = 0;

  it('without an Email mandate, a send through call-tool is refused exactly like a direct call, and both are Blocked', async () => {
    const direct = new Client({ name: 'direct-app', version: '1.0.0' }, { capabilities: {} });
    await direct.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
    const before = (await denials()).length;
    const d = await direct.callTool({ name: 'mail__send_message', arguments: SEND });
    const t = await app.through('mail__send_message', SEND);
    sendAttempts++;
    await direct.close();
    expect(d.isError, textOf(d)).toBe(true);
    expect(t.denied, t.text).toBe(true);
    expect(t.text).toBe(textOf(d));
    // Refused for the missing mandate, never for its arguments: the note's list was enough.
    expect(t.text).not.toContain('do not fit');
    expect(t.text).not.toContain('does not offer');
    const after = await denials();
    expect(after.length - before).toBe(2);
    // Both recorded under Blocked, the same way.
    expect([after[0].tool, after[0].kind, after[0].detail]).toEqual([after[1].tool, after[1].kind, after[1].detail]);
    const tickets = (await sp.getMyTicketsPage(owner.apiKey, { limit: 50 })).tickets;
    expect(tickets).toHaveLength(0);
  }, 60_000);

  it('an internal tool name is refused as not there', async () => {
    const r = await app.through('setup__describe_mandate_proposal', { profile: 'email' });
    expect(r.denied).toBe(true);
    expect(r.text).toBe('Refused: there is no tool "setup__describe_mandate_proposal" here. Nothing was done and no ticket was requested. Use a tool name exactly as the gateway names it; list-authorizations(domain) names the tools of an area.');
  });

  it('bad arguments are refused by the target tool\'s own schema', async () => {
    const before = (await as('GET', '/api/proposals?domain=owner')).body.proposals?.length ?? 0;
    const r = await app.through('mail__send_message', { to: RECIPIENT, subject: 1, body: 'x' });
    expect(r.denied).toBe(true);
    expect(r.text).toMatch(/^Refused: the arguments do not fit "mail__send_message": /);
    expect(r.text).toContain('no ticket was requested');
    // The refusal names the tool's arguments, as the note did.
    expect(r.text).toMatch(/Call it again with the arguments that tool takes: mail__send_message\(to\[\], subject, body[^)]*\)\.$/);
    expect((await as('GET', '/api/proposals?domain=owner')).body.proposals?.length ?? 0).toBe(before);
  });

  it('the person approves the Email mandate; a send through call-tool becomes a proposal, runs once approved, and is ticketed', async () => {
    const mandateId = await approveMandate(emailProposal);
    expect((await gatewayMandates())[mandateId]).toMatch(/\/email@/);
    await new Promise((r) => setTimeout(r, 1_000));

    const sent = await app.through('mail__send_message', SEND);
    sendAttempts++;
    expect(sent.denied, sent.text).toBe(false);
    // The same arguments, built from the note: no attempt was ever refused for them.
    expect(sendAttempts).toBe(2);
    expect(sent.text).toContain('Awaiting commitment');
    const sendProposal = proposalIdOf(sent.text)!;
    expect(sendProposal).toBeTruthy();

    await approveAsTheCard(sendProposal, 'Your question');
    const done = await app.call('check-pending-commitments', { proposal_id: sendProposal, wait_seconds: 30 });
    let text = done.text;
    const until = Date.now() + 30_000;
    while (!/executed/i.test(text) && Date.now() < until) {
      await new Promise((r) => setTimeout(r, 1_000));
      text = (await app.call('check-pending-commitments', { proposal_id: sendProposal })).text;
    }
    expect(text).toMatch(/executed/i);

    const tickets = (await sp.getMyTicketsPage(owner.apiKey, { limit: 50 })).tickets;
    expect(tickets.length, JSON.stringify(tickets)).toBeGreaterThan(0);
    expect(JSON.stringify(tickets)).toContain(mandateId);

    // The mail is in the mailbox's sent items, read through call-tool too.
    const box = await app.through('mail__list_messages', { folder: 'sent' });
    expect(box.denied, box.text).toBe(false);
    expect(box.text).toContain('Your question');
  }, 120_000);
});
