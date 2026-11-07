/**
 * Sealed-args rule (gateway PR #190) — the refused path, end to end.
 *
 * Where a tool's content is sealed, every argument the AI passes must be
 * bound and shown, a declared reference, or declared non-content by the
 * connector's manifest. Anything else would change what is sent without the
 * approver seeing it or the ticket sealing it, so the gateway refuses the call
 * BEFORE any proposal or ticket.
 *
 * Real stack, nothing mocked: Authority Server + control plane + MCP server +
 * the real records connector, gated under `publish` (text binding on
 * `content`) the way verification-footer-local.test.ts gates it, but with the
 * manifest declaring only `type` and `title` as non-content. `metadata` is
 * deliberately left undeclared. The test proves:
 *   - a call with only declared arguments runs and the Authority Server issues
 *     a ticket (positive control — the rule does not block normal use);
 *   - the same call plus the undeclared `metadata` is refused with the neutral
 *     text that names the argument and never echoes the content;
 *   - no proposal exists, the Authority Server issued NO new ticket, and the
 *     connector's own database has no new row (the downstream system's view);
 *   - the gateway's Blocked list (GET /denials) has one record of kind
 *     `unsealed_arg`, naming the argument but carrying no content.
 *
 * Runs only against a gateway that has the rule.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient, recordTitles } from '../src/helpers/gateway-stack.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

const SP_PORT = 18990;
const GW_PORT = 18991;
const CP_PORT = 18992;
const SP_URL = `http://localhost:${SP_PORT}`;
const GW_URL = `http://localhost:${GW_PORT}`;

const ROOT = join(import.meta.dirname, '..', '..');
const PROFILES_DIR = join(ROOT, 'hap-profiles');
const RECORDS_DIST = join(ROOT, 'hap-records-mcp', 'dist', 'index.js');
const HAS_RULE = existsSync(join(ROOT, 'suveren-gateway', 'apps', 'mcp-server', 'src', 'lib', 'sealed-args.ts'));

const PROFILE_ID = PROFILE_V07.publish;
const BOUNDS_KEY_ORDER = ['profile', 'post_daily_max', 'post_monthly_max'];
const BOUNDS = { profile: PROFILE_ID, post_daily_max: 10, post_monthly_max: 50 };
const CONTEXT_KEY_ORDER = ['allowed_platforms', 'content_type', 'audience'];
const CONTEXT = { allowed_platforms: 'linkedin', content_type: 'text', audience: 'public' };
const GATE_CONTENT = { intent: 'E2E: sealed-args rule — bounded public publishing.' };
const STATIC = { allowed_platforms: 'linkedin', content_type: 'text', audience: 'public', action_type: 'post' };

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);
const gw = new GatewayClient(GW_URL);
const cp = new ControlPlaneClient(`http://localhost:${CP_PORT}`);

let user: { id: string; name: string; email: string; did: string; apiKey: string };
let mcpClient: Client;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function call(tool: string, args: Record<string, unknown>) {
  const r = await mcpClient.callTool({ name: tool, arguments: args });
  const text = (r.content as Array<{ text?: string }>)?.map((c) => c.text ?? '').join('\n') ?? '';
  return { denied: r.isError === true, text };
}

async function ticketCount(): Promise<number> {
  return (await sp.getMyTicketsPage(user.apiKey, { limit: 200 })).tickets.length;
}

async function proposalCount(): Promise<number> {
  const res = await fetch(`${SP_URL}/api/proposals?domain=owner&status=all`, { headers: { 'X-API-Key': user.apiKey } });
  expect(res.status).toBe(200);
  return (((await res.json()) as { proposals?: unknown[] }).proposals ?? []).length;
}

async function blockedList(): Promise<Array<Record<string, any>>> {
  const res = await cp.authed(user.apiKey, 'GET', '/denials?limit=500');
  expect(res.status).toBe(200);
  return ((await res.json()) as { records?: Array<Record<string, any>> }).records ?? [];
}

beforeAll(async () => {
  execSync('npm run build', { cwd: join(ROOT, 'hap-records-mcp'), stdio: 'pipe', timeout: 120_000 });
  pm.buildGateway();
  await pm.startSP(SP_PORT);
  const result = await sp.register('Sealed Args Test', `sealed-args-${Date.now()}@test.local`);
  user = { ...result.user, apiKey: result.apiKey };
  const personalGroupId = await sp.getPersonalGroupId(user.apiKey);
  await pm.startGateway({ port: GW_PORT, cpPort: CP_PORT, spUrl: SP_URL, spApiKey: user.apiKey, profilesDir: PROFILES_DIR });

  const boundsHash = computeBoundsHash(BOUNDS, BOUNDS_KEY_ORDER);
  const contextHash = computeScopeHash(CONTEXT, CONTEXT_KEY_ORDER);
  const mandate = await sp.submitMandate(user.apiKey, {
    profile_id: PROFILE_ID,
    profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
    group_id: personalGroupId,
    bounds: BOUNDS,
    bounds_hash: boundsHash,
    scope_hash: contextHash,
    domain: 'owner',
    did: user.did,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent(GATE_CONTENT),
    execution_context_hash: hashExecutionContext({
      ...CONTEXT, post_count_daily: BOUNDS.post_daily_max, post_count_monthly: BOUNDS.post_monthly_max,
    }),
  });
  await gw.configure({ sessionCookie: 'sealed-args-test', apiKey: user.apiKey });
  await gw.pushGateContent(
    { authorizationId: mandate.authorization_id, boundsHash, contextHash, context: CONTEXT },
    PROFILE_ID, GATE_CONTENT,
  );

  const added = await gw.addIntegration({
    id: 'recordspublish',
    name: 'Records',
    command: 'node',
    args: [RECORDS_DIST],
    envKeys: {},
    profile: 'publish',
    enabled: true,
    toolGating: {
      default: { executionMapping: {}, staticExecution: STATIC },
      overrides: {
        // `content` is the bound text; `type` and `title` are declared
        // non-content (the connector requires `type`); `metadata` is NOT
        // declared anywhere — the argument the rule must refuse.
        create_record: { executionMapping: {}, staticExecution: STATIC, message: { text: 'content', verb: 'Published' }, nonContentArgs: ['type', 'title'] },
      },
    },
  });
  expect(added.ok).toBe(true);
  await sleep(4_000);

  mcpClient = new Client({ name: 'sealed-args-e2e', version: '0.1.0' }, { capabilities: {} });
  await mcpClient.connect(new SSEClientTransport(new URL(`${GW_URL}/sse`)));
}, 240_000);

afterAll(async () => {
  if (mcpClient) { try { await mcpClient.close(); } catch { /* ignore */ } }
  await pm.killAll();
}, 30_000);

describe.skipIf(!HAS_RULE)('Sealed-args rule — refused path (real gateway, real records connector, real Authority Server)', () => {
  let ticketsBefore = 0;

  it('positive control: only declared arguments (content bound, title non-content) run and get a ticket', async () => {
    const t0 = await ticketCount();
    const r = await call('recordspublish__create_record', { type: 'note', title: 'Declared only', content: 'DECLARED-ONLY-CONTENT announcement.' });
    expect(r.denied, r.text).toBe(false);
    expect(await ticketCount()).toBe(t0 + 1);
    expect(await recordTitles(pm.getDataDir())).toContain('Declared only');
    ticketsBefore = t0 + 1;
  });

  it('an undeclared argument is refused with neutral text that names the argument, never the content', async () => {
    const r = await call('recordspublish__create_record', {
      type: 'note', title: 'Smuggled', content: 'SECRET-BODY-TEXT must never be echoed.',
      metadata: { url: 'https://unseen.example/payload' },
    });
    expect(r.denied).toBe(true);
    expect(r.text).toContain('"metadata"');
    expect(r.text).toMatch(/would change what is sent without being shown to the approver or sealed in the ticket/);
    expect(r.text).toContain('No ticket was requested');
    expect(r.text).toContain('Call it again without that argument');
    expect(r.text).not.toContain('SECRET-BODY-TEXT');
    // Not the title either: only the argument's name is named.
    expect(r.text).not.toContain('Smuggled');
    expect(r.text).not.toContain('unseen.example');
  });

  it('no proposal was made, the Authority Server issued no ticket, and nothing reached the connector', async () => {
    expect(await proposalCount()).toBe(0);
    expect(await ticketCount()).toBe(ticketsBefore);
    const titles = await recordTitles(pm.getDataDir());
    expect(titles).toContain('Declared only');
    expect(titles).not.toContain('Smuggled');
  });

  it('the gateway\'s Blocked list has a record of kind unsealed_arg naming the argument, without content', async () => {
    const blocked = (await blockedList()).filter((d) => d.kind === 'unsealed_arg');
    expect(blocked).toHaveLength(1);
    const [rec] = blocked;
    expect(rec.tool).toBe('create_record');
    expect(rec.integrationId).toBe('recordspublish');
    expect(rec.code).toBe('UNSEALED_ARG');
    expect(rec.who).toBe('gateway');
    expect(rec.field).toBe('metadata');
    expect(JSON.stringify(rec)).not.toContain('SECRET-BODY-TEXT');
    expect(JSON.stringify(rec)).not.toContain('Smuggled');
    expect(JSON.stringify(rec)).not.toContain('unseen.example');
  });
});
