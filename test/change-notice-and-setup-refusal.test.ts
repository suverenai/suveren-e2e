/**
 * Two things an AI in a running chat must be told, proven on a real gateway and AS:
 *
 * The note (src/lib/change-notice.ts): after the brief is edited or a mandate is revoked
 * mid-session, the next tool answer carries one note — the current brief, the mandate by the title
 * the person gave — and the answer after that carries nothing. A refused call carries it too.
 * A new session of an app that last heard something else gets it as well (reconnect / resume).
 *
 * The refusal with Setup: a call no mandate covers. Without a Setup mandate the refusal names
 * the form; with a Setup mandate covering the area it says to prepare the mandate and does
 * not name the form.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import {
  ControlPlaneClient, ROOT, RECORDS_DIST, RECORDS_INTEGRATION, RECORDS_PROFILE_ID, PROFILES_DIR,
  newSecret, startControlPlane, startMcpServer, textOf, type StackOptions,
} from '../src/helpers/gateway-stack.js';
import { computeBoundsHash, computeScopeHash, hashGateContent, hashExecutionContext } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import { e2ePort } from '../src/helpers/ports.js';

const AS_PORT = e2ePort(18840);
const CP_PORT = e2ePort(18841);
const MCP_PORT = e2ePort(18842);
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const DELEGATION = 'github.com/humanagencyprotocol/hap-profiles/delegation@0.4';
const available = existsSync(join(PROFILES_DIR, 'delegation', '0.4.profile.json'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-note-'));
const stack: StackOptions = {
  dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret: newSecret(), asUrl: AS_URL,
  extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_PROFILES_DIR: PROFILES_DIR },
};
const cp = new ControlPlaneClient(CP_URL);
const internal = new GatewayClient(`http://localhost:${MCP_PORT}`, stack.secret);
let owner: { apiKey: string; user: { id: string; did: string } };
const appName = `note-app-${Date.now()}`;

async function connect(name: string): Promise<Client> {
  const c = new Client({ name, version: '1.0.0' }, { capabilities: {} });
  await c.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
  return c;
}
const listAuth = (c: Client) => c.callTool({ name: 'list-authorizations', arguments: {} });
const put = (content: string) => cp.authed(owner.apiKey, 'PUT', '/agent-brief/context', { content });

interface Grant { head: { authorizationId: string; boundsHash: string; contextHash: string; context: Record<string, string> }; profile: string; gate: { intent: string } }

async function grant(profile: string, bounds: Record<string, string | number>, boundKeys: string[], context: Record<string, string>, title: string, mode: 'automatic' | 'review'): Promise<Grant> {
  const groupId = await sp.getPersonalGroupId(owner.apiKey);
  const b = { profile, ...bounds };
  const boundsHash = computeBoundsHash(b, ['profile', ...boundKeys]);
  const contextHash = computeScopeHash(context, Object.keys(context));
  const gate = { intent: `E2E: ${title}.` };
  const res = await sp.submitMandateRaw(owner.apiKey, {
    authorization_id: `authz_${randomUUID()}`, profile_id: profile, profile_hash: profileHashFor(profile, PROFILES_DIR), group_id: groupId, bounds: b,
    bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: owner.user.did, commitment_mode: mode, title,
    gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: profile }),
  });
  expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
  const authorizationId = String(res.body.authorization_id);
  await internal.pushGateContent({ authorizationId, boundsHash, contextHash, context }, profile, gate);
  return { head: { authorizationId, boundsHash, contextHash, context }, profile, gate };
}

/** The gateway learns of a revocation when it next syncs that mandate; this does it the way the UI's refresh does. */
async function revoke(g: Grant): Promise<void> {
  await sp.revokeAuthorization(owner.apiKey, g.head.authorizationId);
  await internal.pushGateContent(g.head, g.profile, g.gate).catch(() => {});
}

describe.skipIf(!available)('the change note and the Setup refusal (real AS + gateway + connector)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    if (!existsSync(RECORDS_DIST)) execSync('npm run build', { cwd: join(ROOT, 'hap-records-mcp'), stdio: 'pipe', timeout: 120_000 });
    await pm.startSP(AS_PORT);
    owner = await sp.register('Note Owner', `note-${Date.now()}@test.local`);
    await startControlPlane(pm, stack);
    await startMcpServer(pm, stack);
    const login = await cp.login(owner.apiKey);
    expect(login.status, JSON.stringify(login.body)).toBe(200);
    if (!(await internal.integrations()).some((i: { id: string }) => i.id === 'records')) await internal.addIntegration(RECORDS_INTEGRATION);
    await internal.waitForIntegration('records');
  }, 300_000);

  afterAll(async () => {
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 30_000);

  let session: Client;
  const results: string[] = [];

  it('nothing changed: the first answers carry no note', async () => {
    await put('Brief one: only drafts.');
    session = await connect(appName);
    const a = await listAuth(session);
    expect(textOf(a)).not.toContain('[Suveren gateway]');
    const b = await listAuth(session);
    expect(textOf(b)).not.toContain('[Suveren gateway]');
  });

  it('the brief is edited mid-session: the next answer points to the current brief, once', async () => {
    const res = await put('Brief two: send only with an approval.');
    expect(res.status).toBeLessThan(300);
    const noted = await listAuth(session);
    expect(textOf(noted)).toContain('The agent brief changed since this chat started. Call list-authorizations() with no area to read the current one.');
    expect(textOf(noted).split('[Suveren gateway]')[1]).not.toContain('Brief two');
    // The AI follows the note to the gateway's own tool, and the current brief is there.
    expect(textOf(noted).split('[Suveren gateway]')[0]).toContain('Brief two: send only with an approval.');
    results.push(textOf(noted));
    const again = await listAuth(session);
    expect(textOf(again)).not.toContain('[Suveren gateway]');
  });

  it('a mandate is revoked mid-session: a refused call names it by its title, once', async () => {
    const g = await grant(RECORDS_PROFILE_ID, { read_access: 'unlimited', write_daily_max: 20, delete_access: 'allowed', archive_access: 'allowed' }, ['read_access', 'write_daily_max', 'delete_access', 'archive_access'], {}, 'Notes for the customer log', 'automatic');
    await new Promise((r) => setTimeout(r, 1_500));
    // The session already had a chance to learn it; the first answer after granting names it as added.
    const added = await listAuth(session);
    expect(textOf(added)).toContain('added "Notes for the customer log"');
    await revoke(g);
    await new Promise((r) => setTimeout(r, 1_000));
    const refused = await session.callTool({ name: 'records__create_record', arguments: { type: 'note', title: 'x', content: 'y' } });
    expect(refused.isError, textOf(refused)).toBe(true);
    expect(textOf(refused)).toMatch(/Refused/);
    expect(textOf(refused)).toContain('Mandates changed since this chat started: revoked "Notes for the customer log"');
    const again = await listAuth(session);
    expect(textOf(again)).not.toContain('[Suveren gateway]');
  });

  it('a reconnected session of the same app hears a change that happened meanwhile', async () => {
    await put('Brief three: reconnection test.');
    await session.close();
    const reconnected = await connect(appName);
    const a = await listAuth(reconnected);
    expect(textOf(a)).toContain('since this app last connected');
    expect(textOf(a)).toContain('Brief three: reconnection test.');
    const b = await listAuth(reconnected);
    expect(textOf(b)).not.toContain('[Suveren gateway]');
    await reconnected.close();
  });

  it('an app seen for the first time gets no note, whatever happened before', async () => {
    const fresh = await connect(`${appName}-fresh`);
    expect(textOf(await listAuth(fresh))).not.toContain('[Suveren gateway]');
    await fresh.close();
  });

  it('a note never appears in the proposals or tickets the person sees', async () => {
    const res = await fetch(`${AS_URL}/api/proposals?domain=owner`, { headers: { 'X-API-Key': owner.apiKey } });
    expect(JSON.stringify(await res.json())).not.toContain('Suveren gateway');
    const tickets = await sp.getMyTicketsPage(owner.apiKey, { limit: 50 });
    expect(JSON.stringify(tickets)).not.toContain('Suveren gateway');
    expect(results.length).toBeGreaterThan(0);
  });

  const SETUP_FORM = '**Mandates → + New mandate';
  const records = () => session.callTool({ name: 'records__create_record', arguments: { type: 'note', title: 't', content: 'c' } });

  it('without a Setup mandate the refusal names the form', async () => {
    session = await connect(`${appName}-setup`);
    const r = await records();
    expect(r.isError, textOf(r)).toBe(true);
    expect(textOf(r)).toContain(SETUP_FORM);
  });

  it('with a Setup mandate covering the area the refusal has the AI prepare it, and does not name the form', async () => {
    await grant(DELEGATION, { read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 5 }, ['read_access', 'brief_daily_max', 'mandate_daily_max'], { allowed_profiles: 'records', allowed_modes: 'review' }, 'Setup', 'review');
    await new Promise((r) => setTimeout(r, 1_500));
    const r = await records();
    const text = textOf(r);
    expect(r.isError, text).toBe(true);
    expect(text).toContain('You can prepare this mandate yourself, so do not send the person to the form.');
    expect(text).toContain('setup__create_mandate');
    expect(text).not.toContain(SETUP_FORM);
    await session.close();
  });
});
