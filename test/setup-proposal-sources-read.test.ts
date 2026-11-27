/**
 * Walkthrough 2026-11-11 (real ChatGPT): (1) asked to set up email with images, the AI proposed an
 * Email mandate without the saved-files source, so every attachment was refused later; (2) it proposed
 * a CRM mandate with read access "none", so it could not check its own update.
 *
 * Real stack, outside simulation: Authority Server, control plane, MCP server, shipped manifests and
 * profiles, the AI's own MCP connection. What must hold:
 * - list-authorizations(domain: "email") names every attachable source by its title, what it holds
 *   (Saved files: "... images ..."), and says to include the one the work attaches;
 * - the field list marks the read switch's declared default and why reading is needed;
 * - an Email proposal with files:file carries it to the card; a Customers proposal that leaves out
 *   read access is proposed — and signed — with the profile's default, shown on the card first.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
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
import { e2ePort } from '../src/helpers/ports.js';

const AS_PORT = e2ePort(19870);
const CP_PORT = e2ePort(19871);
const MCP_PORT = e2ePort(19872);
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const DELEGATION = `${P}/delegation@0.6`;
const available = existsSync(join(PROFILES_DIR, 'delegation', '0.6.profile.json'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-srcread-'));
const stack: StackOptions = {
  dataDir, ports: { cp: CP_PORT, mcp: MCP_PORT }, secret: newSecret(), asUrl: AS_URL,
  extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
};
const cp = new ControlPlaneClient(CP_URL);
const mcpInternal = new GatewayClient(`http://localhost:${MCP_PORT}`, stack.secret);

let anna: { apiKey: string; user: { id: string; did: string } };
let agent: Client;

async function as(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}
async function pending(): Promise<Array<{ id: string; tool: string; status: string }>> {
  return ((await as('GET', '/api/proposals?domain=owner', anna.apiKey)).body.proposals ?? [])
    .filter((p: { status: string }) => p.status === 'pending');
}
async function call(tool: string, args: Record<string, unknown>) {
  const r = await agent.callTool({ name: tool, arguments: args });
  return { denied: r.isError === true, text: textOf(r) };
}
async function previewOf(proposalId: string) {
  const res = await cp.authed(anna.apiKey, 'GET', `/proposal-status/${proposalId}/preview`);
  return { status: res.status, body: await res.json().catch(() => null) as any };
}
async function gatewayMandates(): Promise<Record<string, string>> {
  const res = await fetch(`http://localhost:${MCP_PORT}/internal/gate-content`, { headers: { 'X-Internal-Secret': stack.secret } });
  const entries = ((await res.json()) as { entries?: Array<{ authorizationId: string; profileId: string }> }).entries ?? [];
  return Object.fromEntries(entries.map((e) => [e.authorizationId, e.profileId]));
}

describe.skipIf(!available)('Setup proposals: attachment sources named, read switch defaulted (real stack)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    anna = await sp.register('Anna SR', `anna-sr-${Date.now()}@test.local`);
    await startControlPlane(pm, stack);
    await startMcpServer(pm, stack);
    const login = await cp.login(anna.apiKey);
    expect(login.status, JSON.stringify(login.body)).toBe(200);

    const groupId = await sp.getPersonalGroupId(anna.apiKey);
    const bounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 10 };
    const keys = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];
    const scope = { allowed_profiles: 'email,customers', allowed_modes: 'review' };
    const boundsHash = computeBoundsHash(bounds, keys);
    const contextHash = computeScopeHash(scope, ['allowed_profiles', 'allowed_modes']);
    const gate = { intent: 'E2E: the AI may propose Email and Customers mandates in review mode.' };
    const att = await sp.submitMandate(anna.apiKey, {
      profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: groupId, bounds,
      bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: anna.user.did, commitment_mode: 'review',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: 'delegation-0.6' }),
    });
    await mcpInternal.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, DELEGATION, gate);

    await new Promise((r) => setTimeout(r, 1_500));
    agent = new Client({ name: 'setup-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
  }, 300_000);

  afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 30_000);

  it('the Email answer names every source by title and what it holds, and to include the one the work attaches', async () => {
    const r = await call('list-authorizations', { domain: 'email' });
    if (process.env.HAP_E2E_SHOW_CARD) console.error('[SR E2E] email answer:\n' + r.text);
    expect(r.text).toContain('Propose it with setup__create_mandate(profile: "email", ...)');
    expect(r.text).toContain('Saved files (files:file: Files your AI saved, such as PDFs, images, video and text)');
    expect(r.text).toContain('when the work attaches files, include the source they come from, or every attachment is refused');
    expect(r.text).toMatch(/read_access\* \(Read access\) = unlimited\|none \[default unlimited: keep it unless the person says otherwise; you need it to check your own results\]/);
  });

  it('the Customers answer marks the read switch, not the export switch', async () => {
    const r = await call('list-authorizations', { domain: 'customers' });
    expect(r.text).toContain('read_access* (Read access) = unlimited|none [default unlimited: keep it unless the person says otherwise; you need it to check your own results]');
    expect(r.text).toContain('export_access* (Export access) = allowed|none [default none]');
  });

  it('an Email proposal with the saved-files source carries it to the card', async () => {
    const r = await call('setup__create_mandate', {
      profile: 'email', mode: 'review', duration_hours: 720, title: 'Mails mit Bildern',
      limits: { read_access: 'unlimited', send_daily_max: 5, recipient_max: 3, setup_daily_max: 0 },
      scope: { allowed_domains: 'example.com', allowed_attachment_sources: 'files:file' },
      intent: 'Why — send customers the pictures they ask for.',
    });
    expect(r.denied, r.text).toBe(false);
    const [p] = await pending();
    const { status, body } = await previewOf(p.id);
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.body.structured.scope).toMatchObject({ 'Allowed attachment sources': 'files:file' });
    const res = await as('POST', `/api/proposals/${p.id}/resolve`, anna.apiKey, { action: 'reject', domain: 'owner', reason: 'e2e' });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
  }, 60_000);

  it('a Customers proposal without read access is proposed and signed with the profile default', async () => {
    const r = await call('setup__create_mandate', {
      profile: 'customers', mode: 'review', duration_hours: 720, title: 'CRM pflegen',
      limits: { export_access: 'none', write_daily_max: 5, delete_daily_max: 0, setup_daily_max: 0 },
      scope: { contact_type: 'customer' },
      intent: 'Why — keep customer records current after each call.',
    });
    expect(r.denied, r.text).toBe(false);
    const [p] = await pending();
    const { body } = await previewOf(p.id);
    expect(body.body.structured.limits).toMatchObject({ 'Read access': 'unlimited' });

    const before = new Set(Object.keys(await gatewayMandates()));
    const res = await as('POST', `/api/proposals/${p.id}/resolve`, anna.apiKey, { action: 'commit', domain: 'owner' });
    expect(res.status, JSON.stringify(res.body)).toBeLessThan(300);
    let created: string | undefined;
    const until = Date.now() + 25_000;
    while (!created && Date.now() < until) {
      created = Object.keys(await gatewayMandates()).find((id) => !before.has(id));
      if (!created) await new Promise((res2) => setTimeout(res2, 500));
    }
    expect(created, 'no mandate appeared after approval').toBeTruthy();
    const summary = await sp.getAuthorizationSummary(anna.apiKey, created!);
    // The AS recomputes the bounds hash from what it signed: it signed read_access at the profile default.
    const profileId = String(summary.body.profile_id);
    const def = JSON.parse(readFileSync(join(PROFILES_DIR, 'customers', `${profileId.split('@')[1]}.profile.json`), 'utf8'));
    const signed = { profile: profileId, read_access: 'unlimited', export_access: 'none', write_daily_max: 5, delete_daily_max: 0, setup_daily_max: 0 };
    expect(summary.body.bounds_hash).toBe(computeBoundsHash(signed, def.boundsSchema.keyOrder));
  }, 90_000);

  it('a value the AI sets, none included, is proposed as it is', async () => {
    const r = await call('setup__create_mandate', {
      profile: 'customers', mode: 'review', duration_hours: 720, title: 'CRM nur schreiben',
      limits: { read_access: 'none', export_access: 'none', write_daily_max: 5, delete_daily_max: 0, setup_daily_max: 0 },
      scope: { contact_type: 'customer' }, intent: 'Why — the person asked for no reading.',
    });
    expect(r.denied, r.text).toBe(false);
    const [p] = await pending();
    const { body } = await previewOf(p.id);
    expect(body.body.structured.limits).toMatchObject({ 'Read access': 'none' });
  }, 60_000);
});
