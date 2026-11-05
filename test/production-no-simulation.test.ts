/**
 * A gateway is EITHER in simulation mode OR in production — never both
 * (gateway fix/production-no-simulation).
 *
 * The existing half (simulation-mode.test.ts): in simulation mode a connector
 * whose current mode is not simulated is paused ('simulation').
 *
 * The half pinned here: in PRODUCTION (no SUVEREN_SIMULATION), a connector
 * whose CURRENT mode is simulated does not start. The crm connector at its
 * default mode — no saved `mode` — is simulated, so:
 *   1. its status is paused: 'production', not running, and not an error;
 *   2. its tools are not offered (a connector that never started has none) and
 *      a call reaches nothing: the Authority Server is never asked for a ticket;
 *   3. once its settings say "simulation" again, it is paused "production" again
 *      and a call from a still-connected session fails closed, no ticket (last
 *      test). The neutral "is not available. No ticket was requested." refusal
 *      (+ blocked-action record) of tool-proxy.ts is decided when a session
 *      registers a tool, and a simulated connector in production has no tools
 *      to register — it is covered by the gateway's own unit test
 *      (simulation-tool-proxy.test.ts), not reachable end to end;
 *   4. the mode is read from the connector's SAVED settings (vault
 *      credentials, field `mode`): saving mode=live + liveAdapter=local and
 *      activating the connector again starts it, and the same call then works
 *      (and is the one that asks for a ticket).
 *
 * Real AS, real gateway (control plane + MCP server), the real crm-mcp the
 * shipped manifest pins. Nothing is mocked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient, PROFILES_DIR } from '../src/helpers/gateway-stack.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

const AS_PORT = 19960;
const MCP_PORT = 19961;
const CP_PORT = 19962;
const AS_URL = `http://localhost:${AS_PORT}`;
const MCP_URL = `http://localhost:${MCP_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;

const PROFILE = PROFILE_V07.customers;
const KEYS = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const BOUNDS = { profile: PROFILE, read_access: 'unlimited', export_access: 'none', write_daily_max: 10, delete_daily_max: 5, setup_daily_max: 0 };
const SCOPE = { contact_type: 'customer' };


const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const gw = new GatewayClient(MCP_URL);
const cp = new ControlPlaneClient(CP_URL);

let apiKey: string;
let agent: Client;

async function ticketCount(): Promise<number> {
  return (await sp.getMyTicketsPage(apiKey, { limit: 100 })).tickets.length;
}

async function callCreateContact(name: string) {
  const r = await agent.callTool({ name: 'crm__create_contact', arguments: { name, type: 'customer' } });
  return { denied: r.isError === true, text: (r.content as Array<{ text?: string }>)?.map((c) => c.text ?? '').join('\n') ?? '' };
}

describe('production gateway: a simulated connector does not start (real AS + gateway + crm-mcp)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    const reg = await sp.register('Production No Simulation', `prod-nosim-${Date.now()}@test.local`);
    apiKey = reg.apiKey;
    const groupId = await sp.getPersonalGroupId(apiKey);

    // Production: no `simulation: true`. Only crm is of interest here.
    const prevAuto = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    await pm.startGateway({ port: MCP_PORT, cpPort: CP_PORT, spUrl: AS_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
    if (prevAuto !== undefined) process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = prevAuto;
    await gw.configure({ sessionCookie: 'prod-nosim-e2e', apiKey });

    // A mandate that covers the call: the refusal below is NOT a missing mandate.
    const boundsHash = computeBoundsHash(BOUNDS, KEYS);
    const contextHash = computeScopeHash(SCOPE, ['contact_type']);
    const gate = { intent: 'E2E: production without simulation' };
    const att = await sp.submitMandate(apiKey, {
      profile_id: PROFILE, profile_hash: profileHashFor(PROFILE, PROFILES_DIR), group_id: groupId,
      bounds: BOUNDS, bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: reg.user.did,
      commitment_mode: 'automatic', gate_content_hashes: hashGateContent(gate),
      execution_context_hash: hashExecutionContext({ intent: 'prod-nosim' }),
    });
    await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: SCOPE }, PROFILE, gate);

    agent = new Client({ name: 'prod-nosim-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  }, 300_000);

  afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    await pm.killAll();
  }, 30_000);

  it('crm with no saved mode is paused "production": not running, and not reported as an error', async () => {
    let crm: Awaited<ReturnType<GatewayClient['integrations']>>[number] | undefined;
    for (let i = 0; i < 60 && !crm?.paused; i++) {
      crm = (await gw.integrations()).find((x) => x.id === 'crm');
      if (!crm?.paused) await new Promise((r) => setTimeout(r, 1_000));
    }
    expect(crm?.paused).toBe('production');
    expect(crm?.running).toBeFalsy();
    expect(crm?.error).toBeFalsy();
  });

  it('activating it from the manifest at its default mode does not start it either', async () => {
    const act = await cp.authed(apiKey, 'POST', '/mcp/integrations/crm/activate');
    expect(act.status).toBe(200);
    // Saved, but not started - and it says why, on the human side.
    expect(((await act.json()) as { warning?: string }).warning).toMatch(/failed to start: crm: blocked: simulated connector/);
    const crm = (await gw.integrations()).find((x) => x.id === 'crm');
    expect(crm?.running).toBeFalsy();
    expect(crm?.paused).toBe('production');
  });

  it('its tools are not offered, and a call to one reaches nothing: no ticket', async () => {
    const before = await ticketCount();
    const names = (await agent.listTools()).tools.map((t) => t.name);
    expect(names.some((n) => n.startsWith('crm__'))).toBe(false);
    const r = await callCreateContact('Must Not Exist');
    expect(r.denied, r.text).toBe(true);
    expect(r.text).toMatch(/Tool crm__create_contact not found/);
    expect(await ticketCount()).toBe(before);
  });

  it('saving mode=live + liveAdapter=local (the connector\'s own settings) and activating it starts the connector', async () => {
    const put = await cp.authed(apiKey, 'PUT', '/vault/credentials/crm', { mode: 'live', liveAdapter: 'local' });
    expect(put.status, await put.text()).toBe(200);
    const act = await cp.authed(apiKey, 'POST', '/mcp/integrations/crm/activate');
    expect(act.status, await act.text()).toBe(200);
    await gw.waitForIntegration('crm');
    const crm = (await gw.integrations()).find((x) => x.id === 'crm');
    expect(crm?.running).toBe(true);
    expect(crm?.paused).toBeFalsy();
    // A session learns the tool list when it connects: reconnect to see crm's tools.
    await agent.close().catch(() => {});
    agent = new Client({ name: 'prod-nosim-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
    expect((await agent.listTools()).tools.map((t) => t.name)).toContain('crm__create_contact');
  }, 180_000);

  it('the same call now reaches the connector and asks for a ticket', async () => {
    const before = await ticketCount();
    const r = await callCreateContact('Live Local Contact');
    expect(r.denied, r.text).toBe(false);
    expect(r.text).not.toMatch(/is not available/);
    expect(await ticketCount()).toBe(before + 1);
  }, 60_000);

  it('saving mode=simulation again: the connector is paused "production" again, and a call from the still-connected session fails closed — no ticket', async () => {
    const put = await cp.authed(apiKey, 'PUT', '/vault/credentials/crm', { mode: 'simulation' });
    expect(put.status, await put.text()).toBe(200);
    let crm: Awaited<ReturnType<GatewayClient['integrations']>>[number] | undefined;
    for (let i = 0; i < 40 && crm?.paused !== 'production'; i++) {
      crm = (await gw.integrations()).find((x) => x.id === 'crm');
      if (crm?.paused !== 'production') await new Promise((r) => setTimeout(r, 500));
    }
    expect(crm?.paused).toBe('production');
    expect(crm?.running).toBeFalsy();
    const before = await ticketCount();
    const r = await callCreateContact('Must Not Exist Either');
    // NOT the neutral "is not available" text: that refusal is decided when a session
    // registers the tool (tool-proxy.ts createGatedToolHandler), and this session
    // registered it while the connector was live. The stopped connector still refuses (its tool
    // is either gone from the session by now or answers "is not running").
    expect(r.denied, r.text).toBe(true);
    expect(r.text).toMatch(/Integration "crm" is not running\.|Tool crm__create_contact not found/);
    expect(await ticketCount()).toBe(before);
  }, 60_000);
});
