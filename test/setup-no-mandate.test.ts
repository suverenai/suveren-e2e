/**
 * Delegation / Setup tools with no Setup mandate: the AI is told, in one fixed
 * text, what the person can do — and nothing runs.
 *
 * Real AS + real gateway (production), a Delegation mandate that is REVOKED after
 * the agent connected. (Without any Setup mandate the Setup tools are not even
 * listed — hideUnlessAuthorized — so a first-time call is "Tool not found". The
 * text is reached by a session that listed the tool while a mandate existed.)
 * Once the gateway no longer holds an eligible mandate, a call to
 * setup__create_mandate must:
 *   - be refused with exactly the gateway's Setup no-mandate text,
 *   - request no ticket (none exists at the Authority Server),
 *   - leave no proposal,
 *   - be recorded as a blocked action on the owner's Blocked list.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { ControlPlaneClient, PROFILES_DIR } from '../src/helpers/gateway-stack.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';

const AS_PORT = 19965;
const MCP_PORT = 19966;
const CP_PORT = 19967;
const AS_URL = `http://localhost:${AS_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;

const EXPECTED =
  'Refused: Not done: I may only prepare mandates once you have given me a **Setup** mandate. Two ways: ' +
  '(1) In the gateway, open **Mandates → New mandate → Setup** and sign it. Then I prepare mandates and you approve each one. ' +
  '(2) Or sign the mandate you want yourself: **Mandates → New mandate**, then pick the area. Tell me which you prefer. ' +
  'No ticket was requested.';

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const cp = new ControlPlaneClient(CP_URL);
let apiKey: string;
let agent: Client;
let authorizationId: string;
let grantArgs: { head: Parameters<GatewayClient['pushGateContent']>[0]; profile: string; gate: Record<string, string> };
const gw = new GatewayClient(`http://localhost:${MCP_PORT}`);

describe('a Setup tool with no Setup mandate (real AS + gateway)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    const reg = await sp.register('Setup No Mandate', `setup-nomandate-${Date.now()}@test.local`);
    apiKey = reg.apiKey;
    const prevAuto = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';
    try {
      await pm.startGateway({ port: MCP_PORT, cpPort: CP_PORT, spUrl: AS_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
    } finally {
      if (prevAuto === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
      else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = prevAuto;
    }
    await gw.configure({ sessionCookie: 'setup-nomandate-e2e', apiKey });

    // A Delegation mandate, so the agent's session lists the Setup tools ...
    const DELEGATION = 'github.com/humanagencyprotocol/hap-profiles/delegation@0.4';
    const groupId = await sp.getPersonalGroupId(apiKey);
    const bounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 5 };
    const scope = { allowed_profiles: 'sales', allowed_modes: 'review' };
    const boundsHash = computeBoundsHash(bounds, ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max']);
    const contextHash = computeScopeHash(scope, ['allowed_profiles', 'allowed_modes']);
    const gate = { intent: 'E2E: the AI may propose Sales mandates.' };
    const att = await sp.submitMandate(apiKey, {
      profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: groupId, bounds,
      bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did: reg.user.did, commitment_mode: 'review',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: 'delegation-0.4' }),
    });
    await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, DELEGATION, gate);
    authorizationId = att.authorization_id;
    grantArgs = { head: { authorizationId, boundsHash, contextHash, context: scope }, profile: DELEGATION, gate };
    await new Promise((r) => setTimeout(r, 1_500));
    agent = new Client({ name: 'setup-nomandate-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${MCP_PORT}/sse`)));
  }, 300_000);

  afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    await pm.killAll();
  }, 30_000);

  it('setup__create_mandate is refused with the Setup text, no ticket, no proposal, a blocked-action record', async () => {
    expect((await agent.listTools()).tools.map((t) => t.name)).toContain('setup__create_mandate');
    // ... then the person revokes it. The gateway's own copy of the mandate list
    // refreshes asynchronously; until then the AS refuses the stale one as revoked.
    await sp.revokeAuthorization(apiKey, authorizationId);
    // The gateway learns of a revocation when it next syncs that mandate with the AS
    // (the UI does this when the person opens the Mandates page): a sync drops it.
    await gw.pushGateContent(grantArgs.head, grantArgs.profile, grantArgs.gate).catch(() => {});
    const call = () => agent.callTool({
      name: 'setup__create_mandate',
      arguments: {
        profile: 'sales', limits: { read_access: 'unlimited', value_max: 1000, discount_max: 5, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 },
        scope: { currency: 'EUR' }, intent: 'Why — test.', mode: 'review',
      },
    });
    const textOf = (x: Awaited<ReturnType<typeof call>>) => (x.content as Array<{ text?: string }>)?.map((c) => c.text ?? '').join('\n') ?? '';
    let r = await call();
    for (let i = 0; i < 30 && textOf(r) !== EXPECTED; i++) { await new Promise((x) => setTimeout(x, 1_000)); r = await call(); }
    const text = textOf(r);
    expect(r.isError, text).toBe(true);
    expect(text).toBe(EXPECTED);

    expect((await sp.getMyTicketsPage(apiKey, { limit: 50 })).tickets).toHaveLength(0);
    const props = await fetch(`${AS_URL}/api/proposals?domain=owner`, { headers: { 'X-API-Key': apiKey } });
    expect(((await props.json()) as { proposals?: unknown[] }).proposals ?? []).toHaveLength(0);

    const res = await cp.authed(apiKey, 'GET', '/denials?limit=500');
    const records = ((await res.json()) as { records?: Array<{ tool: string }> }).records ?? [];
    expect(records.filter((d) => /create_mandate/.test(d.tool)).length, JSON.stringify(records)).toBeGreaterThanOrEqual(1);
  });
});
