/**
 * A blank write argument is not a stated value — real stack.
 *
 * hap-core skips a scope check when the call's value is empty, exactly as when
 * it is absent; the connector then uses whatever it gets. The gateway treats a
 * scalar argument that is "" (or only whitespace) after trimming as OMITTED:
 * under a mandate whose scope constrains its field, the call is refused before
 * any ticket, naming the argument (security review of stream H, 2026-11-12:
 * `visibility: ""` under an audience=connections LinkedIn mandate).
 *
 * LinkedIn needs real credentials and has no simulation mode, so this runs a
 * MADE-UP area on the real stack instead: a "Venue" profile (served to the real
 * Authority Server and the gateway from a temp copy of hap-profiles) whose scope
 * `rooms` is a subset field WITHOUT requiredFor — the shape of publish's
 * `audience` — and a "venue" manifest that drives the real records connector
 * (@humanagencyp/records-mcp, installed as every suite installs it), mapping
 * create_record's free-text `content` to `rooms` (`type` is an enum the MCP
 * layer validates before the gate, so "" could not reach it). Nothing is mocked.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { ControlPlaneClient, newSecret, startControlPlane, startMcpServer, textOf, PROFILES_DIR, MANIFESTS_DIR, type StackOptions } from '../src/helpers/gateway-stack.js';
import { localProfilesForAs } from '../src/helpers/local-profiles.js';
import { profileHashFor } from '../src/helpers/profiles.js';
import { e2ePort } from '../src/helpers/ports.js';

// 18720–18729 belong to this file.
const AS_PORT = e2ePort(18720);
const PORTS = { cp: e2ePort(18721), mcp: e2ePort(18722) };
const AS_URL = `http://localhost:${AS_PORT}`;
const VENUE = 'github.com/humanagencyprotocol/hap-profiles/venue@1.0';
const KEYS = ['profile', 'read_access', 'write_daily_max'];
const SCOPE_KEYS = ['rooms'];

const VENUE_PROFILE = {
  id: VENUE,
  name: 'Venue',
  version: '1.0',
  description: 'E2E made-up area: which rooms the AI may book. `rooms` is a subset scope without requiredFor.',
  boundsSchema: {
    actionTypes: ['write'],
    keyOrder: KEYS,
    fields: {
      profile: { type: 'string', required: true },
      read_access: {
        type: 'string', required: true, displayName: 'Read access', description: 'Read bookings',
        boundType: { kind: 'enum', values: ['unlimited', 'none'] }, default: 'unlimited',
      },
      write_daily_max: {
        type: 'number', required: true, displayName: 'Daily bookings', description: 'Bookings per day', unit: 'count',
        boundType: { kind: 'cumulative_count', window: 'daily' }, appliesTo: ['write'],
      },
    },
  },
  scopeSchema: {
    keyOrder: SCOPE_KEYS,
    fields: {
      rooms: {
        type: 'string', required: false, displayName: 'Bookable rooms', description: 'Comma-separated rooms the AI may book',
        constraint: { type: 'string', enforceable: ['subset'] },
      },
    },
  },
  executionContextSchema: {
    fields: {
      rooms: { source: 'declared', description: 'The room this call books', required: false, constraint: { type: 'string', enforceable: ['subset'] } },
      write_count_daily: {
        source: 'cumulative', cumulativeField: '_count', window: 'daily', description: 'Running daily count', required: true,
        constraint: { type: 'number', enforceable: ['max'] },
      },
    },
  },
  requiredGates: ['bounds', 'intent', 'commitment', 'mandate_owner'],
  ttl: { default: 86400, max: 31536000 },
  retention_minimum: 7776000,
  content_binding: { version: '1', kind: 'jcs' },
};

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
type Account = { apiKey: string; user: { id: string; did: string } };
let owner: Account;
let stack: StackOptions;
let cp: ControlPlaneClient;
let agent: Client;
let work: string;
let mandateId = '';

async function ticketsFor(id: string): Promise<number> {
  const { tickets } = await sp.getMyTicketsPage(owner.apiKey, { limit: 100 });
  return tickets.filter((t) => JSON.stringify(t).includes(id)).length;
}

async function book(args: Record<string, unknown>) {
  const r = await agent.callTool({ name: 'venue__create_record', arguments: { type: 'note', title: 'Booking', ...args } });
  return { denied: r.isError === true, text: textOf(r) };
}

describe('a blank write argument is not a stated value (real stack, made-up area on the records connector)', () => {
  beforeAll(async () => {
    work = mkdtempSync(join(tmpdir(), 'hap-e2e-blank-arg-'));

    // Profiles: the local hap-profiles plus the made-up Venue profile.
    const profiles = join(work, 'profiles');
    cpSync(PROFILES_DIR, profiles, { recursive: true });
    mkdirSync(join(profiles, 'venue'), { recursive: true });
    writeFileSync(join(profiles, 'venue', '1.0.profile.json'), JSON.stringify(VENUE_PROFILE, null, 2));
    const pIndex = JSON.parse(readFileSync(join(profiles, 'index.json'), 'utf8'));
    pIndex.profiles[VENUE] = 'venue/1.0.profile.json';
    writeFileSync(join(profiles, 'index.json'), JSON.stringify(pIndex, null, 2));

    // Manifests: the gateway's own plus a "venue" manifest on the records connector.
    const manifests = join(work, 'manifests');
    cpSync(MANIFESTS_DIR, manifests, { recursive: true });
    const records = JSON.parse(readFileSync(join(manifests, 'records.json'), 'utf8'));
    const venue = {
      ...records, id: 'venue', name: 'Venue', description: 'E2E made-up area on the records connector', profile: 'venue',
      toolGating: {
        default: records.toolGating.default,
        overrides: {
          ...Object.fromEntries(Object.entries(records.toolGating.overrides as Record<string, Record<string, unknown> | null>)
            .filter(([, o]) => o === null || o?.category === 'read' || o?.category === 'disabled')),
          create_record: {
            summary: 'New booking: {title|short}',
            executionMapping: { content: 'rooms' },
            staticExecution: { action_type: 'write' },
            actionLabel: 'Room booked',
          },
        },
      },
    };
    delete venue.report;
    delete venue.personalDefault;
    delete venue.replaces;
    writeFileSync(join(manifests, 'venue.json'), JSON.stringify(venue, null, 2));
    const mIndex = JSON.parse(readFileSync(join(manifests, 'index.json'), 'utf8'));
    mIndex.integrations.venue = 'venue.json';
    writeFileSync(join(manifests, 'index.json'), JSON.stringify(mIndex, null, 2));

    pm.buildGateway();
    const asProfiles = localProfilesForAs(profiles);
    await pm.startSP(AS_PORT, { cwd: asProfiles.cwd, env: asProfiles.env });
    owner = await sp.register('Erika Blank', `erika-blank-${Date.now()}@test.local`) as unknown as Account;
    const groupId = await sp.getPersonalGroupId(owner.apiKey);
    stack = {
      dataDir: join(work, 'data'), ports: PORTS, secret: newSecret(), asUrl: AS_URL,
      extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_PROFILES_DIR: profiles, SUVEREN_MANIFESTS_DIR: manifests },
    };
    mkdirSync(stack.dataDir, { recursive: true });
    await startControlPlane(pm, stack, 'cp-blank');
    await startMcpServer(pm, stack, 'mcp-blank');
    cp = new ControlPlaneClient(`http://localhost:${PORTS.cp}`);
    expect((await cp.login(owner.apiKey)).status).toBe(200);
    const mcp = new GatewayClient(`http://localhost:${PORTS.mcp}`, stack.secret);
    const act = await cp.authed(owner.apiKey, 'POST', '/mcp/integrations/venue/activate');
    expect(act.status, await act.text()).toBe(200);
    await mcp.waitForIntegration('venue');

    // An automatic Venue mandate: only the lobby.
    const b = { profile: VENUE, read_access: 'unlimited', write_daily_max: 10 };
    const scope = { rooms: 'lobby' };
    const boundsHash = computeBoundsHash(b, KEYS);
    const contextHash = computeScopeHash(scope, SCOPE_KEYS);
    const gate = { intent: 'E2E: book the lobby only.' };
    const att = await sp.submitMandate(owner.apiKey, {
      profile_id: VENUE, profile_hash: profileHashFor(VENUE, profiles), group_id: groupId, bounds: b, bounds_hash: boundsHash, scope_hash: contextHash,
      domain: 'owner', did: owner.user.did, commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent(gate), execution_context_hash: hashExecutionContext({ m: VENUE }),
    });
    mandateId = att.authorization_id;
    await mcp.pushGateContent({ authorizationId: mandateId, boundsHash, contextHash, context: scope }, VENUE, gate);
    await new Promise((r) => setTimeout(r, 1_500));

    agent = new Client({ name: 'blank-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`http://localhost:${PORTS.mcp}/sse`)));
  }, 300_000);

  afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    await pm.stopProcess('mcp-blank').catch(() => {});
    await pm.stopProcess('cp-blank').catch(() => {});
    await pm.killAll();
    if (work) rmSync(work, { recursive: true, force: true });
  }, 30_000);

  it('positive control: the allowed room books, with a ticket', async () => {
    const r = await book({ content: 'lobby' });
    expect(r.denied, r.text).toBe(false);
    expect(await ticketsFor(mandateId)).toBe(1);
  }, 60_000);

  it('a room outside the scope is refused by the scope check', async () => {
    const r = await book({ content: 'cellar' });
    expect(r.denied, r.text).toBe(true);
    expect(await ticketsFor(mandateId)).toBe(1);
  }, 60_000);

  for (const [label, value] of [['""', ''], ['only whitespace', '   ']] as const) {
    it(`content ${label} under a rooms scope is refused before any ticket, naming the argument`, async () => {
      const before = await ticketsFor(mandateId);
      const r = await book({ content: value });
      expect(r.denied, r.text).toBe(true);
      expect(await ticketsFor(mandateId), 'a ticket was issued for it').toBe(before);
      expect(r.text).toContain('was called without "content"');
    }, 60_000);
  }
});
