/**
 * No dead proposals — Gateway + Authority Server E2E, real servers, no mocks.
 *
 * THE PROBLEM: a review-mode call used to create a proposal without asking the
 * Authority Server whether a ticket could ever follow. A mandate revoked on the
 * server, or a daily limit already used up, left a proposal that a person
 * approved and the ticket then refused. Neither the person nor the AI could
 * tell why until it was too late.
 *
 * THE RULE: a proposal is created only if a ticket for it is possible today.
 *   - the Authority Server refuses to CREATE a proposal on a mandate that is
 *     revoked or expired (MANDATE_REVOKED / MANDATE_EXPIRED), or whose
 *     cumulative limit has no room (CUMULATIVE_LIMIT_EXCEEDED — the code and
 *     message the ticket would have used);
 *   - the gateway drops that mandate for the call and tries the next one that
 *     fits; with none left the AI gets ONE refusal naming the real reason,
 *     and no proposal exists anywhere.
 *
 * Cumulative counts are per (group, profile, actionType), not per mandate
 * (protocol.md, Cumulative Bounds) — so "no room" is the same fact for every
 * mandate of the group and the LIMIT is what differs. The setup here uses
 * that: an automatic mandate on a scope the AI never calls with (partner)
 * burns the shared count straight on the server (POST /api/as/ticket), so the
 * review mandates see a used-up day without any gateway involvement.
 *
 * One AS, one gateway per scenario (each scenario has its own user, hence its
 * own group, hence its own counts).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient } from '../src/helpers/gateway-stack.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

const PROFILE_ID = PROFILE_V07.customers;
const ROOT = join(import.meta.dirname, '..', '..');
const PROFILES_DIR = join(ROOT, 'hap-profiles');
const BOUNDS_KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const CONTEXT_KEY_ORDER = ['contact_type'];

const SP_PORT = 17940;
const SP_URL = `http://localhost:${SP_PORT}`;

const CRM_INTEGRATION = {
  id: 'crm',
  name: 'CRM',
  command: 'npx',
  args: ['-y', '@humanagencyp/crm-mcp@1.4.1'],
  envKeys: {},
  profile: 'customers',
  enabled: true,
  toolGating: {
    default: { executionMapping: {}, staticExecution: { contact_type: 'customer' } },
    overrides: {
      create_contact: { executionMapping: { type: 'contact_type' }, staticExecution: { action_type: 'write' } },
      find_contacts: { category: 'read' },
      get_timeline: { category: 'read' },
      get_pipeline: { category: 'read' },
      list_tasks: { category: 'read' },
      export_crm: { category: 'read' },
    },
  },
};

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const textOf = (r: unknown): string => ((r as { content?: Array<{ text?: string }> }).content ?? []).map((c) => c.text ?? '').join('\n');
const isProposal = (t: string) => /Awaiting commitment/i.test(t) && /Proposal ID/i.test(t);

const pm = new ProcessManager(); // owns the one Authority Server
const sp = new SPClient(SP_URL);

/** One user, one group, one gateway — a scenario's private world. */
class World {
  readonly gwPm = new ProcessManager();
  apiKey = '';
  did = '';
  groupId = '';
  client!: Client;
  cp!: ControlPlaneClient;
  cpPort = 0;
  private gw!: GatewayClient;

  constructor(private readonly label: string, private readonly gwPort: number, private readonly cpPortArg: number) {}

  async start(): Promise<void> {
    const user = await sp.register(`NoDead ${this.label}`, `nodead-${this.label}-${Date.now()}@test.local`);
    this.apiKey = user.apiKey;
    this.did = user.user.did;
    this.groupId = await sp.getPersonalGroupId(this.apiKey);
    this.cpPort = this.cpPortArg;
    await this.gwPm.startGateway({
      simulation: true, port: this.gwPort, cpPort: this.cpPort, spUrl: SP_URL, spApiKey: this.apiKey, profilesDir: PROFILES_DIR,
    });
    this.gw = new GatewayClient(`http://localhost:${this.gwPort}`);
    await this.gw.configure({ sessionCookie: `nodead-${this.label}`, apiKey: this.apiKey });
    this.cp = new ControlPlaneClient(`http://localhost:${this.cpPort}`);
  }

  /** Sign a customers mandate. The gateway learns of it by the same push the UI does. */
  async grant(opts: { contactType: string; mode: 'automatic' | 'review'; writeDailyMax: number; intent: string }): Promise<string> {
    const bounds = {
      profile: PROFILE_ID, read_access: 'unlimited', export_access: 'none',
      write_daily_max: opts.writeDailyMax, delete_daily_max: 5, setup_daily_max: 0,
    };
    const boundsHash = computeBoundsHash(bounds, BOUNDS_KEY_ORDER);
    const context = { contact_type: opts.contactType };
    const contextHash = computeScopeHash(context, CONTEXT_KEY_ORDER);
    const gateContent = { intent: opts.intent };
    const att = await sp.submitMandate(this.apiKey, {
      profile_id: PROFILE_ID,
      profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
      group_id: this.groupId,
      bounds,
      bounds_hash: boundsHash,
      scope_hash: contextHash,
      domain: 'owner',
      did: this.did,
      commitment_mode: opts.mode,
      gate_content_hashes: hashGateContent(gateContent),
      execution_context_hash: hashExecutionContext({ contact_type: opts.contactType, write_count_daily: opts.writeDailyMax }),
    });
    await this.gw.pushGateContent(
      { authorizationId: att.authorization_id, boundsHash, contextHash, context },
      PROFILE_ID,
      gateContent,
    );
    return att.authorization_id;
  }

  async connect(): Promise<void> {
    await sleep(500);
    const added = await this.gw.addIntegration(CRM_INTEGRATION);
    expect(added.ok).toBe(true);
    await this.gw.waitForIntegration('crm');
    await sleep(2_000);
    this.client = new Client({ name: `nodead-${this.label}`, version: '0.1.0' }, { capabilities: {} });
    await this.client.connect(new SSEClientTransport(new URL(`http://localhost:${this.gwPort}/sse`)));
  }

  async createContact(name: string, type = 'customer'): Promise<string> {
    return textOf(await this.client.callTool({ name: 'crm__create_contact', arguments: { name, type } }));
  }

  /** Burn `n` units of the group's daily write count, straight on the server. */
  async useUpWrites(burnerId: string, n: number): Promise<void> {
    for (let i = 0; i < n; i++) {
      const t = await sp.postTicket(this.apiKey, {
        authorizationId: burnerId,
        profileId: PROFILE_ID,
        action: 'crm__create_contact',
        actionType: 'write',
        executionContext: { contact_type: 'partner', action_type: 'write' },
      });
      expect(t.status).toBe(201);
    }
  }

  /** Every proposal of this user on the AS, any state (own domain, pending + decided). */
  async proposals(): Promise<Array<Record<string, any>>> {
    const res = await fetch(`${SP_URL}/api/proposals?domain=owner&status=all`, { headers: { 'X-API-Key': this.apiKey } });
    expect(res.ok).toBe(true);
    return ((await res.json()) as { proposals: Array<Record<string, any>> }).proposals;
  }

  async stop(): Promise<void> {
    try { await this.client?.close(); } catch { /* ignore */ }
    await this.gwPm.killAll();
  }
}

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);
}, 180_000);

afterAll(async () => {
  await pm.killAll();
}, 60_000);

// ─────────────────────────────────────────────────────────────────────────────

describe('revoked directly on the server, then a review call', () => {
  const w = new World('revoked', 17941, 17951);
  let revokedId: string;

  beforeAll(async () => {
    await w.start();
    revokedId = await w.grant({ contactType: 'customer', mode: 'review', writeDailyMax: 10, intent: 'REVIEW: customers.' });
    await w.connect();
  }, 240_000);
  afterAll(() => w.stop(), 30_000);

  it('the AI gets one refusal naming the revoked mandate, and no proposal exists', async () => {
    // Revoked ON THE SERVER, behind the gateway's back: its cache still lists the mandate.
    await sp.revokeAuthorization(w.apiKey, revokedId);

    const text = await w.createContact('Ghost Customer');
    expect(isProposal(text)).toBe(false);
    expect(text).toMatch(/^Refused: the mandate ".*" was revoked\./);
    expect(text).toContain('No proposal was created and nothing ran.');
    expect(text).toContain('Ask the person to grant a new mandate.');

    expect(await w.proposals()).toHaveLength(0);
  });

  it('the Authority Server itself refuses to create a proposal on it (envelope, 403)', async () => {
    const res = await fetch(`${SP_URL}/api/proposals`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': w.apiKey },
      body: JSON.stringify({ authorization_id: revokedId, profile_id: PROFILE_ID, tool: 'crm__create_contact', actionType: 'write', execution_context: {} }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { approved: boolean; errors: Array<{ code: string; message: string }>; error?: string };
    expect(body.approved).toBe(false);
    expect(body.errors[0].code).toBe('MANDATE_REVOKED');
    // Additive: the same message as a string, which is all a gateway from before this change reads.
    expect(body.error).toBe(body.errors[0].message);
    expect(await w.proposals()).toHaveLength(0);
  });
});

describe('the limit is used up, then a review call', () => {
  const w = new World('limit', 17942, 17952);
  let reviewId: string;
  let burnerId: string;

  beforeAll(async () => {
    await w.start();
    reviewId = await w.grant({ contactType: 'customer', mode: 'review', writeDailyMax: 2, intent: 'REVIEW: customers, two a day.' });
    // Automatic, on a scope the AI never calls with: only here to use up the shared count.
    burnerId = await w.grant({ contactType: 'partner', mode: 'automatic', writeDailyMax: 50, intent: 'BURNER: partner contacts.' });
    await w.connect();
  }, 240_000);
  afterAll(() => w.stop(), 30_000);

  it('with room left, the call becomes a proposal', async () => {
    await w.useUpWrites(burnerId, 1); // 1 of 2 used
    const text = await w.createContact('Has Room');
    expect(isProposal(text)).toBe(true);
    expect((await w.proposals()).filter((p) => p.authorizationId === reviewId || p.authorization_id === reviewId)).toHaveLength(1);
  });

  it('with the limit used up, the AI gets the server\'s reason and no proposal is created', async () => {
    await w.useUpWrites(burnerId, 1); // 2 of 2 used: the next write would be the 3rd
    const before = (await w.proposals()).length;

    const text = await w.createContact('Too Many');
    expect(isProposal(text)).toBe(false);
    expect(text).toMatch(/^Refused: Cumulative daily count \(3\) exceeds write_daily_max=2\./);
    expect(text).toContain('No proposal was created and nothing ran.');

    expect(await w.proposals()).toHaveLength(before);
  });

  it('the Authority Server refuses with the ticket\'s own code, message and numbers', async () => {
    const res = await fetch(`${SP_URL}/api/proposals`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': w.apiKey },
      body: JSON.stringify({ authorization_id: reviewId, profile_id: PROFILE_ID, tool: 'crm__create_contact', actionType: 'write', execution_context: { contact_type: 'customer' } }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { errors: Array<Record<string, unknown>> };
    expect(body.errors[0]).toMatchObject({ code: 'CUMULATIVE_LIMIT_EXCEEDED', expected: 2, actual: 3 });
    expect(String(body.errors[0].message)).toBe('Cumulative daily count (3) exceeds write_daily_max=2');
  });
});

describe('two mandates fit and one has no room', () => {
  const w = new World('two', 17943, 17953);
  let narrowId: string; // most specific: the selector prefers it
  let broadId: string;
  let burnerId: string;

  beforeAll(async () => {
    await w.start();
    // NARROW is strictly more specific than BROAD, so the existing selection rule picks it first.
    narrowId = await w.grant({ contactType: 'customer', mode: 'review', writeDailyMax: 1, intent: 'NARROW: customers, one a day.' });
    broadId = await w.grant({ contactType: 'customer,lead', mode: 'review', writeDailyMax: 10, intent: 'BROAD: customers and leads, ten a day.' });
    burnerId = await w.grant({ contactType: 'partner', mode: 'automatic', writeDailyMax: 50, intent: 'BURNER: partner contacts.' });
    await w.connect();
  }, 240_000);
  afterAll(() => w.stop(), 30_000);

  it('the proposal rides on the mandate that has room, and none exists on the full one', async () => {
    await w.useUpWrites(burnerId, 1); // NARROW (limit 1) is now full; BROAD (limit 10) is not

    const text = await w.createContact('Fits Broad');
    expect(isProposal(text)).toBe(true);

    const all = await w.proposals();
    const idOf = (p: Record<string, any>) => p.authorizationId ?? p.authorization_id;
    expect(all.filter((p) => idOf(p) === narrowId)).toHaveLength(0);
    expect(all.filter((p) => idOf(p) === broadId)).toHaveLength(1);
    expect(all).toHaveLength(1);
  });
});

describe('the limit fills up AFTER the proposal exists', () => {
  const w = new World('late', 17944, 17954);
  let reviewId: string;
  let burnerId: string;
  let proposalId: string;

  beforeAll(async () => {
    await w.start();
    reviewId = await w.grant({ contactType: 'customer', mode: 'review', writeDailyMax: 2, intent: 'REVIEW: customers, two a day.' });
    burnerId = await w.grant({ contactType: 'partner', mode: 'automatic', writeDailyMax: 50, intent: 'BURNER: partner contacts.' });
    await w.connect();
  }, 240_000);
  afterAll(() => w.stop(), 30_000);

  it('a proposal is created while there is room', async () => {
    const text = await w.createContact('Late Customer');
    expect(isProposal(text)).toBe(true);
    proposalId = text.match(/Proposal ID: ([a-f0-9]+)/)![1];
  });

  it('then the day fills up, the person approves, and the ticket is refused with the reason kept on the proposal', async () => {
    await w.useUpWrites(burnerId, 2); // 2 of 2 used before the approval

    const res = await fetch(`${SP_URL}/api/proposals/${proposalId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': w.apiKey },
      body: JSON.stringify({ action: 'commit', domain: 'owner' }),
    });
    expect(res.ok).toBe(true); // approving is still possible: only the ticket enforces a cumulative limit

    // The gateway's auto-execution loop asks for the ticket (5s poll) and is refused.
    let proposal: Record<string, any> | undefined;
    for (let i = 0; i < 40; i++) {
      await sleep(1_000);
      const r = await fetch(`${SP_URL}/api/proposals/${proposalId}`, { headers: { 'X-API-Key': w.apiKey } });
      proposal = ((await r.json()) as { proposal: Record<string, any> }).proposal;
      if (proposal.status !== 'committed') break;
    }
    // THE FIELD THE UI READS: status 'refused' and refusal { code, message, at } on the proposal record.
    expect(proposal!.status).toBe('refused');
    expect(proposal!.refusal.code).toBe('CUMULATIVE_LIMIT_EXCEEDED');
    expect(proposal!.refusal.message).toBe('Cumulative daily count (3) exceeds write_daily_max=2');
    expect(typeof proposal!.refusal.at).toBe('number');

    // The same record is what the lists the gateway UI shows carry.
    const listed = (await w.proposals()).find((p) => p.id === proposalId);
    expect(listed?.status).toBe('refused');
    expect(listed?.refusal?.code).toBe('CUMULATIVE_LIMIT_EXCEEDED');

    // The gateway's own record of the outcome (GET /proposal-status/:id/outcome).
    const out = await w.cp.authed(w.apiKey, 'GET', `/proposal-status/${proposalId}/outcome`);
    expect(out.status).toBe(200);
    const outcome = (await out.json()) as { state: string; outcome?: string; detail?: string };
    expect(outcome.state).toBe('failed');
    expect(outcome.outcome).toBe('as_refused');
    expect(outcome.detail).toContain('CUMULATIVE_LIMIT_EXCEEDED');

    // And the AI is told, not left waiting.
    const status = textOf(await w.client.callTool({ name: 'check-pending-commitments', arguments: { proposal_id: proposalId } }));
    expect(status).toMatch(/refused/i);
    expect(status).toContain('Cumulative daily count (3) exceeds write_daily_max=2');
    expect(reviewId).toBeTruthy();
  }, 90_000);
});

describe('a revoked mandate leaves no way to act', () => {
  const w = new World('noway', 17945, 17955);
  let id: string;
  let pendingProposalId: string;

  beforeAll(async () => {
    await w.start();
    id = await w.grant({ contactType: 'customer', mode: 'review', writeDailyMax: 10, intent: 'REVIEW: customers.' });
    await w.connect();
  }, 240_000);
  afterAll(() => w.stop(), 30_000);

  it('a proposal waits; the mandate is revoked on the server', async () => {
    const text = await w.createContact('Waiting Customer');
    expect(isProposal(text)).toBe(true);
    pendingProposalId = text.match(/Proposal ID: ([a-f0-9]+)/)![1];
    await sp.revokeAuthorization(w.apiKey, id);
  });

  it('approving the waiting proposal is refused', async () => {
    const res = await fetch(`${SP_URL}/api/proposals/${pendingProposalId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': w.apiKey },
      body: JSON.stringify({ action: 'commit', domain: 'owner' }),
    });
    expect(res.ok).toBe(false);
  });

  it('a ticket for it is refused', async () => {
    const t = await sp.postTicket(w.apiKey, {
      authorizationId: id, profileId: PROFILE_ID, action: 'crm__create_contact', actionType: 'write',
      proposalId: pendingProposalId, executionContext: { contact_type: 'customer' },
    });
    expect(t.status).toBe(403);
    expect((t.body.errors as Array<{ code: string }>)[0].code).toBe('MANDATE_REVOKED');
  });

  it('a new call is refused with no new proposal, and the contact was never created', async () => {
    const before = (await w.proposals()).length;
    const text = await w.createContact('Second Try');
    expect(isProposal(text)).toBe(false);
    expect(text).toMatch(/^Refused: the mandate ".*" was revoked\./);
    expect(await w.proposals()).toHaveLength(before);

    const found = textOf(await w.client.callTool({ name: 'crm__find_contacts', arguments: { query: 'Second Try' } }));
    expect(found).not.toContain('Second Try');
  });
});
