/**
 * v0.8 proposal readers are named by DID — a GATEWAY-BUILT envelope is
 * accepted under a 0.8 mandate (content/0.8/protocol.md → *Proposals — what
 * the Authority Server receives*, rule 2: "Each is named by DID").
 *
 * Release blocker found 2026-11-04 on the Rehearsal test AS: gateway 0.41.0
 * named `readers` / `encrypted_keys` by ACCOUNT id, the AS checks them against
 * the signed DIDs, so EVERY review proposal under a 0.8 mandate was refused
 * PROPOSAL_APPROVERS_INVALID. test/v08-wire.test.ts never caught it: it builds
 * its envelopes by hand, by DID — this suite lets the real gateway build them.
 *
 *  1. Personal mode, the real trigger path: an agent's MCP call under a 0.8
 *     `review` mandate becomes a proposal the AS accepts; its readers are the
 *     owner's DID; the same content key also travels by account id (`keys`)
 *     for 0.40 gateways; the owner's gateway opens it.
 *  2. A team with an above-cap approver: the grantor's real gateway seals the
 *     content (its control plane's /internal/encrypt-content, the call the MCP
 *     server makes) to the owner DID + the signed `above_cap_approvers`; the
 *     AS accepts it; the APPROVER's own gateway opens it.
 *
 * Needs: SUVEREN_DB_URL (Postgres admin URL), sibling checkouts
 * ../suveren-as, ../suveren-gateway, ../hap-profiles.
 * Run: npx vitest run test/v08-proposal-readers.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { canonicalize } from '@humanagencyp/hap-core';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { GatewayClient, internalSecretHeaders } from '../src/helpers/gateway-client.js';
import { hashGateContent, computeBoundsHash, computeScopeHash, computeExecutionContextHash, sha256Hash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';

const SP_PORT = 19620; // unused elsewhere in the suite as of 2026-11-04
const SP_URL = `http://localhost:${SP_PORT}`;
const OWNER_GW = { mcp: 19630, cp: 19631 };
const GRANTOR_GW = { mcp: 19632, cp: 19633 };
const APPROVER_GW = { mcp: 19634, cp: 19635 };
const PROFILES_DIR = join(process.cwd(), '..', 'hap-profiles');

const sp = new SPClient(SP_URL);
const asPm = new ProcessManager();
const ownerPm = new ProcessManager();
const grantorPm = new ProcessManager();
const approverPm = new ProcessManager();

interface User { id: string; did: string; apiKey: string }
interface Envelope { ciphertext: string; keys: Record<string, unknown>; encrypted_keys?: Record<string, unknown>; readers: string[]; unreadable: string[]; hash: string }

async function api(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${SP_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, any> };
}

/** The gateway control plane's own /internal route (what its MCP server calls). */
async function cpInternal(gw: { mcp: number; cp: number }, path: string, body: unknown) {
  const res = await fetch(`http://localhost:${gw.cp}/internal${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...internalSecretHeaders(`http://localhost:${gw.mcp}`) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, any> };
}

function decodeBlob(blob: string): { payload: Record<string, any> } {
  return JSON.parse(Buffer.from(blob, 'base64url').toString('utf8'));
}

async function register(name: string): Promise<User> {
  const u = await sp.register(name, `${name.toLowerCase().replace(/\W+/g, '-')}-${Date.now()}@test.local`);
  return { id: u.user.id, did: u.user.did, apiKey: u.apiKey };
}

beforeAll(async () => {
  asPm.buildGateway();
  await asPm.startSP(SP_PORT);
}, 600_000);

afterAll(async () => {
  for (const pm of [ownerPm, grantorPm, approverPm, asPm]) await pm.killAll();
}, 60_000);

describe('v0.8 — personal mode: an agent\'s review proposal, built by the real gateway, is accepted', () => {
  let owner: User;
  let mcp: Client;
  let proposalId: string;
  const CUSTOMERS = PROFILE_V07.customers;
  const KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];

  beforeAll(async () => {
    owner = await register('Readers Owner');
    const groupId = await sp.getPersonalGroupId(owner.apiKey);
    await ownerPm.startGateway({ port: OWNER_GW.mcp, cpPort: OWNER_GW.cp, spUrl: SP_URL, spApiKey: owner.apiKey, profilesDir: PROFILES_DIR });
    const gw = new GatewayClient(`http://localhost:${OWNER_GW.mcp}`);
    await gw.configure({ sessionCookie: `api-key=${owner.apiKey}`, apiKey: owner.apiKey });

    const bounds = { profile: CUSTOMERS, read_access: 'unlimited', export_access: 'none', write_daily_max: 10, delete_daily_max: 5, setup_daily_max: 0 };
    const boundsHash = computeBoundsHash(bounds, KEY_ORDER);
    const scopeHash = computeScopeHash({}, []);
    const m = await sp.submitMandateRaw(owner.apiKey, {
      authorization_id: mintAuthorizationId(),
      profile_id: CUSTOMERS,
      profile_hash: profileHashFor(CUSTOMERS, PROFILES_DIR),
      group_id: groupId, domain: 'owner', did: owner.did,
      bounds, bounds_hash: boundsHash, scope_hash: scopeHash,
      gate_content_hashes: hashGateContent({ intent: 'v0.8 readers by DID.' }),
      execution_context_hash: computeExecutionContextHash(loadProfile(CUSTOMERS, PROFILES_DIR) as { executionContextSchema?: unknown }),
      commitment_mode: 'review',
      supported_versions: ['0.8', '0.7'],
    });
    expect(m.status, JSON.stringify(m.body)).toBeLessThan(300);
    const payload = decodeBlob(m.body.blob as string).payload;
    expect(payload.version).toBe('0.8');
    expect(payload.mandate_owners[0].did).toBe(owner.did);

    await gw.pushGateContent(
      { authorizationId: m.body.authorization_id as string, boundsHash, contextHash: scopeHash, context: {} },
      CUSTOMERS,
      { intent: 'v0.8 readers by DID.' },
    );
    await gw.waitForIntegration('crm');
    await new Promise((r) => setTimeout(r, 2_000));
    mcp = new Client({ name: 'readers-agent', version: '1.0.0' }, { capabilities: {} });
    await mcp.connect(new SSEClientTransport(new URL(`http://localhost:${OWNER_GW.mcp}/sse`)));
  }, 300_000);

  afterAll(async () => { try { await mcp?.close(); } catch { /* */ } });

  it('the MCP call under a 0.8 review mandate becomes a proposal (not PROPOSAL_APPROVERS_INVALID)', async () => {
    const result = await mcp.callTool({ name: 'crm__create_contact', arguments: { name: 'Readers Contact', type: 'customer' } });
    const text = (result.content as Array<{ text: string }>)[0].text;
    expect(result.isError, text).toBeFalsy();
    expect(text).toContain('Awaiting commitment');
    const match = text.match(/Proposal ID: ([a-f0-9-]+)/);
    expect(match, text).toBeTruthy();
    proposalId = match![1];
  });

  it('the AS holds readers = [owner DID]; the same content key is also wrapped by account id for 0.40 gateways', async () => {
    const r = await api('GET', `/api/proposals/${proposalId}`, owner.apiKey);
    expect(r.status).toBe(200);
    const content = r.body.proposal.content as Envelope;
    expect(content.readers).toEqual([owner.did]);
    expect(content.unreadable).toEqual([]);
    expect(Object.keys(content.keys).sort()).toEqual([owner.did, owner.id].sort());
  });

  it('the owner\'s gateway opens it — the plaintext is the agent\'s arguments, fingerprint-checked', async () => {
    const r = await api('GET', `/api/proposals/${proposalId}`, owner.apiKey);
    const content = r.body.proposal.content as Envelope;
    const opened = await cpInternal(OWNER_GW, '/decrypt-content', { ciphertext: content.ciphertext, keys: content.keys, hash: content.hash });
    expect(opened.status, JSON.stringify(opened.body)).toBe(200);
    expect(JSON.parse(opened.body.plaintext)).toMatchObject({ name: 'Readers Contact', type: 'customer' });
  });
});

describe('v0.8 — a team with an above-cap approver: the gateway-built envelope names owner + signed approver by DID', () => {
  let grantor: User;
  let approver: User;
  let authorizationId: string;
  let promoted: Record<string, any>;
  let proposalId: string;
  const CHARGE = PROFILE_V07.charge;
  const args = { amount: 250, description: 'Annual licence', customer_id: 'cus_1' };
  const fingerprint = sha256Hash(canonicalize(args));

  beforeAll(async () => {
    grantor = await register('Readers Grantor');
    approver = await register('Readers Approver');
    const team = await sp.createGroup(grantor.apiKey, `Readers Team ${Date.now()}`);
    const teamGroupId = team.group.id;
    await sp.joinGroup(approver.apiKey, team.inviteCode, grantor.apiKey);
    // One approver, an approval cap on amount_max: an automatic request is promoted to review_above_cap.
    const cfg = await api('PUT', `/api/groups/${teamGroupId}/profile-config/${encodeURIComponent(CHARGE)}`, grantor.apiKey, {
      grantors: [grantor.id], approvers: [approver.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } },
    });
    expect(cfg.status, JSON.stringify(cfg.body)).toBeLessThan(300);

    // Both run their own real gateway; sign-in registers each one's reader key at the AS.
    await grantorPm.startGateway({ port: GRANTOR_GW.mcp, cpPort: GRANTOR_GW.cp, spUrl: SP_URL, spApiKey: grantor.apiKey, profilesDir: PROFILES_DIR });
    await approverPm.startGateway({ port: APPROVER_GW.mcp, cpPort: APPROVER_GW.cp, spUrl: SP_URL, spApiKey: approver.apiKey, profilesDir: PROFILES_DIR });

    const bounds = { profile: CHARGE, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 };
    const r = await sp.submitMandateRaw(grantor.apiKey, {
      authorization_id: mintAuthorizationId(),
      profile_id: CHARGE,
      profile_hash: profileHashFor(CHARGE, PROFILES_DIR),
      group_id: teamGroupId,
      bounds,
      bounds_hash: computeBoundsHash(bounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
      scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
      domain: 'owner', did: grantor.did, commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: 'v0.8 readers by DID, team.' }),
      execution_context_hash: computeExecutionContextHash(loadProfile(CHARGE, PROFILES_DIR) as { executionContextSchema?: unknown }),
      supported_versions: ['0.8', '0.7'],
    });
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    authorizationId = r.body.authorization_id as string;
    promoted = decodeBlob(r.body.blob as string).payload;
  }, 300_000);

  it('the signed mandate is 0.8 review_above_cap, naming the approver by DID', () => {
    expect(promoted.version).toBe('0.8');
    expect(promoted.commitment_mode).toBe('review_above_cap');
    expect(promoted.above_cap_approvers).toEqual([approver.did]);
  });

  it('the AS tells a gateway each account\'s current DID beside its reader key (GET /api/users/:id/pubkey)', async () => {
    const byId = await api('GET', `/api/users/${encodeURIComponent(approver.id)}/pubkey`, grantor.apiKey);
    expect(byId.status, JSON.stringify(byId.body)).toBe(200);
    expect(byId.body.did).toBe(approver.did);
    const byDid = await api('GET', `/api/users/${encodeURIComponent(approver.did)}/pubkey`, grantor.apiKey);
    expect(byDid.status).toBe(200);
    expect(byDid.body.pubkey).toBe(byId.body.pubkey);
  });

  it('the grantor\'s gateway seals to owner + signed approver by DID, and the AS accepts the proposal', async () => {
    // What tool-proxy hands its control plane under a 0.8 mandate: the
    // account-id recipients it always had, plus the signed reader DIDs.
    const sealed = await cpInternal(GRANTOR_GW, '/encrypt-content', {
      toolArgs: args,
      recipientUserIds: [grantor.id, approver.id],
      readers: { ownerDid: promoted.mandate_owners[0].did, deciders: promoted.above_cap_approvers },
    });
    expect(sealed.status, JSON.stringify(sealed.body)).toBe(200);
    const content = sealed.body.content as Envelope;
    expect(content.readers.sort()).toEqual([grantor.did, approver.did].sort());
    expect(content.unreadable).toEqual([]);
    expect(Object.keys(content.keys).sort()).toEqual([grantor.id, approver.id].sort());
    expect(content.hash).toBe(fingerprint);

    const created = await api('POST', '/api/proposals', grantor.apiKey, {
      authorization_id: authorizationId,
      mandateId: promoted.mandate_id, boundsHash: promoted.bounds_hash,
      profile_id: CHARGE,
      tool: 'create_payment_link', action: 'create_payment_link', actionType: 'charge',
      execution_context: { amount: 250 }, executionContext: { amount: 250 },
      content, proposalContentHash: content.hash,
      pending_approvers: [approver.id],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    proposalId = created.body.proposal.id;
  });

  it('the approver\'s own gateway opens what the AS relays; a 0.40 gateway finds its wrap by account id', async () => {
    const r = await api('GET', `/api/proposals/${proposalId}`, approver.apiKey);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const content = r.body.proposal.content as Envelope;
    expect(content.readers.sort()).toEqual([grantor.did, approver.did].sort());
    expect(Object.keys(content.keys)).toEqual(expect.arrayContaining([approver.id, approver.did]));

    const opened = await cpInternal(APPROVER_GW, '/decrypt-content', { ciphertext: content.ciphertext, keys: content.keys, hash: content.hash });
    expect(opened.status, JSON.stringify(opened.body)).toBe(200);
    expect(JSON.parse(opened.body.plaintext)).toEqual(args);

    // Only the account-id wrap — what a 0.40 gateway (which knows no DID) looks up.
    const legacy = await cpInternal(APPROVER_GW, '/decrypt-content', {
      ciphertext: content.ciphertext, keys: { [approver.id]: content.keys[approver.id] }, hash: content.hash,
    });
    expect(legacy.status, JSON.stringify(legacy.body)).toBe(200);
    expect(JSON.parse(legacy.body.plaintext)).toEqual(args);
  });
});
