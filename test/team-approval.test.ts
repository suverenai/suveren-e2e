/**
 * Team approval + intent sharing (Phase 4a).
 *
 * Exercises the multi-party / above-cap authority flow end to end against the
 * real Authority Server — the scenarios the rest of the suite didn't cover:
 *
 *  1. A team admin sets a profile-config CAP + APPROVERS.
 *  2. A team member creates an authorization ABOVE the cap → it's accepted but
 *     flagged above_cap, and carries E2EE intent (ciphertext + per-approver keys).
 *  3. INTENT SHARING: an approver can fetch the encrypted intent; an outsider
 *     (not an approver) is denied.
 *  4. TEAM APPROVAL: when the member's payment exceeds the team's per-payment
 *     cap, the ticket escalates to 409 approval_required (routed to the approvers)
 *     instead of a hard 403. A proposal is created, the approver approves it,
 *     and the proposal commits (a receipt is issued).
 *
 * Only the AS is needed (no gateway).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { hashGateContent, hashExecutionContext, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AS_DIR } from '../src/helpers/as-dir.js';
import { e2ePort } from '../src/helpers/ports.js';

// TR5/TR6: cumulative team caps escalate from the first write
// over the cap. An AS checkout before it escalated only past the mandate's own
// bound. Detected from the AS source (same gate as team-roles-caps.test.ts).
const PROFILE_CONFIG_ROUTE = join(AS_DIR, 'src', 'app', 'api', 'groups', '[id]', 'profile-config', '[profileId]', 'route.ts');
const hasTeamRolesCaps =
  existsSync(PROFILE_CONFIG_ROUTE) && readFileSync(PROFILE_CONFIG_ROUTE, 'utf8').includes('grantors');

const SP_PORT = e2ePort(15300);
const SP_URL = `http://localhost:${SP_PORT}`;
const PROFILE_ID = PROFILE_V07.charge;
const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);

let adminKey = '';
let adminId = '';
let agentKey = '';
let agentId = '';
let agentDid = '';
let outsiderKey = '';
let groupId = '';
let authorizationId = '';

// The team's approval cap is on a PER-PAYMENT bound (amount_max 100). A cap on a cumulative bound is
// always hard since DEC-71 (suveren-as #142), so above-cap escalation lives on per-transaction bounds.
// The mandate's own per-payment bound (500) is above the cap, so it is flagged above_cap.
const BOUNDS = {
  profile: PROFILE_ID, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50,
};
const SCOPE = { currency: 'EUR', action_type: 'charge' };
const SCOPE_KEYS = ['currency', 'action_type'];
const EXEC_HASH = hashExecutionContext({ action_type: 'charge', amount: BOUNDS.amount_max, currency: 'EUR' });
const INTENT = {
  intent_ciphertext: 'BASE64_CIPHERTEXT_e2e==',
  // encrypted_keys is keyed by approver userId — filled in once admin is registered.
  encrypted_keys: {} as Record<string, { ct: string; enc: string }>,
  approvers_frozen: [] as string[],
};

async function api(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${SP_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, body: json as Record<string, unknown> };
}

const charge = (amount: number) =>
  sp.postTicket(agentKey, {
    authorizationId,
    profileId: PROFILE_ID,
    action: 'charge',
    actionType: 'charge',
    amount,
    executionContext: { amount, currency: 'EUR', action_type: 'charge' },
  });

beforeAll(async () => {
  await pm.startSP(SP_PORT);

  const admin = await sp.register('Team Admin', `admin-team-${Date.now()}@test.local`);
  adminKey = admin.apiKey;
  adminId = admin.user.id;

  const agent = await sp.register('Team Agent', `agent-team-${Date.now()}@test.local`);
  agentKey = agent.apiKey;
  agentId = agent.user.id;
  agentDid = agent.user.did;

  const outsider = await sp.register('Outsider', `outsider-team-${Date.now()}@test.local`);
  outsiderKey = outsider.apiKey;

  // Admin creates the team; agent joins.
  const grp = await sp.createGroup(adminKey, 'Approval Test Team');
  groupId = grp.group.id;
  await sp.joinGroup(agentKey, grp.inviteCode, adminKey);

  // Admin configures the profile: an approval cap of 100 per payment, with the admin AND
  // the agent as approvers.
  //
  // The agent is in the list because in a team group the AS now refuses an
  // attest from anyone who is not a configured approver for that profile (403
  // OWNER_NOT_APPROVER) — membership alone is not authority to grant. The agent
  // runs the ceremony below, so it must be named here or the whole scenario
  // stops at its first request. Being allowed to GRANT is a separate question
  // from the cap: the cap still limits what may be granted without escalation,
  // which is what the rest of this file exercises.
  await sp.setProfileConfig(adminKey, groupId, PROFILE_ID, {
    approvers: [adminId, agentId],
    caps: { amount_max: { value: 100, kind: 'approval' } },
  } as never);

  // The agent's authorization shares its intent with the admin (approver).
  INTENT.encrypted_keys = { [adminId]: { ct: 'CT_FOR_ADMIN==', enc: 'ENC_FOR_ADMIN==' } };
  INTENT.approvers_frozen = [adminId];
}, 60_000);

afterAll(async () => {
  await pm.killAll();
}, 30_000);

// ── 1. Above-cap attestation (accepted, flagged, with shared intent) ──────────

describe('Above-cap authorization with shared intent', () => {
  it('accepts an above-cap team authorization and flags it above_cap', async () => {
    const res = await api('POST', '/api/as/mandate', agentKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: PROFILE_ID,
      profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
      group_id: groupId,
      bounds: BOUNDS,
      // bounds_hash omitted → AS computes it
      scope_hash: computeScopeHash(SCOPE, SCOPE_KEYS),
      domain: agentId, // team: resolved domain is the member's userId
      did: agentDid,
      commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: "Take payments on the team's behalf." }),
      execution_context_hash: EXEC_HASH,
      ...INTENT,
    });

    expect(res.status).toBe(201);
    expect(res.body.above_cap).toBe(true);
    authorizationId = res.body.authorization_id as string;
    expect(authorizationId).toBeTruthy();
  });
});

// ── 2. Intent sharing (E2EE) ──────────────────────────────────────────────────

describe('Intent sharing', () => {
  it('lets an approver fetch the encrypted intent', async () => {
    const res = await api('GET', `/api/authorizations/${encodeURIComponent(authorizationId)}/intent`, adminKey);
    expect(res.status).toBe(200);
    // The approver receives the ciphertext + their own wrapped key.
    expect(JSON.stringify(res.body)).toContain('CT_FOR_ADMIN');
  });

  it('denies a non-approver outsider', async () => {
    const res = await api('GET', `/api/authorizations/${encodeURIComponent(authorizationId)}/intent`, outsiderKey);
    expect(res.status).toBe(403);
  });
});

// ── 2b. Intent-disclosure C2 binding (the AS rejects a tampered disclosure) ────

describe('Intent disclosure — C2 binding', () => {
  const attestWithIntent = (overrides: Record<string, unknown>) =>
    api('POST', '/api/as/mandate', agentKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: PROFILE_ID,
      profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
      group_id: groupId,
      bounds: BOUNDS,
      scope_hash: computeScopeHash(SCOPE, SCOPE_KEYS),
      domain: agentId,
      did: agentDid,
      commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: "Take payments on the team's behalf." }),
      execution_context_hash: EXEC_HASH,
      ...INTENT,
      ...overrides,
    });

  it('rejects an attestation whose intent_disclosure_hash does not match', async () => {
    const res = await attestWithIntent({ intent_disclosure_hash: 'sha256:deadbeef' });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toContain('intent_disclosure_hash');
  });

  it('rejects encrypted_keys carrying a recipient not in approvers_frozen', async () => {
    const res = await attestWithIntent({
      encrypted_keys: { ...INTENT.encrypted_keys, 'ghost-user': { ct: 'X==', enc: 'Y==' } },
    });
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).toContain('ghost-user');
  });
});

// ── 3. Team approval: escalate → approve → commit ─────────────────────────────

describe('Team approval (above-cap escalation)', () => {
  it('a payment within the team cap runs; one above it escalates to approval_required', async () => {
    // Within the team's per-payment cap (100): a ticket at once.
    expect((await charge(50)).status).toBe(201);
    // Above the cap (250 > 100) but within the mandate's own bound (500): the authority is above-cap
    // and the profile has approvers, so it escalates to 409 (not a hard 403).
    const escalated = await charge(250);
    expect(escalated.status).toBe(409);
    const errors = escalated.body.errors as Array<Record<string, unknown>>;
    expect(errors[0].code).toBe('APPROVAL_REQUIRED');
    expect(errors[0].field).toBe('amount_max');
    // The escalation routes to EXACTLY the configured approver set, in configured order.
    expect(errors[0].approvers).toEqual([adminId, agentId]);
  });

  it('routes a proposal to the approver, who approves it → committed', async () => {
    // The gateway would create this on the 409; we create it directly.
    const created = await api('POST', '/api/proposals', agentKey, {
      authorization_id: authorizationId,
      profile_id: PROFILE_ID,
      tool: 'mollie__CreatePaymentLink',
      tool_args: { amount: { value: '250.00', currency: 'EUR' }, description: 'Escalated payment' },
      execution_context: { amount: 250, currency: 'EUR', action_type: 'charge' },
      pending_approvers: [adminId],
    });
    expect(created.status).toBe(201);
    const proposalId = (created.body.proposal as { id: string }).id;
    expect(proposalId).toBeTruthy();

    // The approver approves; with the only approver signed off, it commits.
    const approved = await api('POST', `/api/proposals/${proposalId}/approve`, adminKey);
    expect(approved.status).toBe(200);
    expect(approved.body.status).toBe('committed');
  });

  it('does not let a non-approver approve', async () => {
    const created = await api('POST', '/api/proposals', agentKey, {
      authorization_id: authorizationId,
      profile_id: PROFILE_ID,
      tool: 'mollie__CreatePaymentLink',
      tool_args: { amount: { value: '260.00', currency: 'EUR' }, description: 'Another payment' },
      execution_context: { amount: 260, currency: 'EUR', action_type: 'charge' },
      pending_approvers: [adminId],
    });
    const proposalId = (created.body.proposal as { id: string }).id;

    const res = await api('POST', `/api/proposals/${proposalId}/approve`, outsiderKey);
    expect(res.status).not.toBe(200);
  });
});
