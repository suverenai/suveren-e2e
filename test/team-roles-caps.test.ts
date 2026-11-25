/**
 * Team permissions, above-cap approval, read limits (TR5/TR6) — end to end
 * against the real Authority Server.
 *
 * Direction: content/0.7/review.md — "Group roles: who may grant, who
 * approves above the cap" and "A group can cap reads and capability
 * switches" (hap-protocol #14). Written from the DECISIONS (maintainer,
 * 2026-10-14), not from the implementation's code or its unit test — this file calls the
 * real running AS over HTTP exactly as a gateway or another conformant
 * client would, the same style as the existing team-approval.test.ts.
 *
 * Three real users (never mocked): a GRANTOR who is the team's sole
 * grantor and never an approver, and two APPROVERS who are never
 * grantors — the minimum shape the task brief asks for. A grantor who is
 * also one of the two approvers is used separately (Profile B below) to
 * exercise the proposer-exclusion rule, which only bites when the overlap
 * exists.
 *
 * What is covered, mapped to the decisions:
 *   1. A grantor who is not an approver can sign; an approver who is not a
 *      grantor cannot (403 OWNER_NOT_APPROVER — wire code unchanged).
 *   2. Hard caps refuse signing: a numeric cap, an enum (capability-switch)
 *      cap — pinning the real, permissive-first `values` order — and an
 *      omitted gatekeeper-enforced (`enforcedBy: "gatekeeper"`) capped
 *      field, which refuses rather than silently filling a default.
 *   3. With NO approvers configured, an 'approval'-kind cap is still
 *      enforced as hard.
 *   4. An approval-kind cap promotes an 'automatic' request to a signed
 *      'review_above_cap' mandate.
 *   5. A cap on a CUMULATIVE bound (a daily count or total) is always hard
 *      (DEC-71, suveren-as #142): signing above it is refused, and team
 *      settings refuse an approval-kind cap on it (CAP_KIND_NOT_SUPPORTED).
 *      Above-cap approval runs per single action: every escalation scenario
 *      here uses a per-transaction bound (charge, purchase, sales, calendar).
 *   6. A proposal commits only after the configured number of DISTINCT
 *      approvals (N-of-M, tested at N=2 with two different approvers).
 *   7. The proposer's own approval is refused (APPROVER_IS_PROPOSER) and
 *      never counts, even when the proposer is also a configured approver.
 *   8. An approver set that cannot reach the required count without the
 *      proposer refuses the TICKET outright (APPROVAL_IMPOSSIBLE) — no
 *      proposal is ever created.
 *   9. Personal mode, and the pre-existing owner-chosen review_above_cap
 *      (no team governance at all), are untouched — the published v0.7
 *      conformance vector keeps passing.
 *  10. A migrated (pre-TR5) team config — `approvers` only, no `grantors`,
 *      no `approvals` — keeps granting and defaults `approvals` to 1.
 *
 * Only the AS is needed for all of the above (no gateway, no MCP
 * connector) — the same scope as team-approval.test.ts, and the scope the
 * README's "Which layer to put a test in" calls for: the subject under
 * test (grantor/approver roles, cap kinds, N-of-M approval) lives entirely
 * at the Authority Server's HTTP surface, which is reachable directly.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { hashGateContent, hashExecutionContext, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';
import { AS_DIR } from '../src/helpers/as-dir.js';

// ── Feature gate: skip only when this AS checkout lacks TR5/TR6 ────────────
// Mirrors ws-account-one-workspace.test.ts's gate (a known route file must
// exist AND mention the new concept) so CI shows a loud skip, never a
// silent false pass, against an AS checkout that predates team roles and caps.
const PROFILE_CONFIG_ROUTE = join(AS_DIR, 'src', 'app', 'api', 'groups', '[id]', 'profile-config', '[profileId]', 'route.ts');
const hasTeamRolesCaps =
  existsSync(PROFILE_CONFIG_ROUTE) && readFileSync(PROFILE_CONFIG_ROUTE, 'utf8').includes('grantors');

const SP_PORT = 19210; // unused in the suite as of 2026-10-14 (max assigned elsewhere: 18951)
const SP_URL = `http://localhost:${SP_PORT}`;
const PROFILES_DIR = join(process.cwd(), '..', 'hap-profiles');

const EMAIL_ID = PROFILE_V07.email; // email@0.8 — hard enum + hard gatekeeper + approval cumulative
const RECORDS_ID = PROFILE_V07.records; // records@0.6 — personal mode (owner-chosen review_above_cap)
// DEC-71 (suveren-as #142): a team cap on a CUMULATIVE bound is always hard, so every above-cap
// approval scenario uses a PER-TRANSACTION bound: charge amount_max, purchase spend_max, sales value_max,
// calendar booking_duration_max (each its own (group, profile) config).
const CHARGE_ID = PROFILE_V07.charge; // per-payment approval cap: escalation + N-of-2
const PURCHASE_ID = PROFILE_V07.purchase; // per-purchase approval cap: proposer exclusion
const SALES_ID = PROFILE_V07.sales; // per-quote value cap: no-approvers-hard + impossible set
const CALENDAR_ID = PROFILE_V07.calendar; // bare per-booking cap: migrated (pre-TR5) config

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);

async function api(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${SP_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, body: json as Record<string, unknown> };
}

const putProfileConfig = (
  apiKey: string,
  groupId: string,
  profileId: string,
  config: {
    approvers: string[];
    grantors?: 'all' | string[];
    approvals?: number;
    caps?: Record<string, number | string | { value: number | string; kind: 'hard' | 'approval' }>;
  },
) => api('PUT', `/api/groups/${groupId}/profile-config/${encodeURIComponent(profileId)}`, apiKey, config);

interface User { id: string; did: string; apiKey: string }

let grantor: User;
let approverA: User;
let approverB: User;
let soloOwner: User; // never joins any team — "account is Personal or in one team" (WS0)
                      // means the personal-mode scenario needs its OWN user, not the grantor
let teamGroupId: string; // every team scenario lives here, on a DIFFERENT profile each —
                          // config is keyed per (group, profile), so this is enough isolation

beforeAll(async () => {
  await pm.startSP(SP_PORT);

  const g = await sp.register('Grantor Only', `grantor-tr5-${Date.now()}@test.local`);
  grantor = { id: g.user.id, did: g.user.did, apiKey: g.apiKey };
  const a = await sp.register('Approver A', `approver-a-tr5-${Date.now()}@test.local`);
  approverA = { id: a.user.id, did: a.user.did, apiKey: a.apiKey };
  const b = await sp.register('Approver B', `approver-b-tr5-${Date.now()}@test.local`);
  approverB = { id: b.user.id, did: b.user.did, apiKey: b.apiKey };
  const s = await sp.register('Solo Owner', `solo-owner-tr5-${Date.now()}@test.local`);
  soloOwner = { id: s.user.id, did: s.user.did, apiKey: s.apiKey };

  const team = await sp.createGroup(grantor.apiKey, `TR5 Team ${Date.now()}`);
  teamGroupId = team.group.id;
  await sp.joinGroup(approverA.apiKey, team.inviteCode, grantor.apiKey);
  await sp.joinGroup(approverB.apiKey, team.inviteCode, grantor.apiKey);
}, 60_000);

afterAll(async () => {
  await pm.killAll();
}, 30_000);

// ── 1. Grantors vs approvers, hard caps (email@0.8) ─────────────────────────

describe.skipIf(!hasTeamRolesCaps)('Grantor/approver roles + hard caps (email@0.8)', () => {
  const EMAIL_BASE = {
    profile_id: EMAIL_ID,
    profile_hash: profileHashFor(EMAIL_ID, PROFILES_DIR),
    group_id: '', // filled per call
    domain: 'ignored-for-teams',
    scope_hash: computeScopeHash({}, []),
    commitment_mode: 'automatic' as const,
    gate_content_hashes: hashGateContent({ intent: 'Send email on the team\'s behalf.' }),
    execution_context_hash: hashExecutionContext({ action_type: 'send' }),
  };

  beforeAll(async () => {
    const res = await putProfileConfig(grantor.apiKey, teamGroupId, EMAIL_ID, {
      approvers: [approverA.id, approverB.id],
      grantors: [grantor.id],
      approvals: 2,
      caps: {
        read_access: { value: 'none', kind: 'hard' },
        read_max_age_days: { value: 30, kind: 'approval' }, // gatekeeper-enforced → always hard regardless
        send_daily_max: { value: 2, kind: 'hard' }, // a daily count can only be hard (DEC-71)
      },
    });
    expect(res.status).toBe(200);
  });

  it('an approver who is NOT a grantor cannot sign (403 OWNER_NOT_APPROVER)', async () => {
    const res = await api('POST', '/api/as/mandate', approverA.apiKey, {
      ...EMAIL_BASE,
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      group_id: teamGroupId,
      did: approverA.did,
      bounds: { profile: EMAIL_ID, read_access: 'none', read_max_age_days: 30, send_daily_max: 1, setup_daily_max: 0 },
    });
    expect(res.status).toBe(403);
    expect((res.body.errors as Array<Record<string, unknown>>)[0].code).toBe('OWNER_NOT_APPROVER');
  });

  it('a hard enum cap refuses a more permissive requested value (422 cap_exceeded) — real permissive-first values order', async () => {
    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      ...EMAIL_BASE,
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      group_id: teamGroupId,
      did: grantor.did,
      bounds: { profile: EMAIL_ID, read_access: 'unlimited', read_max_age_days: 30, send_daily_max: 1, setup_daily_max: 0 },
    });
    expect(res.status).toBe(422);
    expect((res.body.errors as Array<Record<string, unknown>>)[0].code).toBe('cap_exceeded');
  });

  it('an omitted gatekeeper-enforced capped field refuses signing rather than filling a default (422 cap_exceeded)', async () => {
    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      ...EMAIL_BASE,
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      group_id: teamGroupId,
      did: grantor.did,
      bounds: { profile: EMAIL_ID, read_access: 'none', send_daily_max: 1, setup_daily_max: 0 }, // read_max_age_days omitted
    });
    expect(res.status).toBe(422);
    const err = (res.body.errors as Array<Record<string, unknown>>)[0];
    expect(err.code).toBe('cap_exceeded');
    expect(err.field).toBe('read_max_age_days');
  });

  it('a grantor who is not an approver CAN sign within the caps', async () => {
    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      ...EMAIL_BASE,
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      group_id: teamGroupId,
      did: grantor.did,
      bounds: { profile: EMAIL_ID, read_access: 'none', read_max_age_days: 30, send_daily_max: 1, setup_daily_max: 0 },
    });
    expect(res.status).toBe(201);
    expect(res.body.above_cap).toBeFalsy();
  });

  it('a daily cap is hard: above it signing is refused (422 cap_exceeded), although the team has approvers (DEC-71)', async () => {
    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      ...EMAIL_BASE,
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      group_id: teamGroupId,
      did: grantor.did,
      bounds: { profile: EMAIL_ID, read_access: 'none', read_max_age_days: 30, send_daily_max: 5, setup_daily_max: 0 },
    });
    expect(res.status).toBe(422);
    const err = (res.body.errors as Array<Record<string, unknown>>)[0];
    expect(err.code).toBe('cap_exceeded');
    expect(err.field).toBe('send_daily_max');
  });

  it('team settings refuse an approval-kind cap on the daily count (400 CAP_KIND_NOT_SUPPORTED)', async () => {
    const res = await putProfileConfig(grantor.apiKey, teamGroupId, EMAIL_ID, {
      approvers: [approverA.id, approverB.id], grantors: [grantor.id], approvals: 2,
      caps: { send_daily_max: { value: 2, kind: 'approval' } },
    });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('CAP_KIND_NOT_SUPPORTED');
  });
});

// ── 2. Above-cap promotion, ticket escalation + N-of-2 approval (charge@0.6, per-payment cap) ──

describe.skipIf(!hasTeamRolesCaps)('Above-cap approval per payment + N-of-2 distinct approvals (charge@0.6)', () => {
  const SCOPE = computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']);
  let authorizationIdA = '';
  const chargeTicket = (amount: number, extra: Record<string, unknown> = {}) =>
    sp.postTicket(grantor.apiKey, {
      authorizationId: authorizationIdA, profileId: CHARGE_ID, action: 'charge', actionType: 'charge', amount,
      executionContext: { amount, currency: 'EUR', action_type: 'charge' }, ...extra,
    });
  const TOOL_ARGS = { amount: { value: '250.00', currency: 'EUR' }, description: 'Escalated payment' };

  beforeAll(async () => {
    const cfg = await putProfileConfig(grantor.apiKey, teamGroupId, CHARGE_ID, {
      approvers: [approverA.id, approverB.id], grantors: [grantor.id], approvals: 2,
      caps: { amount_max: { value: 100, kind: 'approval' } },
    });
    expect(cfg.status).toBe(200);
  });

  it('an approval-kind cap on a per-payment bound promotes automatic → signed review_above_cap', async () => {
    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: CHARGE_ID,
      profile_hash: profileHashFor(CHARGE_ID, PROFILES_DIR),
      group_id: teamGroupId,
      domain: 'ignored-for-teams',
      scope_hash: SCOPE,
      did: grantor.did,
      commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: "Take payments on the team's behalf." }),
      execution_context_hash: hashExecutionContext({ action_type: 'charge', amount: 500, currency: 'EUR' }),
      bounds: { profile: CHARGE_ID, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.above_cap).toBe(true);
    expect(res.body.commitment_mode).toBe('review_above_cap');
    authorizationIdA = res.body.authorization_id as string;
  });

  it('a payment within the team cap runs; one above it → 409 APPROVAL_REQUIRED naming both approvers', async () => {
    expect((await chargeTicket(50)).status).toBe(201);
    const res = await chargeTicket(250);
    expect(res.status).toBe(409);
    const err = (res.body.errors as Array<Record<string, unknown>>)[0];
    expect(err.code).toBe('APPROVAL_REQUIRED');
    expect(err.field).toBe('amount_max');
    expect(err.approvers).toEqual([approverA.id, approverB.id]);
  });

  let proposalId = '';

  it('a proposal routed to both approvers does NOT commit after only one approval (test 1 of N=2)', async () => {
    const created = await api('POST', '/api/proposals', grantor.apiKey, {
      authorization_id: authorizationIdA, profile_id: CHARGE_ID,
      tool: 'mollie__CreatePaymentLink', tool_args: TOOL_ARGS,
      execution_context: { amount: 250, currency: 'EUR', action_type: 'charge' },
      pending_approvers: [approverA.id, approverB.id],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    proposalId = (created.body.proposal as { id: string }).id;
    const res = await api('POST', `/api/proposals/${proposalId}/approve`, approverA.apiKey);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('pending');
    expect(res.body.approvedCount).toBe(1);
    expect(res.body.requiredApprovals).toBe(2);
    expect(res.body.remainingApprovers).toEqual([approverB.id]);
  });

  it('the SECOND distinct approval commits it (test 2 of N=2)', async () => {
    const res = await api('POST', `/api/proposals/${proposalId}/approve`, approverB.apiKey);
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('committed');
    expect(res.body.approvedCount).toBe(2);
  });

  it('the ticket replayed with the committed proposalId now executes (201)', async () => {
    const res = await chargeTicket(250, { action: 'mollie__CreatePaymentLink', proposalId, toolArgs: TOOL_ARGS });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
  });
});

// ── 3. Proposer exclusion: APPROVER_IS_PROPOSER, never counted (purchase@0.7, per-purchase cap, overlap) ─

describe.skipIf(!hasTeamRolesCaps)('Proposer exclusion — the proposer cannot approve their own above-cap action (purchase@0.7)', () => {
  let authorizationIdB = '';
  const purchase = (spend: number) => sp.postTicket(grantor.apiKey, {
    authorizationId: authorizationIdB, profileId: PURCHASE_ID, action: 'purchase', actionType: 'purchase',
    executionContext: { spend, currency: 'EUR', category: 'office', action_type: 'purchase' },
  });

  beforeAll(async () => {
    // The GRANTOR is also one of the two configured approvers here — the overlap case the rule exists
    // for. approvals=1 keeps it solvable once the proposer is excluded (approverA remains).
    const cfg = await putProfileConfig(grantor.apiKey, teamGroupId, PURCHASE_ID, {
      approvers: [grantor.id, approverA.id],
      grantors: [grantor.id],
      approvals: 1,
      caps: { spend_max: { value: 100, kind: 'approval' } },
    });
    expect(cfg.status).toBe(200);

    const res = await api('POST', '/api/as/mandate', grantor.apiKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: PURCHASE_ID,
      profile_hash: profileHashFor(PURCHASE_ID, PROFILES_DIR),
      group_id: teamGroupId,
      domain: 'ignored-for-teams',
      scope_hash: computeScopeHash({}, []),
      did: grantor.did,
      commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: "Buy office supplies on the team's behalf." }),
      execution_context_hash: hashExecutionContext({ action_type: 'purchase' }),
      bounds: { profile: PURCHASE_ID, spend_max: 500, spend_daily_max: 5000, spend_monthly_max: 50_000, transaction_count_daily_max: 50 },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    expect(res.body.above_cap).toBe(true);
    authorizationIdB = res.body.authorization_id as string;
  });

  it('exceeding the cap escalates with BOTH configured approvers named, proposer included', async () => {
    expect((await purchase(50)).status).toBe(201); // within the per-purchase cap
    const res = await purchase(250);
    expect(res.status).toBe(409);
    const err = (res.body.errors as Array<Record<string, unknown>>)[0];
    expect(err.code).toBe('APPROVAL_REQUIRED');
    expect(err.approvers).toEqual([grantor.id, approverA.id]);
  });

  it('the proposer (grantor) cannot approve their own proposal: 403 APPROVER_IS_PROPOSER', async () => {
    const created = await api('POST', '/api/proposals', grantor.apiKey, {
      authorization_id: authorizationIdB,
      profile_id: PURCHASE_ID,
      tool: 'purchase__order',
      tool_args: { item: 'Escalated purchase', spend: 250 },
      execution_context: { spend: 250, currency: 'EUR', category: 'office', action_type: 'purchase' },
      pending_approvers: [grantor.id, approverA.id],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const proposalId = (created.body.proposal as { id: string }).id;

    const res = await api('POST', `/api/proposals/${proposalId}/approve`, grantor.apiKey);
    expect(res.status).toBe(403);
    expect((res.body as { errors?: Array<Record<string, unknown>> }).errors?.[0]?.code).toBe('APPROVER_IS_PROPOSER');

    // Never counted: approverA alone is enough to commit (approvals=1).
    const approved = await api('POST', `/api/proposals/${proposalId}/approve`, approverA.apiKey);
    expect(approved.status).toBe(200);
    expect(approved.body.status).toBe('committed');
    expect(approved.body.approvedCount).toBe(1);
  });
});

// ── 4. No approvers → every cap is hard; an impossible approver set refuses the TICKET, no dead proposal (sales@0.4) ─

describe.skipIf(!hasTeamRolesCaps)('No-approvers hard caps + impossible approver set (sales@0.4)', () => {
  const SALES_BOUNDS = {
    profile: SALES_ID, read_access: 'unlimited', value_max: 5000, discount_max: 10,
    order_value_daily_max: 50_000, quote_daily_max: 20, send_daily_max: 20, order_daily_max: 20, setup_daily_max: 0,
  };
  const mandate = () => api('POST', '/api/as/mandate', grantor.apiKey, {
    authorization_id: mintAuthorizationId(),
    supported_versions: ['0.7'],
    profile_id: SALES_ID,
    profile_hash: profileHashFor(SALES_ID, PROFILES_DIR),
    group_id: teamGroupId,
    domain: 'ignored-for-teams',
    scope_hash: computeScopeHash({}, []),
    did: grantor.did,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'Make quotes.' }),
    execution_context_hash: hashExecutionContext({ action_type: 'quote' }),
    bounds: SALES_BOUNDS,
  });

  it('with NO approvers at all, an "approval"-kind cap is still enforced as hard (422 cap_exceeded)', async () => {
    const cfg = await putProfileConfig(grantor.apiKey, teamGroupId, SALES_ID, {
      approvers: [],
      grantors: [grantor.id],
      caps: { value_max: { value: 1000, kind: 'approval' } }, // stored kind is irrelevant with no approvers
    });
    expect(cfg.status).toBe(200);
    const res = await mandate();
    expect(res.status).toBe(422);
    expect((res.body.errors as Array<Record<string, unknown>>)[0].code).toBe('cap_exceeded');
  });

  it('reconfigured with 2 approvers (one is the grantor) needing 2 distinct approvals → ticket refuses APPROVAL_IMPOSSIBLE, no proposal', async () => {
    const cfg = await putProfileConfig(grantor.apiKey, teamGroupId, SALES_ID, {
      approvers: [grantor.id, approverA.id],
      grantors: [grantor.id],
      approvals: 2, // excluding the proposer leaves only approverA (1) — short of 2
      caps: { value_max: { value: 1000, kind: 'approval' } },
    });
    expect(cfg.status).toBe(200);
    const m = await mandate();
    expect(m.status, JSON.stringify(m.body)).toBe(201);
    expect(m.body.above_cap).toBe(true);
    const authorizationIdC = m.body.authorization_id as string;
    const quote = (value: number) => sp.postTicket(grantor.apiKey, {
      authorizationId: authorizationIdC, profileId: SALES_ID, action: 'erp__create_quote', actionType: 'quote',
      executionContext: { value, discount_pct: 0, currency: 'EUR', action_type: 'quote' },
    });
    expect((await quote(500)).status).toBe(201); // within the per-quote cap
    // Above it — and the only non-proposer approver (1) can never reach the required 2: refused outright.
    const second = await quote(2000);
    expect(second.status).toBe(403);
    expect((second.body.errors as Array<Record<string, unknown>>)[0].code).toBe('APPROVAL_IMPOSSIBLE');
  });
});

// ── 5. Personal mode / owner-chosen review_above_cap is untouched (records@0.6, no team governance) ─

describe.skipIf(!hasTeamRolesCaps)('Personal mode — owner-chosen review_above_cap (no team governance) keeps working', () => {
  it('the owner naming themself as their own sole above-cap approver still escalates to APPROVAL_REQUIRED, never APPROVAL_IMPOSSIBLE', async () => {
    // soloOwner never joins the team — WS0's "Personal OR one team" rule
    // means this scenario needs its own ungoverned account, not the grantor.
    const personalGroupId = await sp.getPersonalGroupId(soloOwner.apiKey);

    const mandate = await api('POST', '/api/as/mandate', soloOwner.apiKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: RECORDS_ID,
      profile_hash: profileHashFor(RECORDS_ID, PROFILES_DIR),
      group_id: personalGroupId,
      domain: soloOwner.id,
      scope_hash: computeScopeHash({}, []),
      did: soloOwner.did,
      commitment_mode: 'review_above_cap',
      above_cap_caps: { write_daily_max: 1 },
      above_cap_approvers: [soloOwner.id], // the owner names THEMSELF — pre-existing mechanism, untouched by TR5
      gate_content_hashes: hashGateContent({ intent: 'Personal records authority.' }),
      execution_context_hash: hashExecutionContext({ action_type: 'write' }),
      bounds: { profile: RECORDS_ID, read_access: 'unlimited', write_daily_max: 3, delete_access: 'none', archive_access: 'none' },
    });
    expect(mandate.status).toBe(201);
    const authorizationIdPersonal = mandate.body.authorization_id as string;

    const first = await sp.postTicket(soloOwner.apiKey, {
      authorizationId: authorizationIdPersonal,
      profileId: RECORDS_ID,
      action: 'create_record',
      actionType: 'write',
      executionContext: { action_type: 'write' },
    });
    expect(first.status).toBe(201);

    const second = await sp.postTicket(soloOwner.apiKey, {
      authorizationId: authorizationIdPersonal,
      profileId: RECORDS_ID,
      action: 'create_record',
      actionType: 'write',
      executionContext: { action_type: 'write' },
    });
    expect(second.status).toBe(409); // NOT 403 APPROVAL_IMPOSSIBLE — ungoverned, the TR5 rule does not apply
    expect((second.body.errors as Array<Record<string, unknown>>)[0].code).toBe('APPROVAL_REQUIRED');
  });
});

// ── 6. A migrated (pre-TR5) team config keeps granting; approvals defaults to 1 (calendar@0.6, bare per-booking cap) ─

describe.skipIf(!hasTeamRolesCaps)('Migrated team config (approvers only, no grantors/approvals field) — migration 012', () => {
  it('a config written the OLD way (bare numeric cap, approvers doubling as grantors) still lets an approver grant, and commits after exactly 1 approval', async () => {
    // The pre-TR5 shape: no `grantors`, no `approvals`, a bare number for the cap. A bare cap on a
    // PER-TRANSACTION bound keeps the legacy default 'approval' (on a cumulative bound it is now
    // stored hard, DEC-71 — so this uses the per-booking duration).
    const cfg = await putProfileConfig(grantor.apiKey, teamGroupId, CALENDAR_ID, {
      approvers: [grantor.id, approverA.id],
      caps: { booking_duration_max: 60 },
    });
    expect(cfg.status).toBe(200);

    const mandate = await api('POST', '/api/as/mandate', grantor.apiKey, {
      authorization_id: mintAuthorizationId(),
      supported_versions: ['0.7'],
      profile_id: CALENDAR_ID,
      profile_hash: profileHashFor(CALENDAR_ID, PROFILES_DIR),
      group_id: teamGroupId,
      domain: 'ignored-for-teams',
      scope_hash: computeScopeHash({}, []),
      did: grantor.did,
      commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: 'Legacy-config calendar authority.' }),
      execution_context_hash: hashExecutionContext({ action_type: 'booking' }),
      bounds: { profile: CALENDAR_ID, booking_daily_max: 10, booking_duration_max: 240, lookahead_days_max: 30 },
    });
    // grantors falls back to approvers → the approver-that-is-also-a-grantor can sign.
    expect(mandate.status, JSON.stringify(mandate.body)).toBe(201);
    expect(mandate.body.above_cap).toBe(true);
    const authorizationIdLegacy = mandate.body.authorization_id as string;
    const book = (duration: number) => sp.postTicket(grantor.apiKey, {
      authorizationId: authorizationIdLegacy, profileId: CALENDAR_ID, action: 'calendar__create_event', actionType: 'booking',
      executionContext: { duration, lookahead: 1, action_type: 'booking' },
    });

    expect((await book(30)).status).toBe(201);
    const escalated = await book(120);
    expect(escalated.status).toBe(409);
    const err = (escalated.body.errors as Array<Record<string, unknown>>)[0];
    expect(err.code).toBe('APPROVAL_REQUIRED');
    expect(err.approvers).toEqual([grantor.id, approverA.id]);

    const created = await api('POST', '/api/proposals', grantor.apiKey, {
      authorization_id: authorizationIdLegacy,
      profile_id: CALENDAR_ID,
      tool: 'calendar__create_event',
      tool_args: { summary: 'Escalated meeting', duration: 120 },
      execution_context: { duration: 120, lookahead: 1, action_type: 'booking' },
      pending_approvers: [grantor.id, approverA.id],
    });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const proposalId = (created.body.proposal as { id: string }).id;

    // approvals defaults to 1 — a SINGLE distinct (non-proposer) approval commits it.
    const approved = await api('POST', `/api/proposals/${proposalId}/approve`, approverA.apiKey);
    expect(approved.status).toBe(200);
    expect(approved.body.status).toBe('committed');
    expect(approved.body.requiredApprovals).toBe(1);
    expect(approved.body.approvedCount).toBe(1);
  });
});
