/**
 * DEC-71 (maintainer, 2026-11-19; suveren-as #142): a team cap on a CUMULATIVE bound (a daily or
 * monthly total, a count per day) is always a hard limit. "Needs approval above the limit" works per
 * single action only (v0.8 protocol, Commitment Modes rule 7).
 *
 * Real Authority Server, the charge profile: `amount_max` is per payment, `amount_daily_max` a daily
 * total.
 *  - Team settings refuse an approval cap on a cumulative bound (400 CAP_KIND_NOT_SUPPORTED).
 *  - A bare number on a cumulative bound is stored hard; GET reports the kind it is ENFORCED as
 *    (`capKinds`), so a gateway never offers "needs approval" where the AS would refuse it.
 *  - With only the hard daily cap, a v0.8 mandate within it signs as asked (automatic); above it is
 *    refused (422 GROUP_CAP_EXCEEDED), although the team has an approver.
 *  - A per-payment approval cap promotes the mandate to review_above_cap (v0.8 signs every reachable
 *    approval cap); the daily total stays hard beside it.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { join } from 'node:path';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { hashGateContent, computeScopeHash, computeExecutionContextHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';

const SP_PORT = 15310; // unused elsewhere in the suite (2026-11-19)
const SP_URL = `http://localhost:${SP_PORT}`;
const PROFILES_DIR = join(process.cwd(), '..', 'hap-profiles');
const CHARGE = PROFILE_V07.charge;
const KEY_ORDER = ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max'];

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);

async function api(method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${SP_URL}${path}`, {
    method, headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey }, body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as Record<string, any> };
}

let owner: { apiKey: string; user: { id: string; did: string } };
let approver: { apiKey: string; user: { id: string } };
let groupId = '';
const configPath = () => `/api/groups/${groupId}/profile-config/${encodeURIComponent(CHARGE)}`;

function mandate(bounds: Record<string, number>) {
  return sp.submitMandateRaw(owner.apiKey, {
    authorization_id: mintAuthorizationId(),
    profile_id: CHARGE,
    profile_hash: profileHashFor(CHARGE, PROFILES_DIR),
    group_id: groupId,
    bounds: { profile: CHARGE, ...bounds },
    scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
    domain: 'owner', did: owner.user.did, commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'DEC-71: cumulative caps are hard.' }),
    execution_context_hash: computeExecutionContextHash(loadProfile(CHARGE, PROFILES_DIR) as { executionContextSchema?: unknown }),
    supported_versions: ['0.8', '0.7'],
  } as never);
}
const decode = (blob: string) => JSON.parse(Buffer.from(blob.split('.')[1] ?? blob, 'base64url').toString('utf8'));

beforeAll(async () => {
  await pm.startSP(SP_PORT);
  owner = await sp.register('DEC-71 Owner', `dec71-owner-${Date.now()}@test.local`);
  approver = await sp.register('DEC-71 Approver', `dec71-appr-${Date.now()}@test.local`);
  const team = await sp.createGroup(owner.apiKey, `DEC-71 Team ${Date.now()}`);
  groupId = team.group.id;
  await sp.joinGroup(approver.apiKey, team.inviteCode, owner.apiKey);
}, 120_000);

afterAll(async () => { await pm.killAll(); }, 30_000);

describe('DEC-71: a cap on a cumulative bound is hard', () => {
  it('team settings refuse an approval cap on a daily total (400 CAP_KIND_NOT_SUPPORTED)', async () => {
    const r = await api('PUT', configPath(), owner.apiKey, {
      grantors: [owner.user.id], approvers: [approver.user.id], approvals: 1,
      caps: { amount_daily_max: { value: 1000, kind: 'approval' } },
    });
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.code).toBe('CAP_KIND_NOT_SUPPORTED');
    expect(r.body.field).toBe('amount_daily_max');
  });

  it('a bare number on a daily total is stored hard; a per-payment approval cap stays approval; GET reports the enforced kinds', async () => {
    const put = await api('PUT', configPath(), owner.apiKey, {
      grantors: [owner.user.id], approvers: [approver.user.id], approvals: 1,
      caps: { amount_daily_max: 1000, amount_max: { value: 100, kind: 'approval' } },
    });
    expect(put.status, JSON.stringify(put.body)).toBeLessThan(300);
    const got = await api('GET', configPath(), owner.apiKey);
    expect(got.status).toBe(200);
    expect(got.body.config.capKinds).toEqual({ amount_daily_max: 'hard', amount_max: 'approval' });
  });

  it('with only the hard daily cap: a v0.8 mandate within it signs automatic', async () => {
    const put = await api('PUT', configPath(), owner.apiKey, {
      grantors: [owner.user.id], approvers: [approver.user.id], approvals: 1, caps: { amount_daily_max: 1000 },
    });
    expect(put.status, JSON.stringify(put.body)).toBeLessThan(300);
    const r = await mandate({ amount_max: 500, amount_daily_max: 800, amount_monthly_max: 5000, transaction_count_daily_max: 10 });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const payload = decode(r.body.blob as string).payload ?? decode(r.body.blob as string);
    expect(payload.version).toBe('0.8');
    expect(payload.commitment_mode).toBe('automatic');
  });

  it('above the daily cap it is refused (422 GROUP_CAP_EXCEEDED), although the team has an approver', async () => {
    const r = await mandate({ amount_max: 500, amount_daily_max: 2000, amount_monthly_max: 5000, transaction_count_daily_max: 10 });
    expect(r.status, JSON.stringify(r.body)).toBe(422);
    expect(JSON.stringify(r.body)).toContain('GROUP_CAP_EXCEEDED');
  });

  it('with a per-payment approval cap as well: the mandate is promoted to review_above_cap with that cap only', async () => {
    const put = await api('PUT', configPath(), owner.apiKey, {
      grantors: [owner.user.id], approvers: [approver.user.id], approvals: 1,
      caps: { amount_daily_max: 1000, amount_max: { value: 100, kind: 'approval' } },
    });
    expect(put.status, JSON.stringify(put.body)).toBeLessThan(300);
    const r = await mandate({ amount_max: 500, amount_daily_max: 800, amount_monthly_max: 5000, transaction_count_daily_max: 10 });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    const payload = decode(r.body.blob as string).payload ?? decode(r.body.blob as string);
    expect(payload.commitment_mode).toBe('review_above_cap');
    expect(payload.above_cap_caps).toEqual({ amount_max: 100 });
    // The daily total is still a hard cap: above it, refused even with the approval cap present.
    const above = await mandate({ amount_max: 500, amount_daily_max: 2000, amount_monthly_max: 5000, transaction_count_daily_max: 10 });
    expect(above.status).toBe(422);
  });
});
