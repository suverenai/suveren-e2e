/**
 * cumulative_usage on GET /api/authorizations/:id — real Authority Server.
 *
 * The mandate summary carries today's team-wide consumption against each of
 * the mandate's cumulative bounds, per (group, profile, actionType), over
 * every window the profile declares (daily, monthly here), read exactly as
 * the ticket reads it. Only an active member of the mandate's group is given
 * it; anyone else gets the summary without the field.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { hashGateContent, hashExecutionContext, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

const SP_PORT = 17948;
const SP_URL = `http://localhost:${SP_PORT}`;
const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;
const PROFILE_ID = PROFILE_V07.charge;
const CONTEXT = { currency: 'USD', action_type: 'charge' };
const BOUNDS = { profile: PROFILE_ID, amount_max: 25, amount_daily_max: 50, amount_monthly_max: 1000, transaction_count_daily_max: 3 };

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);
let apiKey = '';
let stranger = '';
let authorizationId = '';

const summary = async (key: string) => {
  const res = await fetch(`${SP_URL}/api/authorizations/${authorizationId}`, { headers: { 'X-API-Key': key } });
  expect(res.ok).toBe(true);
  return (await res.json()) as { cumulative_usage?: Array<Record<string, unknown>> };
};

beforeAll(async () => {
  await pm.startSP(SP_PORT);
  const u = await sp.register('Usage Owner', `usage-owner-${Date.now()}@test.local`);
  apiKey = u.apiKey;
  stranger = (await sp.register('Usage Stranger', `usage-stranger-${Date.now()}@test.local`)).apiKey;
  const groupId = await sp.getPersonalGroupId(apiKey);
  const res = await sp.submitMandate(apiKey, {
    profile_id: PROFILE_ID,
    profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR),
    group_id: groupId,
    bounds: BOUNDS,
    scope_hash: computeScopeHash(CONTEXT, ['currency', 'action_type']),
    domain: 'owner',
    did: u.user.did,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'Usage numbers test.' }),
    execution_context_hash: hashExecutionContext({ action_type: 'charge', amount: 25, currency: 'USD' }),
  });
  authorizationId = res.authorization_id;
}, 90_000);

afterAll(async () => { await pm.killAll(); }, 30_000);

describe('cumulative_usage on the mandate summary', () => {
  it('starts at zero for every cumulative bound, in every window', async () => {
    const usage = (await summary(apiKey)).cumulative_usage!;
    expect(usage).toContainEqual({ field: 'amount_daily_max', action_type: 'charge', kind: 'cumulative_sum', window: 'daily', of: 'amount', used: 0, limit: 50 });
    expect(usage).toContainEqual({ field: 'amount_monthly_max', action_type: 'charge', kind: 'cumulative_sum', window: 'monthly', of: 'amount', used: 0, limit: 1000 });
    expect(usage).toContainEqual({ field: 'transaction_count_daily_max', action_type: 'charge', kind: 'cumulative_count', window: 'daily', used: 0, limit: 3 });
  });

  it('shows what tickets have used, per window and per action type', async () => {
    for (let i = 0; i < 2; i++) {
      const t = await sp.postTicket(apiKey, {
        authorizationId, profileId: PROFILE_ID, action: 'charge', actionType: 'charge', amount: 20,
        executionContext: { amount: 20, currency: 'USD', action_type: 'charge' },
      });
      expect(t.status).toBe(201);
    }
    const usage = (await summary(apiKey)).cumulative_usage!;
    expect(usage).toContainEqual(expect.objectContaining({ field: 'amount_daily_max', action_type: 'charge', used: 40, limit: 50 }));
    expect(usage).toContainEqual(expect.objectContaining({ field: 'amount_monthly_max', action_type: 'charge', used: 40, limit: 1000 }));
    expect(usage).toContainEqual(expect.objectContaining({ field: 'transaction_count_daily_max', action_type: 'charge', used: 2, limit: 3 }));
    // The count is per action type: nothing was done as "subscribe".
    expect(usage).toContainEqual(expect.objectContaining({ field: 'transaction_count_daily_max', action_type: 'subscribe', used: 0 }));
  });

  it('is not given to someone outside the mandate\'s group; the rest of the summary is unchanged', async () => {
    const body = (await summary(stranger)) as Record<string, unknown>;
    expect(body.cumulative_usage).toBeUndefined();
    expect(body.authorization_id).toBe(authorizationId);
  });
});
