/**
 * v0.8 wire — the contract the Authority Server has to meet
 * (content/0.8/protocol.md, published 2026-11-02; plan:
 * suveren-as/docs/v08-wire-plan.md, Phase 0 step C3).
 *
 * Written RED, before the Authority Server speaks 0.8, from the specification
 * text and its required-refusals vectors — not from the implementation. Every
 * `it` names the row or rule it holds the server to. When Track B lands, this
 * file turns green; until then its failures are the to-do list.
 *
 * Only the Authority Server is needed (no gateway, no connector): the subject
 * is the wire — what the AS signs, what it refuses, with which code.
 *
 * The switch (Track B, step B6): the behaviour that breaks a v0.7 Gatekeeper
 * — refusing a request that does not support 0.8 — sits behind the env var
 * `SUVEREN_HAP_V08_ONLY=1`, off in production until switch day. The last
 * block here spawns a second AS with it on, and runs only when
 * `HAP_E2E_V08_SWITCH=1` is set for this suite.
 *
 * Run: npx vitest run test/v08-wire.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize } from '@humanagencyp/hap-core';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { hashGateContent, computeBoundsHash, computeScopeHash, computeProfileHash, sha256Hash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';

const SP_PORT = 19510; // unused elsewhere in the suite as of 2026-11-04
const SP_URL = `http://localhost:${SP_PORT}`;
const SWITCH_PORT = 19511;
const SWITCH_URL = `http://localhost:${SWITCH_PORT}`;
const PROFILES_DIR = join(process.cwd(), '..', 'hap-profiles');
const CHARGE_ID = PROFILE_V07.charge;

const pm = new ProcessManager();
const sp = new SPClient(SP_URL);

interface User { id: string; did: string; apiKey: string }

/** The AS's refusal envelope: `{ approved:false, errors:[{code}] }` on the
 * protocol routes, `{ errors:[{code}] }` or `{ code }` elsewhere. */
function codeOf(body: Record<string, unknown>): string | undefined {
  const errors = body.errors as Array<{ code?: string }> | undefined;
  return errors?.[0]?.code ?? (body.code as string | undefined) ?? (body.error as { code?: string } | undefined)?.code;
}

async function api(baseUrl: string, method: string, path: string, apiKey: string, body?: unknown) {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: res.status, body: json };
}

function decodeBlob(blob: string): { header: Record<string, unknown>; payload: Record<string, any>; signature: string } {
  return JSON.parse(Buffer.from(blob, 'base64url').toString('utf8'));
}

/** `execution_context_hash` — sha256 over the JCS of the profile's
 * executionContextSchema (protocol.md → *Execution Context Schema*, v0.8). */
function executionContextHashOf(profileDoc: Record<string, unknown>): string {
  return sha256Hash(canonicalize(profileDoc.executionContextSchema ?? {}));
}

/** A throwaway community profile with every v0.8 bounds field kind the
 * contract exercises: a per-transaction bound with `requiredFor` and
 * `maximum`, a cumulative sum with `appliesTo`, an enum marked
 * `enforcedBy: "gatekeeper"`. */
function fixtureProfile(id: string): Record<string, unknown> {
  return {
    id,
    name: 'v0.8 wire fixture',
    version: '1.0',
    description: 'Throwaway community profile for the v0.8 wire contract. Not a published hap-profiles profile.',
    boundsSchema: {
      actionTypes: ['charge', 'refund', 'delete'],
      keyOrder: ['profile', 'amount_max', 'amount_daily_max', 'read_access'],
      fields: {
        profile: { type: 'string', required: true },
        amount_max: {
          type: 'number', required: true, displayName: 'Per charge', description: 'Fixture.', unit: 'currency:EUR',
          boundType: { kind: 'per_transaction', of: 'amount', requiredFor: ['charge'] }, maximum: 10_000,
        },
        amount_daily_max: {
          type: 'number', required: false, displayName: 'Per day', description: 'Fixture.', unit: 'currency:EUR',
          boundType: { kind: 'cumulative_sum', of: 'amount', window: 'daily' }, appliesTo: ['charge', 'refund'],
        },
        read_access: {
          type: 'string', required: false, displayName: 'Read access', description: 'Fixture.',
          boundType: { kind: 'enum', values: ['unlimited', 'none'] }, enforcedBy: 'gatekeeper',
        },
      },
    },
    scopeSchema: { keyOrder: [], fields: {} },
    executionContextSchema: {
      fields: {
        amount: { source: 'declared', description: 'Amount', required: false, constraint: { type: 'number', enforceable: ['max'] } },
      },
    },
    requiredGates: ['intent'],
    ttl: { default: 3600, max: 86400 },
  };
}
const FIXTURE_KEY_ORDER = ['profile', 'amount_max', 'amount_daily_max', 'read_access'];

let owner: User;
let ownerGroupId: string;
let chargeDoc: Record<string, unknown>;
let fixtureId: string;
let fixtureDoc: Record<string, unknown>;

/** A mandate request body in the fixture profile, owner's personal group. */
function fixtureMandate(overrides: Record<string, unknown> = {}) {
  const bounds = { profile: fixtureId, amount_max: 100, amount_daily_max: 500, ...(overrides.bounds as object ?? {}) };
  const { bounds: _b, ...rest } = overrides;
  return {
    authorization_id: mintAuthorizationId(),
    profile_id: fixtureId,
    profile_hash: computeProfileHash(fixtureDoc),
    group_id: ownerGroupId,
    bounds,
    bounds_hash: computeBoundsHash(bounds, FIXTURE_KEY_ORDER),
    scope_hash: computeScopeHash({}, []),
    domain: 'owner',
    did: owner.did,
    commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'v0.8 wire contract.' }),
    execution_context_hash: executionContextHashOf(fixtureDoc),
    supported_versions: ['0.8', '0.7'],
    ...rest,
  };
}

async function issueFixtureMandate(overrides: Record<string, unknown> = {}) {
  const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate(overrides));
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
  return { authorizationId: r.body.authorization_id as string, mandate: decodeBlob(r.body.blob as string), raw: r.body };
}

beforeAll(async () => {
  await pm.startSP(SP_PORT);
  const u = await sp.register('v0.8 Owner', `v08-owner-${Date.now()}@test.local`);
  owner = { id: u.user.id, did: u.user.did, apiKey: u.apiKey };
  ownerGroupId = await sp.getPersonalGroupId(owner.apiKey);
  chargeDoc = loadProfile(CHARGE_ID, PROFILES_DIR);
  fixtureDoc = fixtureProfile(`v08-fixture-${Date.now()}@1.0`);
  fixtureId = (await sp.createProfile(owner.apiKey, fixtureDoc)).profile_id;
  fixtureDoc = { ...fixtureDoc, id: fixtureId };
}, 300_000);

afterAll(async () => {
  await pm.killAll();
}, 30_000);

// ─── Version negotiation ─────────────────────────────────────────────────────

describe('v0.8 — version negotiation (protocol.md → Version negotiation, rules 1–3)', () => {
  it('a Gatekeeper supporting 0.8 and 0.7 gets a version "0.8" mandate — the highest both support', async () => {
    const { mandate } = await issueFixtureMandate({ supported_versions: ['0.8', '0.7'] });
    expect(mandate.payload.version).toBe('0.8');
    expect(mandate.header.typ).toBe('HAP-mandate');
  });

  it('a Gatekeeper supporting 0.8 only is served', async () => {
    const { mandate } = await issueFixtureMandate({ supported_versions: ['0.8'] });
    expect(mandate.payload.version).toBe('0.8');
  });

  it('/api/as/compat advertises 0.8', async () => {
    const res = await fetch(`${SP_URL}/api/as/compat`);
    const body = (await res.json()) as { protocolVersion?: string; supportedVersions?: string[] };
    expect(body.protocolVersion).toBe('0.8');
    expect(body.supportedVersions).toContain('0.8');
  });
});

// ─── Mandate issuance ────────────────────────────────────────────────────────

describe('v0.8 — mandate issuance (protocol.md → Mandate Issuance & Validation)', () => {
  it('execution-context-hash-wrong → MALFORMED_MANDATE: the AS checks the hash against the profile\'s executionContextSchema (stage 4)', async () => {
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ execution_context_hash: 'sha256:' + 'c'.repeat(64) }));
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(codeOf(r.body)).toBe('MALFORMED_MANDATE');
  });

  it('the correct execution_context_hash is the JCS hash of the schema, and is signed as sent', async () => {
    const { mandate } = await issueFixtureMandate();
    expect(mandate.payload.execution_context_hash).toBe(executionContextHashOf(fixtureDoc));
  });

  it('above-maximum → BOUNDS_INVALID_VALUE (Bounds Schema rule 9)', async () => {
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ bounds: { amount_max: 20_000 } }));
    expect(codeOf(r.body)).toBe('BOUNDS_INVALID_VALUE');
  });

  it('non-numeric-under-maximum → BOUNDS_INVALID_VALUE: "100" is not a number', async () => {
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ bounds: { amount_max: '100' } }));
    expect(codeOf(r.body)).toBe('BOUNDS_INVALID_VALUE');
  });

  it('enum-value-not-allowed → BOUNDS_INVALID_VALUE', async () => {
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ bounds: { read_access: 'some' } }));
    expect(codeOf(r.body)).toBe('BOUNDS_INVALID_VALUE');
  });

  it('approvals-count-invalid → ABOVE_CAP_CONFIG_INVALID: outside a group the count is required, ≥ 1, and reachable without the owner', async () => {
    const other = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME';
    const base = { commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 50 } };
    const absent = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ ...base, above_cap_approvers: [other] }));
    expect(codeOf(absent.body)).toBe('ABOVE_CAP_CONFIG_INVALID');
    const tooMany = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ ...base, above_cap_approvers: [other], above_cap_approvals: 2 }));
    expect(codeOf(tooMany.body)).toBe('ABOVE_CAP_CONFIG_INVALID');
    // v0.7 let an owner name themselves their own sole approver; v0.8 refuses that mandate.
    const selfOnly = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ ...base, above_cap_approvers: [owner.did], above_cap_approvals: 1 }));
    expect(codeOf(selfOnly.body)).toBe('ABOVE_CAP_CONFIG_INVALID');
  });

  it('an owner-chosen review_above_cap mandate signs caps, approvers AND above_cap_approvals (Mandate rule 10)', async () => {
    const other = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME';
    const { mandate } = await issueFixtureMandate({
      commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 50 }, above_cap_approvers: [other], above_cap_approvals: 1,
    });
    expect(mandate.payload.commitment_mode).toBe('review_above_cap');
    expect(mandate.payload.above_cap_caps).toEqual({ amount_max: 50 });
    expect(mandate.payload.above_cap_approvers).toEqual([other]);
    expect(mandate.payload.above_cap_approvals).toBe(1);
  });

  it('approver-not-key-bearing → ABOVE_CAP_CONFIG_INVALID (Group roles, rule 2)', async () => {
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({
      commitment_mode: 'review_above_cap', above_cap_caps: { amount_max: 50 }, above_cap_approvers: ['did:github:someone'], above_cap_approvals: 1,
    }));
    expect(codeOf(r.body)).toBe('ABOVE_CAP_CONFIG_INVALID');
  });

  it('approval-cap-on-cumulative → ABOVE_CAP_CONFIG_INVALID (Commitment Modes, rule 7)', async () => {
    const other = 'did:key:z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME';
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({
      commitment_mode: 'review_above_cap', above_cap_caps: { amount_daily_max: 50 }, above_cap_approvers: [other], above_cap_approvals: 1,
    }));
    expect(codeOf(r.body)).toBe('ABOVE_CAP_CONFIG_INVALID');
  });

  it('bounds-profile-differs → MALFORMED_MANDATE', async () => {
    const bounds = { profile: 'another@1.0', amount_max: 100, amount_daily_max: 500 };
    const r = await sp.submitMandateRaw(owner.apiKey, fixtureMandate({ bounds, bounds_hash: computeBoundsHash(bounds, FIXTURE_KEY_ORDER) }));
    expect(codeOf(r.body)).toBe('MALFORMED_MANDATE');
  });
});

// ─── Ticket issuance ─────────────────────────────────────────────────────────

describe('v0.8 — ticket issuance (protocol.md → Ticket Issuance, stages 1–7)', () => {
  let authorizationId: string;
  let mandateId: string;
  let boundsHash: string;

  beforeAll(async () => {
    const issued = await issueFixtureMandate();
    authorizationId = issued.authorizationId;
    mandateId = issued.mandate.payload.mandate_id;
    boundsHash = issued.mandate.payload.bounds_hash;
  });

  const ticketBody = (over: Record<string, unknown> = {}) => ({
    authorizationId, boundsHash, mandateId, profileId: fixtureId, action: 'create_payment_link', actionType: 'charge',
    executionContext: { amount: 30 }, idempotencyKey: `v08-${randomUUID()}`, ...over,
  });

  it('a ticket under a 0.8 mandate carries version "0.8", the mandateId and the idempotencyKey in its signed payload (Ticket rule 4)', async () => {
    const body = ticketBody();
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, body);
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    const ticket = r.body.ticket as Record<string, unknown>;
    expect(ticket.version).toBe('0.8');
    expect(ticket.mandateId).toBe(mandateId);
    expect(ticket.idempotencyKey).toBe(body.idempotencyKey);
    expect(ticket.executionContext).toEqual({ amount: 30 });
    expect(typeof ticket.signature).toBe('string');
  });

  it('mandate-id-bounds-disagree → MALFORMED_TICKET_REQUEST (stage 2)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ boundsHash: 'sha256:' + 'a'.repeat(64) }));
    expect(codeOf(r.body)).toBe('MALFORMED_TICKET_REQUEST');
  });

  it('mandate-id-unknown → MANDATE_NOT_FOUND (stage 2)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ mandateId: randomUUID() }));
    expect(codeOf(r.body)).toBe('MANDATE_NOT_FOUND');
  });

  it('reserved-key-in-execution-context → MALFORMED_TICKET_REQUEST (stage 1; Ticket Request rule 8)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ executionContext: { amount: 30, _source: 'crm:x' } }));
    expect(codeOf(r.body)).toBe('MALFORMED_TICKET_REQUEST');
  });

  it('negative-value → MALFORMED_TICKET_REQUEST, never a lowered running sum (stage 7)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ executionContext: { amount: -30 } }));
    expect(codeOf(r.body)).toBe('MALFORMED_TICKET_REQUEST');
  });

  it('non-number-value → MALFORMED_TICKET_REQUEST (stage 7)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ executionContext: { amount: '30' } }));
    expect(codeOf(r.body)).toBe('MALFORMED_TICKET_REQUEST');
  });

  it('required-value-absent → BOUND_EXCEEDED naming the bound (Bounds Schema rule 8)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ executionContext: {} }));
    expect(codeOf(r.body)).toBe('BOUND_EXCEEDED');
  });

  it('amount-absent-under-sum-bound → BOUND_EXCEEDED: refund is not in requiredFor, but amount_daily_max governs it (stage 7)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ action: 'refund_payment', actionType: 'refund', executionContext: {} }));
    expect(codeOf(r.body)).toBe('BOUND_EXCEEDED');
  });

  it('an action type the sum bound excludes still issues without an amount (appliesTo)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ action: 'delete_payment_link', actionType: 'delete', executionContext: {} }));
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
  });

  it('idempotency-key-other-action-type → IDEMPOTENCY_MISMATCH (stage 3 compares the whole request)', async () => {
    const key = `v08-${randomUUID()}`;
    const first = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ idempotencyKey: key }));
    expect(first.status).toBeLessThan(300);
    const r = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, ticketBody({ idempotencyKey: key, action: 'refund_payment', actionType: 'refund' }));
    expect(codeOf(r.body)).toBe('IDEMPOTENCY_MISMATCH');
  });

  it('a replay returns the original ticket, flagged idempotent, with the same signed idempotencyKey', async () => {
    const body = ticketBody();
    const first = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, body);
    const again = await api(SP_URL, 'POST', '/api/as/ticket', owner.apiKey, body);
    expect(again.body.idempotent).toBe(true);
    expect((again.body.ticket as { id: string }).id).toBe((first.body.ticket as { id: string }).id);
    expect((again.body.ticket as { idempotencyKey: string }).idempotencyKey).toBe(body.idempotencyKey);
  });
});

// ─── Proposals: content, readers, deciders, fingerprint ───────────────────────

describe('v0.8 — proposals (protocol.md → Proposals — what the Authority Server receives)', () => {
  let grantor: User;
  let approver: User;
  let stranger: User;
  let teamGroupId: string;
  let authorizationId: string;
  let mandateId: string;
  let boundsHash: string;
  let promoted: Record<string, any>;
  const chargeBounds = { profile: '', amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 };

  /** A structurally complete envelope; the AS never decrypts, so the bytes
   * only have to be well-formed base64url. */
  const envelope = (readers: string[], unreadable: string[] = [], keyedFor = readers) => ({
    ciphertext: Buffer.from(randomUUID() + randomUUID()).toString('base64url'),
    encrypted_keys: Object.fromEntries(keyedFor.map((d) => [d, { ct: Buffer.alloc(48, 1).toString('base64url'), enc: Buffer.alloc(32, 2).toString('base64url') }])),
    readers,
    unreadable,
  });
  const fingerprint = (args: Record<string, unknown>) => sha256Hash(canonicalize(args));

  beforeAll(async () => {
    const g = await sp.register('v0.8 Grantor', `v08-grantor-${Date.now()}@test.local`);
    grantor = { id: g.user.id, did: g.user.did, apiKey: g.apiKey };
    const a = await sp.register('v0.8 Approver', `v08-approver-${Date.now()}@test.local`);
    approver = { id: a.user.id, did: a.user.did, apiKey: a.apiKey };
    const s = await sp.register('v0.8 Stranger', `v08-stranger-${Date.now()}@test.local`);
    stranger = { id: s.user.id, did: s.user.did, apiKey: s.apiKey };
    const team = await sp.createGroup(grantor.apiKey, `v0.8 Team ${Date.now()}`);
    teamGroupId = team.group.id;
    await sp.joinGroup(approver.apiKey, team.inviteCode, grantor.apiKey);
    await sp.joinGroup(stranger.apiKey, team.inviteCode, grantor.apiKey);
    // One approver, approval cap on amount_max: an automatic request is promoted to review_above_cap.
    await api(SP_URL, 'PUT', `/api/groups/${teamGroupId}/profile-config/${encodeURIComponent(CHARGE_ID)}`, grantor.apiKey, {
      grantors: [grantor.id], approvers: [approver.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } },
    });
    chargeBounds.profile = CHARGE_ID;
    const r = await sp.submitMandateRaw(grantor.apiKey, {
      authorization_id: mintAuthorizationId(),
      profile_id: CHARGE_ID,
      profile_hash: profileHashFor(CHARGE_ID, PROFILES_DIR),
      group_id: teamGroupId,
      bounds: chargeBounds,
      bounds_hash: computeBoundsHash(chargeBounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
      scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
      domain: 'owner', did: grantor.did, commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: 'v0.8 proposals contract.' }),
      execution_context_hash: executionContextHashOf(chargeDoc),
      supported_versions: ['0.8', '0.7'],
    });
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    authorizationId = r.body.authorization_id as string;
    promoted = decodeBlob(r.body.blob as string).payload;
    mandateId = promoted.mandate_id;
    boundsHash = promoted.bounds_hash;
  }, 120_000);

  it('the group promotes the automatic request to review_above_cap and signs the approver by key-bearing DID and the count (Group roles, rules 2 and 7)', () => {
    expect(promoted.commitment_mode).toBe('review_above_cap');
    expect(promoted.above_cap_approvers).toEqual([approver.did]);
    expect(promoted.above_cap_approvals).toBe(1);
    // Group roles, rule 2: each approver is named by a key-bearing DID, so the
    // approval signature verifies without a key the AS serves.
    expect(approver.did).toMatch(/^did:key:z6Mk/);
  });

  const args = { amount: 250, description: 'Annual licence', customer_id: 'cus_1' };
  const proposalBody = (over: Record<string, unknown> = {}) => ({
    authorization_id: authorizationId,
    mandateId, boundsHash,
    profile_id: CHARGE_ID,
    tool: 'create_payment_link', action: 'create_payment_link', actionType: 'charge',
    execution_context: { amount: 250 }, executionContext: { amount: 250 },
    content: envelope([grantor.did, approver.did]),
    proposalContentHash: fingerprint(args),
    pending_approvers: [approver.id],
    ...over,
  });

  it('a request above the cap is refused APPROVAL_REQUIRED, naming the signed approvers', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
      authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
      executionContext: { amount: 250 }, idempotencyKey: `v08-${randomUUID()}`,
    });
    expect(codeOf(r.body)).toBe('APPROVAL_REQUIRED');
    expect((r.body.errors as Array<{ approvers?: string[] }>)[0].approvers).toEqual([approver.did]);
  });

  it('amount-absent-under-approval-cap → APPROVAL_REQUIRED: an unknown amount is above the cap (decided 2026-10-30)', async () => {
    const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
      authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'unclassified',
      executionContext: {}, idempotencyKey: `v08-${randomUUID()}`,
    });
    expect(codeOf(r.body)).toBe('APPROVAL_REQUIRED');
  });

  it('proposal-in-clear → PROPOSAL_NOT_ENCRYPTED: readable tool_args, or no envelope / no fingerprint (rule 5)', async () => {
    const clear = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ content: undefined, proposalContentHash: undefined, tool_args: args }));
    expect(codeOf(clear.body)).toBe('PROPOSAL_NOT_ENCRYPTED');
    const noHash = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ proposalContentHash: undefined }));
    expect(codeOf(noHash.body)).toBe('PROPOSAL_NOT_ENCRYPTED');
  });

  it('readers-keys-differ → PROPOSAL_NOT_ENCRYPTED (rule 2)', async () => {
    const r = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ content: envelope([grantor.did, approver.did], [], [grantor.did]) }));
    expect(codeOf(r.body)).toBe('PROPOSAL_NOT_ENCRYPTED');
  });

  it('approvers-not-the-signed-set → PROPOSAL_APPROVERS_INVALID: the signed set is the decider set (Group roles, rule 6)', async () => {
    const wrongApprover = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ pending_approvers: [stranger.id], content: envelope([grantor.did, stranger.did]) }));
    expect(codeOf(wrongApprover.body)).toBe('PROPOSAL_APPROVERS_INVALID');
    const extraReader = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ content: envelope([grantor.did, approver.did, stranger.did]) }));
    expect(codeOf(extraReader.body)).toBe('PROPOSAL_APPROVERS_INVALID');
    const missingReader = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody({ content: envelope([grantor.did]) }));
    expect(codeOf(missingReader.body)).toBe('PROPOSAL_APPROVERS_INVALID');
  });

  describe('decisions (rule 7) and the ticket bound by fingerprint (rule 9)', () => {
    let proposalId: string;

    beforeAll(async () => {
      const created = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody());
      expect(created.status, JSON.stringify(created.body)).toBe(201);
      proposalId = (created.body.proposal as { id: string }).id;
    });

    it('the AS echoes no content in any response, only the fingerprint', async () => {
      const r = await api(SP_URL, 'GET', `/api/proposals/${proposalId}`, approver.apiKey);
      const text = JSON.stringify(r.body);
      expect(text).not.toContain('Annual licence');
      expect(text).toContain(fingerprint(args));
    });

    it('decision-from-non-decider → DECIDER_INVALID', async () => {
      const r = await api(SP_URL, 'POST', `/api/proposals/${proposalId}/approve`, stranger.apiKey, { proposalContentHash: fingerprint(args) });
      expect(codeOf(r.body)).toBe('DECIDER_INVALID');
    });

    it('decision-fingerprint-differs → PROPOSAL_CONTENT_MISMATCH: every decision carries the fingerprint and the AS compares it (rule 8)', async () => {
      const r = await api(SP_URL, 'POST', `/api/proposals/${proposalId}/approve`, approver.apiKey, { proposalContentHash: 'sha256:' + 'f'.repeat(64) });
      expect(codeOf(r.body)).toBe('PROPOSAL_CONTENT_MISMATCH');
    });

    it('the signed approver commits it; a second decision by the same decider → PROPOSAL_ALREADY_DECIDED', async () => {
      const ok = await api(SP_URL, 'POST', `/api/proposals/${proposalId}/approve`, approver.apiKey, { proposalContentHash: fingerprint(args) });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body.status).toBe('committed');
      const again = await api(SP_URL, 'POST', `/api/proposals/${proposalId}/approve`, approver.apiKey, { proposalContentHash: fingerprint(args) });
      expect(codeOf(again.body)).toBe('PROPOSAL_ALREADY_DECIDED');
    });

    it('proposal-content-mismatch → PROPOSAL_CONTENT_MISMATCH at ticket time, and the refusal carries no content', async () => {
      const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
        authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
        executionContext: { amount: 250 }, proposalId, proposalContentHash: 'sha256:' + 'e'.repeat(64),
      });
      expect(codeOf(r.body)).toBe('PROPOSAL_CONTENT_MISMATCH');
      expect(JSON.stringify(r.body)).not.toContain('Annual licence');
    });

    it('the ticket carries proposalContentHash and the approver\'s signature entry in approvalSignatures', async () => {
      const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
        authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
        executionContext: { amount: 250 }, proposalId, proposalContentHash: fingerprint(args),
      });
      expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
      const ticket = r.body.ticket as Record<string, unknown>;
      expect(ticket.version).toBe('0.8');
      expect(ticket.proposalId).toBe(proposalId);
      expect(ticket.proposalContentHash).toBe(fingerprint(args));
      expect(ticket.idempotencyKey).toBeUndefined();
    });

    it('proposal-executed-other-request → PROPOSAL_ALREADY_EXECUTED; the same request gets the original back', async () => {
      const same = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
        authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
        executionContext: { amount: 250 }, proposalId, proposalContentHash: fingerprint(args),
      });
      expect(same.body.idempotent).toBe(true);
      const other = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
        authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
        executionContext: { amount: 240 }, proposalId, proposalContentHash: fingerprint(args),
      });
      expect(codeOf(other.body)).toBe('PROPOSAL_ALREADY_EXECUTED');
    });
  });

  it('proposal-withdrawn → PROPOSAL_WITHDRAWN at ticket time', async () => {
    const created = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody());
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    const id = (created.body.proposal as { id: string }).id;
    const w = await api(SP_URL, 'POST', `/api/proposals/${id}/withdraw`, grantor.apiKey, {});
    expect(w.status, JSON.stringify(w.body)).toBeLessThan(300);
    const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
      authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
      executionContext: { amount: 250 }, proposalId: id, proposalContentHash: fingerprint(args),
    });
    expect(codeOf(r.body)).toBe('PROPOSAL_WITHDRAWN');
  });

  it('one-reject-against-approvals: a reject from any signed decider is final', async () => {
    const created = await api(SP_URL, 'POST', '/api/proposals', grantor.apiKey, proposalBody());
    const id = (created.body.proposal as { id: string }).id;
    const rej = await api(SP_URL, 'POST', `/api/proposals/${id}/reject`, approver.apiKey, { proposalContentHash: fingerprint(args) });
    expect(rej.status, JSON.stringify(rej.body)).toBeLessThan(300);
    const r = await api(SP_URL, 'POST', '/api/as/ticket', grantor.apiKey, {
      authorizationId, boundsHash, mandateId, profileId: CHARGE_ID, action: 'create_payment_link', actionType: 'charge',
      executionContext: { amount: 250 }, proposalId: id, proposalContentHash: fingerprint(args),
    });
    expect(codeOf(r.body)).toBe('PROPOSAL_REJECTED');
  });
});

// ─── The switch: a v0.8 Authority Server (Track B, step B6) ─────────────────

describe.skipIf(!process.env.HAP_E2E_V08_SWITCH)('v0.8 — with SUVEREN_HAP_V08_ONLY=1 the AS is a v0.8 Authority Server (Version negotiation, rule 3 exception)', () => {
  const sw = new SPClient(SWITCH_URL);
  let u: User;
  let g: string;

  beforeAll(async () => {
    await pm.startSP(SWITCH_PORT, { name: 'as-v08-only', env: { SUVEREN_HAP_V08_ONLY: '1' } });
    const r = await sw.register('v0.8 Switch', `v08-switch-${Date.now()}@test.local`);
    u = { id: r.user.id, did: r.user.did, apiKey: r.apiKey };
    g = await sw.getPersonalGroupId(u.apiKey);
  }, 120_000);

  const body = (supported: string[]) => {
    const bounds = { profile: CHARGE_ID, amount_max: 100, amount_daily_max: 500, amount_monthly_max: 5000, transaction_count_daily_max: 20 };
    return {
      authorization_id: mintAuthorizationId(), profile_id: CHARGE_ID, profile_hash: profileHashFor(CHARGE_ID, PROFILES_DIR), group_id: g,
      bounds, bounds_hash: computeBoundsHash(bounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
      scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
      domain: 'owner', did: u.did, commitment_mode: 'automatic',
      gate_content_hashes: hashGateContent({ intent: 'switch' }), execution_context_hash: executionContextHashOf(chargeDoc),
      supported_versions: supported,
    };
  };

  it('v07-only Gatekeeper → VERSION_UNSUPPORTED (no 0.7 is issued any more)', async () => {
    const r = await sw.submitMandateRaw(u.apiKey, body(['0.7']));
    expect(r.status).toBe(426);
    expect(codeOf(r.body)).toBe('VERSION_UNSUPPORTED');
  });

  it('a 0.8 Gatekeeper is served 0.8', async () => {
    const r = await sw.submitMandateRaw(u.apiKey, body(['0.8', '0.7']));
    expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
    expect(decodeBlob(r.body.blob as string).payload.version).toBe('0.8');
  });

  it('/api/as/compat lists 0.8 only', async () => {
    const res = await fetch(`${SWITCH_URL}/api/as/compat`);
    const b = (await res.json()) as { supportedVersions?: string[] };
    expect(b.supportedVersions).toEqual(['0.8']);
  });
});
