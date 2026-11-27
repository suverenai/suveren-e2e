/**
 * Device keys, build step 17 (stage E): retention of proposal content, and dashboard sign-in by passkey.
 * Against a real Authority Server (`next start`, real Postgres) and a real Chromium with a virtual WebAuthn
 * authenticator. No gateway is needed: the subject is what the AS stores and serves.
 *
 * Retention (plan section 5, DEC-22; v0.8 Proposals rule 11), switch on:
 *   - a proposal whose ticket was issued, one that was rejected with "ask for a change", and one that was withdrawn
 *     hold no ciphertext, no content keys, no device wraps and no card context afterwards; the fingerprint, the
 *     decision and the ticket are still served (the ticket's idempotent replay still answers);
 *   - with the AS clock moved 31 days, an encrypted note is gone too, and a pending proposal that expired has no
 *     content left;
 *   - switch off (a second AS): the same endings keep everything, as today.
 *
 * Dashboard passkey (plan 6.4, DEC-20), switch on:
 *   - a person signed in to the dashboard creates a passkey in the browser; it cannot sign in until a granting
 *     device of the person approves it (`suveren-passkey-register`, signed with the device key, with its check);
 *     then the passkey signs in to the dashboard in the browser;
 *   - a registration approved without the device's check is refused; a start from an email-link session is
 *     refused; an email-link session cannot change team settings.
 *
 * The AS runs from `next build`, which inlines NODE_ENV as "production": the http://localhost dashboard address needs
 * the AS's runtime opt-in SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS=1.
 *
 * Skips (as the other device-key suites do) unless SUVEREN_DB_URL is set and the AS under test has the step 17
 * routes (suveren-as feat/retention-passkey-as).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { chromium, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { canonicalize } from '@humanagencyp/hap-core';
import { objectHash, signObject } from '@humanagencyp/hap-core/device-keys';

import { AS_DIR } from '../src/helpers/as-dir.js';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { shiftedClock, type ShiftedClock } from '../src/helpers/clock.js';
import { hashGateContent, computeBoundsHash, computeScopeHash, sha256Hash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';
import { checkOver, genesisEntry, headOf, newDevice, newRoot, signinBody, type Device, type Root } from '../src/helpers/device-chain.js';

const AS_PORT = 19990;
const AS_OFF_PORT = 19991;
const AS_URL = `http://localhost:${AS_PORT}`;
const AS_OFF_URL = `http://localhost:${AS_OFF_PORT}`;
const PROFILES_DIR = join(process.cwd(), '..', 'hap-profiles');
const CHARGE_ID = PROFILE_V07.charge;
const DAY = 86_400;

const available = !!process.env.SUVEREN_DB_URL
  && existsSync(join(AS_DIR, 'src', 'app', 'api', 'passkeys', 'login', 'route.ts'))
  && existsSync(join(AS_DIR, 'src', 'lib', 'device-keys', 'proposal-retention.ts'));

// ─── HTTP ────────────────────────────────────────────────────────────────────

interface Res { status: number; json: any }
async function http(base: string, method: string, path: string, o: { token?: string; apiKey?: string; cookie?: string; body?: unknown; ip?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (o.token) headers.authorization = `Bearer ${o.token}`;
  if (o.apiKey) headers['x-api-key'] = o.apiKey;
  if (o.cookie) headers.cookie = o.cookie;
  if (o.ip) headers['x-forwarded-for'] = o.ip;
  const res = await fetch(`${base}${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  return { status: res.status, json };
}
const show = (r: Res) => JSON.stringify(r.json);
const code = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.code;
const now = () => Math.floor(Date.now() / 1000);
const fakeIp = () => `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

function decodeBlob(blob: string): { payload: Record<string, any> } {
  return JSON.parse(Buffer.from(blob, 'base64url').toString('utf8'));
}

// ─── the proposal world (the v0.8 proposals flow of v08-wire.test.ts) ───────

interface User { id: string; did: string; apiKey: string }

interface World {
  base: string; sp: SPClient; db: pg.Client;
  grantor: User; approver: User; authorizationId: string; mandateId: string; boundsHash: string;
}

const args = { amount: 250, description: 'Retention licence', customer_id: 'cus_17' };
const fingerprint = sha256Hash(canonicalize(args));
const wrap = () => ({ ct: Buffer.alloc(48, 1).toString('base64url'), enc: Buffer.alloc(32, 2).toString('base64url') });
const envelope = (readers: string[]) => ({
  ciphertext: Buffer.from(randomUUID() + randomUUID()).toString('base64url'),
  encrypted_keys: Object.fromEntries(readers.map((d) => [d, wrap()])),
  readers,
  unreadable: [],
});

async function world(base: string, db: pg.Client): Promise<World> {
  const sp = new SPClient(base);
  const reg = async (name: string): Promise<User> => {
    const u = await sp.register(name, `${name.toLowerCase().replace(/\W+/g, '-')}-${randomUUID().slice(0, 8)}@test.local`);
    return { id: u.user.id, did: u.user.did, apiKey: u.apiKey };
  };
  const grantor = await reg('Retention Grantor');
  const approver = await reg('Retention Approver');
  const team = await sp.createGroup(grantor.apiKey, `Retention Team ${randomUUID().slice(0, 6)}`);
  await sp.joinGroup(approver.apiKey, team.inviteCode, grantor.apiKey);
  const cfg = await http(base, 'PUT', `/api/groups/${team.group.id}/profile-config/${encodeURIComponent(CHARGE_ID)}`, {
    apiKey: grantor.apiKey, body: { grantors: [grantor.id], approvers: [approver.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } } },
  });
  expect(cfg.status, show(cfg)).toBeLessThan(300);
  const bounds = { profile: CHARGE_ID, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 };
  const chargeDoc = loadProfile(CHARGE_ID, PROFILES_DIR) as Record<string, unknown>;
  const r = await sp.submitMandateRaw(grantor.apiKey, {
    authorization_id: mintAuthorizationId(),
    profile_id: CHARGE_ID,
    profile_hash: profileHashFor(CHARGE_ID, PROFILES_DIR),
    group_id: team.group.id,
    bounds,
    bounds_hash: computeBoundsHash(bounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
    scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
    domain: 'owner', did: grantor.did, commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'Step 17 retention.' }),
    execution_context_hash: sha256Hash(canonicalize(chargeDoc.executionContextSchema ?? {})),
    supported_versions: ['0.8', '0.7'],
  });
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
  const payload = decodeBlob(r.body.blob as string).payload;
  return { base, sp, db, grantor, approver, authorizationId: r.body.authorization_id as string, mandateId: payload.mandate_id, boundsHash: payload.bounds_hash };
}

async function propose(w: World): Promise<string> {
  const created = await http(w.base, 'POST', '/api/proposals', {
    apiKey: w.grantor.apiKey,
    body: {
      authorization_id: w.authorizationId, mandateId: w.mandateId, boundsHash: w.boundsHash, profile_id: CHARGE_ID,
      tool: 'create_payment_link', action: 'create_payment_link', actionType: 'charge',
      execution_context: { amount: 250 }, executionContext: { amount: 250 },
      content: envelope([w.grantor.did, w.approver.did]), proposalContentHash: fingerprint, pending_approvers: [w.approver.id],
    },
  });
  expect(created.status, show(created)).toBe(201);
  return created.json.proposal.id as string;
}

const ticketBody = (w: World, proposalId: string) => ({
  authorizationId: w.authorizationId, boundsHash: w.boundsHash, mandateId: w.mandateId, profileId: CHARGE_ID,
  action: 'create_payment_link', actionType: 'charge', executionContext: { amount: 250 }, proposalId, proposalContentHash: fingerprint,
});

interface Row {
  status: string; content_ciphertext: string | null; content_keys: unknown; content_device_keys: unknown; content_context: string | null;
  content_hash: string; content_deleted_at: string | null; approver_rejected_by: Record<string, any> | null; withdrawn_by: Record<string, any> | null;
}
async function row(w: World, id: string): Promise<Row> {
  const r = await w.db.query<Row>('select * from proposals where id = $1', [id]);
  return r.rows[0];
}
function expectGone(r: Row) {
  expect(r.content_ciphertext).toBeNull();
  expect(r.content_keys).toBeNull();
  expect(r.content_device_keys).toBeNull();
  expect(r.content_context).toBeNull();
  expect(r.content_hash).toBe(fingerprint);
  expect(r.content_deleted_at).not.toBeNull();
}
function expectKept(r: Row) {
  expect(r.content_ciphertext).not.toBeNull();
  expect(r.content_keys).not.toBeNull();
  expect(r.content_deleted_at ?? null).toBeNull();
}

/** The three endings that happen at once: ticket issued, "ask for a change", withdrawn. */
async function threeEndings(w: World) {
  const ticketed = await propose(w);
  const ok = await http(w.base, 'POST', `/api/proposals/${ticketed}/approve`, { apiKey: w.approver.apiKey, body: { proposalContentHash: fingerprint } });
  expect(ok.status, show(ok)).toBe(200);
  const t = await http(w.base, 'POST', '/api/as/ticket', { apiKey: w.grantor.apiKey, body: ticketBody(w, ticketed) });
  expect(t.status, show(t)).toBeLessThan(300);

  const changed = await propose(w);
  const note = { ciphertext: Buffer.from(randomUUID()).toString('base64url'), keys: { [w.grantor.did]: wrap() } };
  const rej = await http(w.base, 'POST', `/api/proposals/${changed}/reject`, {
    apiKey: w.approver.apiKey, body: { proposalContentHash: fingerprint, outcome: 'change_needed', note_encrypted: note },
  });
  expect(rej.status, show(rej)).toBeLessThan(300);

  const withdrawn = await propose(w);
  const wd = await http(w.base, 'POST', `/api/proposals/${withdrawn}/withdraw`, { apiKey: w.grantor.apiKey, body: {} });
  expect(wd.status, show(wd)).toBeLessThan(300);
  return { ticketed, ticket: t.json.ticket, changed, note, withdrawn };
}

// ─── people with a device chain ──────────────────────────────────────────────

interface Person { userId: string; apiKey: string; email: string; root: Root; dev: Device; token: string; head: { seq: number; hash: string } }

async function chained(base: string, db: pg.Client, name: string): Promise<Person> {
  const sp = new SPClient(base);
  const email = `${name.toLowerCase().replace(/\W+/g, '-')}-${randomUUID().slice(0, 8)}@test.local`;
  const r = await sp.register(name, email);
  const cookie = await emailLinkCookie(db, r.user.id);
  const codeRes = await http(base, 'POST', '/api/enrolment-codes', { cookie });
  expect(codeRes.status, show(codeRes)).toBe(201);
  const root = await newRoot();
  const dev = await newDevice();
  const g = await genesisEntry(root, dev);
  const chainRes = await http(base, 'POST', '/api/devices/chain', { body: { entry: g, enrolment_code: codeRes.json.code } });
  expect(chainRes.status, show(chainRes)).toBe(201);
  const head = await headOf(g);
  const ch = await http(base, 'POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id }, ip: fakeIp() });
  expect(ch.status, show(ch)).toBe(200);
  const sess = await http(base, 'POST', '/api/devices/session', { body: await signinBody(root, dev, head, ch.json) });
  expect(sess.status, show(sess)).toBe(200);
  return { userId: r.user.id, apiKey: r.apiKey, email, root, dev, token: sess.json.token, head };
}

/** An email-link session, as /api/auth/welcome opens one (the test has no mailbox). */
async function emailLinkCookie(db: pg.Client, userId: string): Promise<string> {
  const token = randomUUID();
  await db.query(`insert into sessions (token, user_id, kind, created_at, expires_at) values ($1, $2, 'email-link', $3, $4)`, [token, userId, now(), now() + 3600]);
  return `hap-session=${token}`;
}

async function registerEnvelope(p: Person, requestId: string, credId: string, rpId: string, o: { check?: boolean } = {}) {
  const register = {
    typ: 'suveren-passkey-register', v: 1, root_did: p.root.did, key_id: p.dev.record.key_id, chain_seq: p.head.seq, chain_head: p.head.hash,
    request_id: requestId, cred_id: credId, rp_id: rpId, issued_at: now(),
  };
  const sig = await signObject(register as never, p.dev.seed);
  return o.check === false ? { register, sig } : { register, sig, check: await checkOver(p.dev.checkPriv, await objectHash(register as never)) };
}

// ─── the suites ──────────────────────────────────────────────────────────────

describe.skipIf(!available)('step 17, switch on (real Authority Server, real Chromium)', () => {
  const pm = new ProcessManager();
  let db: pg.Client;
  let clock: ShiftedClock;
  let browser: Browser;

  beforeAll(async () => {
    clock = shiftedClock(0);
    await pm.startSP(AS_PORT, { name: 'as-step17', env: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_DASHBOARD_ORIGIN: AS_URL, SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS: '1', ...clock.env } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
  }, 240_000);
  afterAll(async () => {
    await browser?.close().catch(() => undefined);
    await db?.end().catch(() => undefined);
    await pm.killAll();
  }, 60_000);

  describe('dashboard sign-in by passkey', () => {
    let p: Person;
    let context: BrowserContext;
    let page: Page;
    let authenticatorId: string;
    let cdp: Awaited<ReturnType<BrowserContext['newCDPSession']>>;

    beforeAll(async () => {
      p = await chained(AS_URL, db, 'Passkey Person');
      context = await browser.newContext();
      page = await context.newPage();
      cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
        options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
      }));
    }, 120_000);
    afterAll(async () => { await context?.close().catch(() => undefined); });

    let requestId: string;
    let credId: string;

    it('signed in to the dashboard, the person creates a passkey in the browser; it waits for a device', async () => {
      await page.goto(`${AS_URL}/login`);
      // The API key field sits behind "Sign in with an API key instead" when device keys are on (sign-in page, 2026-11-27).
      { const k = page.getByTestId('api-key-signin'); if (await k.count()) await k.locator('summary').click(); }
      await page.fill('#apiKey', p.apiKey);
      await page.click('form button[type=submit]');
      await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

      await page.goto(`${AS_URL}/dashboard/passkeys`);
      await page.getByTestId('passkey-register').getByRole('button').click();
      await page.getByTestId('passkey-pending').waitFor({ timeout: 30_000 });
      requestId = (await page.getByTestId('passkey-request-id').textContent())!.trim();
      credId = (await page.getByTestId('passkey-cred-id').textContent())!.trim();
      expect(requestId).toMatch(/^[A-Za-z0-9_-]{22}$/);
      const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
      expect(creds.credentials).toHaveLength(1);
      expect(creds.credentials[0].rpId).toBe('localhost');
      expect(Buffer.from(creds.credentials[0].credentialId, 'base64').toString('base64url')).toBe(credId);
    });

    it('before a device approved it, the passkey does not sign in', async () => {
      await context.clearCookies();
      await page.goto(`${AS_URL}/login`);
      await page.getByTestId('passkey-signin').getByRole('button').click();
      await page.getByTestId('passkey-signin').locator('.alert-danger').waitFor({ timeout: 30_000 });
      expect(page.url()).toContain('/login');
    });

    it('a device approval without the device\'s check is refused; without a device session too', async () => {
      const noCheck = await http(AS_URL, 'POST', '/api/passkeys/register', { token: p.token, body: await registerEnvelope(p, requestId, credId, 'localhost', { check: false }) });
      expect(noCheck.status, show(noCheck)).toBe(403);
      expect(code(noCheck)).toBe('CHECK_REQUIRED');
      const noSession = await http(AS_URL, 'POST', '/api/passkeys/register', { body: await registerEnvelope(p, requestId, credId, 'localhost') });
      expect(noSession.status, show(noSession)).toBe(401);
    });

    it('the person\'s device approves it with its check; then the passkey signs in to the dashboard in the browser', async () => {
      const ok = await http(AS_URL, 'POST', '/api/passkeys/register', { token: p.token, body: await registerEnvelope(p, requestId, credId, 'localhost') });
      expect(ok.status, show(ok)).toBe(201);
      expect(ok.json).toEqual({ registered: true, cred_id: credId });

      await context.clearCookies();
      await page.goto(`${AS_URL}/login`);
      await page.getByTestId('passkey-signin').getByRole('button').click();
      await page.waitForURL(/\/dashboard/, { timeout: 30_000 });
      const cookie = (await context.cookies()).find((c) => c.name === 'hap-session');
      expect(cookie?.httpOnly).toBe(true);
      const kind = await db.query<{ kind: string; user_id: string }>('select kind, user_id from sessions where token = $1', [cookie!.value]);
      expect(kind.rows[0]).toEqual({ kind: 'browser', user_id: p.userId });
    });

    it('an email-link session can neither start a passkey nor change team settings', async () => {
      const cookie = await emailLinkCookie(db, p.userId);
      const start = await http(AS_URL, 'POST', '/api/passkeys/register/options', { cookie });
      expect(start.status, show(start)).toBe(401);
      expect(code(start)).toBe('BROWSER_SESSION_REQUIRED');
      const team = await http(AS_URL, 'POST', '/api/groups', { cookie, body: { name: 'From the email link' } });
      expect(team.status, show(team)).toBe(403);
      expect(code(team)).toBe('EMAIL_LINK_READ_ONLY');
    });
  });

  describe('retention', () => {
    let w: World;
    let e: Awaited<ReturnType<typeof threeEndings>>;
    let expiring: string;

    beforeAll(async () => {
      w = await world(AS_URL, db);
      e = await threeEndings(w);
      expiring = await propose(w); // stays pending; expires within 72 hours
    }, 120_000);

    it('a ticket issued, an "ask for a change" and a withdrawal leave no content; fingerprint, decision and ticket stay', async () => {
      for (const id of [e.ticketed, e.changed, e.withdrawn]) expectGone(await row(w, id));
      expect((await row(w, e.ticketed)).status).toBe('executed');
      const changed = await row(w, e.changed);
      expect(changed.approver_rejected_by!.outcome).toBe('change_needed');
      expect(changed.approver_rejected_by!.noteEncrypted).toEqual(e.note); // the submitting gateway still reads it
      expect((await row(w, e.withdrawn)).withdrawn_by!.userId).toBe(w.grantor.id);

      // Served: no content, the same fingerprint.
      const read = await http(AS_URL, 'GET', `/api/proposals/${e.ticketed}`, { apiKey: w.grantor.apiKey });
      expect(read.status, show(read)).toBe(200);
      expect(read.json.proposal.content).toBeNull();
      expect(read.json.proposal.contentHash).toBe(fingerprint);
      expect(read.json.proposal.status).toBe('executed');
      // The ticket: the same request still gets the original back.
      const replay = await http(AS_URL, 'POST', '/api/as/ticket', { apiKey: w.grantor.apiKey, body: ticketBody(w, e.ticketed) });
      expect(replay.status, show(replay)).toBeLessThan(300);
      expect(replay.json.idempotent).toBe(true);
      expect(replay.json.ticket.proposalContentHash).toBe(fingerprint);
      expect(replay.json.ticket.id ?? replay.json.ticket.ticketId).toBe(e.ticket.id ?? e.ticket.ticketId);
      // A waiting proposal keeps its content.
      expectKept(await row(w, expiring));
    });

    it('31 days later (the AS clock moved): the encrypted note is gone, and the expired proposal has no content', async () => {
      await clock.set(31 * DAY);
      try {
        // The sweep is lazy: a proposal read runs it.
        const read = await http(AS_URL, 'GET', `/api/proposals/${expiring}`, { apiKey: w.grantor.apiKey });
        expect(read.status, show(read)).toBe(200);
        expect(read.json.proposal.status).toBe('expired');
        expectGone(await row(w, expiring));
        const changed = await row(w, e.changed);
        expect(changed.approver_rejected_by!.noteEncrypted).toBeUndefined();
        expect(changed.approver_rejected_by!.outcome).toBe('change_needed');
        expect(changed.content_hash).toBe(fingerprint);
      } finally {
        await clock.set(0);
      }
    });
  });
});

describe.skipIf(!available)('step 17, switch off: nothing is deleted, no passkey route exists', () => {
  const pm = new ProcessManager();
  let db: pg.Client;

  beforeAll(async () => {
    await pm.startSP(AS_OFF_PORT, { name: 'as-step17-off', env: { SUVEREN_DEVICE_KEYS: '', SUVEREN_DASHBOARD_ORIGIN: AS_OFF_URL, SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS: '1' } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
  }, 240_000);
  afterAll(async () => {
    await db?.end().catch(() => undefined);
    await pm.killAll();
  }, 60_000);

  it('the same endings keep the content and the note', async () => {
    const w = await world(AS_OFF_URL, db);
    const e = await threeEndings(w);
    for (const id of [e.ticketed, e.changed, e.withdrawn]) expectKept(await row(w, id));
    expect((await row(w, e.changed)).approver_rejected_by!.noteEncrypted).toEqual(e.note);
    const read = await http(AS_OFF_URL, 'GET', `/api/proposals/${e.ticketed}`, { apiKey: w.grantor.apiKey });
    expect(read.json.proposal.content).not.toBeNull();
  });

  it('every passkey route answers 404', async () => {
    for (const path of ['/api/passkeys/register/options', '/api/passkeys/register/credential', '/api/passkeys/register', '/api/passkeys/login/options', '/api/passkeys/login']) {
      expect((await http(AS_OFF_URL, 'POST', path, { body: {} })).status, path).toBe(404);
    }
  });
});
