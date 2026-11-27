/**
 * Retiring the API key per account (AS switch SUVEREN_API_KEY_RETIRE, only with SUVEREN_DEVICE_KEYS=on).
 * Real Authority Server (`next start`, real Postgres) and a real Chromium with a virtual WebAuthn authenticator.
 * No gateway is started: the subject is what the AS answers to the account key.
 *
 *   1. A chain account without a dashboard passkey: the key still signs in (dashboard and gateway header).
 *   2. After a dashboard passkey is approved by a device: `/api/auth/session` with the key is refused with
 *      401 API_KEY_RETIRED (with and without the gateway header), an X-API-Key route is 401, a session the key opened
 *      earlier is refused, the passkey signs in, and a retired key together with a valid device Bearer still works.
 *   3. Removing the approving device does not bring the key back.
 *   4. A chain-less account gets the same answers with the switch on as with it off (response snapshot).
 *   5. Switch off: the account of test 2 keeps working with its key.
 *   6. An email-link session of a chain account may start a dashboard passkey request (nothing is stored until a
 *      device approves); `generate-key` answers 410.
 *
 * The AS runs from `next build`, which inlines NODE_ENV as "production": the http://localhost dashboard address needs
 * the AS's runtime opt-in SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS=1.
 *
 * Skips unless SUVEREN_DB_URL is set and the AS under test has the retirement switch (migration 037).
 * NOT YET RUN: written against suveren-as feat/api-key-retire; the first run may need selector or timing fixes.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { chromium, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { buildEntry, entryHash, signEntry, objectHash, signObject, type ChainEntry } from '@humanagencyp/hap-core/device-keys';

import { AS_DIR } from '../src/helpers/as-dir.js';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { checkOver, genesisEntry, headOf, newDevice, newRoot, signinBody, type Device, type Root } from '../src/helpers/device-chain.js';

const AS_ON_PORT = 19992;
const AS_OFF_PORT = 19993;
const AS_ON = `http://localhost:${AS_ON_PORT}`;
const AS_OFF = `http://localhost:${AS_OFF_PORT}`;
const GATEWAY_HEADER = { 'x-suveren-gateway-version': '0.47.0' };

const available = !!process.env.SUVEREN_DB_URL
  && existsSync(join(AS_DIR, 'src', 'app', 'api', 'passkeys', 'login', 'route.ts'))
  && (() => { try { return readdirSync(join(AS_DIR, 'migrations')).some((f) => f.startsWith('037_api_key_retire')); } catch { return false; } })();

// ─── HTTP ────────────────────────────────────────────────────────────────────

interface Res { status: number; json: any; setCookie: string | null }
async function http(base: string, method: string, path: string, o: { token?: string; apiKey?: string; cookie?: string; body?: unknown; ip?: string; headers?: Record<string, string> } = {}): Promise<Res> {
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(o.headers ?? {}) };
  if (o.token) headers.authorization = `Bearer ${o.token}`;
  if (o.apiKey) headers['x-api-key'] = o.apiKey;
  if (o.cookie) headers.cookie = o.cookie;
  if (o.ip) headers['x-forwarded-for'] = o.ip;
  const res = await fetch(`${base}${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  return { status: res.status, json, setCookie: res.headers.get('set-cookie') };
}
const show = (r: Res) => JSON.stringify(r.json);
const code = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.code;
const now = () => Math.floor(Date.now() / 1000);
const fakeIp = () => `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
const cookieOf = (r: Res) => /hap-session=([^;]+)/.exec(r.setCookie ?? '')?.[1];

// ─── people with a device chain ──────────────────────────────────────────────

interface Approver { dev: Device; token: string }
interface Person { userId: string; apiKey: string; root: Root; first: Approver; tip: ChainEntry }

async function deviceToken(base: string, root: Root, dev: Device, tip: ChainEntry): Promise<string> {
  const ch = await http(base, 'POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id }, ip: fakeIp() });
  expect(ch.status, show(ch)).toBe(200);
  const sess = await http(base, 'POST', '/api/devices/session', { body: await signinBody(root, dev, await headOf(tip), ch.json) });
  expect(sess.status, show(sess)).toBe(200);
  return sess.json.token as string;
}

/** An email-link session, as /api/auth/welcome opens one (the test has no mailbox). */
async function emailLinkToken(db: pg.Client, userId: string): Promise<string> {
  const token = randomUUID();
  await db.query(`insert into sessions (token, user_id, kind, created_at, expires_at, opened_by) values ($1, $2, 'email-link', $3, $4, 'email-link')`, [token, userId, now(), now() + 3600]);
  return token;
}

async function chained(base: string, db: pg.Client, name: string): Promise<Person> {
  const sp = new SPClient(base);
  const r = await sp.register(name, `${name.toLowerCase().replace(/\W+/g, '-')}-${randomUUID().slice(0, 8)}@test.local`);
  const codeRes = await http(base, 'POST', '/api/enrolment-codes', { cookie: `hap-session=${await emailLinkToken(db, r.user.id)}` });
  expect(codeRes.status, show(codeRes)).toBe(201);
  const root = await newRoot();
  const dev = await newDevice();
  const g = await genesisEntry(root, dev);
  const chainRes = await http(base, 'POST', '/api/devices/chain', { body: { entry: g, enrolment_code: codeRes.json.code } });
  expect(chainRes.status, show(chainRes)).toBe(201);
  return { userId: r.user.id, apiKey: r.apiKey, root, first: { dev, token: await deviceToken(base, root, dev, g) }, tip: g };
}

/** A second device, admitted by the first (its own device session at the new head). */
async function addSecondDevice(base: string, p: Person): Promise<Approver> {
  const dev = await newDevice();
  const e = buildEntry({ root_did: p.root.did, seq: p.tip.seq + 1, prev: await entryHash(p.tip), op: 'add', created_at: now(), signer: p.first.dev.record.key_id, device: dev.record });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, p.first.dev.record.key_id, p.first.dev.seed), await signEntry(e, dev.record.key_id, dev.seed)];
  e.checks = [{ by: p.first.dev.record.key_id, check: await checkOver(p.first.dev.checkPriv, h) }, { by: dev.record.key_id, check: await checkOver(dev.checkPriv, h) }];
  const res = await http(base, 'POST', '/api/devices/chain', { token: p.first.token, body: { entry: e } });
  expect(res.status, show(res)).toBe(201);
  p.tip = e;
  return { dev, token: await deviceToken(base, p.root, dev, e) };
}

async function removeDevice(base: string, p: Person, signer: Approver, target: Approver): Promise<void> {
  const e = buildEntry({ root_did: p.root.did, seq: p.tip.seq + 1, prev: await entryHash(p.tip), op: 'remove', created_at: now(), signer: signer.dev.record.key_id, target: target.dev.record.key_id });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, signer.dev.record.key_id, signer.dev.seed)];
  e.checks = [{ by: signer.dev.record.key_id, check: await checkOver(signer.dev.checkPriv, h) }];
  const res = await http(base, 'POST', '/api/devices/chain', { token: signer.token, body: { entry: e } });
  expect(res.status, show(res)).toBe(201);
  p.tip = e;
}

async function approveEnvelope(p: Person, approver: Approver, requestId: string, credId: string) {
  const head = await headOf(p.tip);
  const register = {
    typ: 'suveren-passkey-register', v: 1, root_did: p.root.did, key_id: approver.dev.record.key_id, chain_seq: head.seq, chain_head: head.hash,
    request_id: requestId, cred_id: credId, rp_id: 'localhost', issued_at: now(),
  };
  const sig = await signObject(register as never, approver.dev.seed);
  return { register, sig, check: await checkOver(approver.dev.checkPriv, await objectHash(register as never)) };
}

// ─── the browser ─────────────────────────────────────────────────────────────

interface Browserish { context: BrowserContext; page: Page }

async function newBrowser(browser: Browser): Promise<Browserish> {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { context, page };
}

async function signInWithKeyInBrowser(base: string, b: Browserish, apiKey: string): Promise<void> {
  await b.page.goto(`${base}/login`);
  // The API key field sits behind "Sign in with an API key instead" when device keys are on (sign-in page, 2026-11-27).
  { const k = b.page.getByTestId('api-key-signin'); if (await k.count()) await k.locator('summary').click(); }
  await b.page.fill('#apiKey', apiKey);
  await b.page.click('form button[type=submit]');
  await b.page.waitForURL(/\/dashboard/, { timeout: 30_000 });
}

/** On /dashboard/passkeys: create the passkey in the browser; returns what a device approves. */
async function createPasskeyInBrowser(base: string, b: Browserish): Promise<{ requestId: string; credId: string }> {
  await b.page.goto(`${base}/dashboard/passkeys`);
  await b.page.getByTestId('passkey-register').getByRole('button').click();
  await b.page.getByTestId('passkey-pending').waitFor({ timeout: 30_000 });
  return {
    requestId: (await b.page.getByTestId('passkey-request-id').textContent())!.trim(),
    credId: (await b.page.getByTestId('passkey-cred-id').textContent())!.trim(),
  };
}

async function signInWithPasskeyInBrowser(base: string, b: Browserish): Promise<void> {
  await b.context.clearCookies();
  await b.page.goto(`${base}/login`);
  await b.page.getByTestId('passkey-signin').getByRole('button').click();
  await b.page.waitForURL(/\/dashboard/, { timeout: 30_000 });
}

/** The key signs in on the login page, or it does not (the page stays on /login with no session cookie). */
async function keySignInRefusedInBrowser(base: string, b: Browserish, apiKey: string): Promise<boolean> {
  await b.context.clearCookies();
  await b.page.goto(`${base}/login`);
  // The API key field sits behind "Sign in with an API key instead" when device keys are on (sign-in page, 2026-11-27).
  { const k = b.page.getByTestId('api-key-signin'); if (await k.count()) await k.locator('summary').click(); }
  await b.page.fill('#apiKey', apiKey);
  await b.page.click('form button[type=submit]');
  await b.page.waitForTimeout(3_000);
  const cookie = (await b.context.cookies()).find((c) => c.name === 'hap-session');
  return !cookie && b.page.url().includes('/login');
}

const proposalsGet = (base: string, o: { apiKey?: string; cookie?: string; token?: string }) => http(base, 'GET', '/api/proposals?creator=me', o);

// ─── the suites ──────────────────────────────────────────────────────────────

describe.skipIf(!available)('API key retirement: switch on (real Authority Server, real Chromium)', () => {
  const pm = new ProcessManager();
  let db: pg.Client;
  let browser: Browser;

  beforeAll(async () => {
    await pm.startSP(AS_ON_PORT, { name: 'as-key-retire-on', env: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_API_KEY_RETIRE: 'on', SUVEREN_DASHBOARD_ORIGIN: AS_ON, SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS: '1' } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
  }, 240_000);
  afterAll(async () => {
    await browser?.close().catch(() => undefined);
    await db?.end().catch(() => undefined);
    await pm.killAll();
  }, 60_000);

  describe('tests 1 and 2: before and after the first dashboard passkey', () => {
    let p: Person;
    let b: Browserish;
    let keyBrowserCookie: string;
    let keyGatewayCookie: string;
    let requestId: string;
    let credId: string;

    beforeAll(async () => {
      p = await chained(AS_ON, db, 'Retire Person');
      b = await newBrowser(browser);
    }, 120_000);
    afterAll(async () => { await b?.context.close().catch(() => undefined); });

    it('1. a chain account without a dashboard passkey: the key still signs in (dashboard, gateway header, X-API-Key route)', async () => {
      const browserRes = await http(AS_ON, 'POST', '/api/auth/session', { apiKey: p.apiKey });
      expect(browserRes.status, show(browserRes)).toBe(200);
      keyBrowserCookie = `hap-session=${cookieOf(browserRes)}`;
      const gatewayRes = await http(AS_ON, 'POST', '/api/auth/session', { apiKey: p.apiKey, headers: GATEWAY_HEADER });
      expect(gatewayRes.status, show(gatewayRes)).toBe(200);
      keyGatewayCookie = `hap-session=${cookieOf(gatewayRes)}`;
      expect((await proposalsGet(AS_ON, { apiKey: p.apiKey })).status).toBe(200);
      await signInWithKeyInBrowser(AS_ON, b, p.apiKey);
      const opened = await db.query<{ opened_by: string }>(`select opened_by from sessions where token = $1`, [keyBrowserCookie.split('=')[1]]);
      expect(opened.rows[0].opened_by).toBe('apikey');
    });

    it('2. a device approves the dashboard passkey; the account is marked', async () => {
      ({ requestId, credId } = await createPasskeyInBrowser(AS_ON, b));
      const before = await db.query(`select api_key_retired_at from users where id = $1`, [p.userId]);
      expect(before.rows[0].api_key_retired_at).toBeNull(); // nothing is marked until a device approves
      const ok = await http(AS_ON, 'POST', '/api/passkeys/register', { token: p.first.token, body: await approveEnvelope(p, p.first, requestId, credId) });
      expect(ok.status, show(ok)).toBe(201);
      const after = await db.query(`select api_key_retired_at from users where id = $1`, [p.userId]);
      expect(after.rows[0].api_key_retired_at).not.toBeNull();
    });

    it('2. the key opens nothing: session route 401 API_KEY_RETIRED (with and without the gateway header), X-API-Key route 401', async () => {
      for (const headers of [undefined, GATEWAY_HEADER]) {
        const r = await http(AS_ON, 'POST', '/api/auth/session', { apiKey: p.apiKey, headers });
        expect(r.status, show(r)).toBe(401);
        expect(r.json.code).toBe('API_KEY_RETIRED');
        expect(typeof r.json.error).toBe('string');
        expect(r.setCookie).toBeNull();
      }
      const route = await proposalsGet(AS_ON, { apiKey: p.apiKey });
      expect(route.status, show(route)).toBe(401);
      expect(route.json).toEqual({ error: 'Authentication required' });
      expect(await keySignInRefusedInBrowser(AS_ON, b, p.apiKey)).toBe(true);
    });

    it('2. sessions the key opened before are gone', async () => {
      expect((await proposalsGet(AS_ON, { cookie: keyBrowserCookie })).status).toBe(401);
      expect((await proposalsGet(AS_ON, { cookie: keyGatewayCookie })).status).toBe(401);
      const left = await db.query<{ n: string }>(`select count(*)::text as n from sessions where user_id = $1 and kind in ('browser','gateway') and opened_by = 'apikey'`, [p.userId]);
      expect(left.rows[0].n).toBe('0');
    });

    it('2. the passkey signs in to the dashboard, and that session is opened_by passkey', async () => {
      await signInWithPasskeyInBrowser(AS_ON, b);
      const cookie = (await b.context.cookies()).find((c) => c.name === 'hap-session')!;
      const row = await db.query<{ kind: string; opened_by: string }>(`select kind, opened_by from sessions where token = $1`, [cookie.value]);
      expect(row.rows[0]).toEqual({ kind: 'browser', opened_by: 'passkey' });
      expect((await proposalsGet(AS_ON, { cookie: `hap-session=${cookie.value}` })).status).toBe(200);
    });

    it('2. a retired key together with a valid device Bearer still works (as the device)', async () => {
      const r = await proposalsGet(AS_ON, { apiKey: p.apiKey, token: p.first.token });
      expect(r.status, show(r)).toBeLessThan(400);
    });
  });

  describe('test 3: removing the approving device does not bring the key back', () => {
    it('the passkey goes with its device; the key stays refused', async () => {
      const p = await chained(AS_ON, db, 'Retire Remove');
      const second = await addSecondDevice(AS_ON, p);
      const b = await newBrowser(browser);
      try {
        await signInWithKeyInBrowser(AS_ON, b, p.apiKey);
        const { requestId, credId } = await createPasskeyInBrowser(AS_ON, b);
        const ok = await http(AS_ON, 'POST', '/api/passkeys/register', { token: second.token, body: await approveEnvelope(p, second, requestId, credId) });
        expect(ok.status, show(ok)).toBe(201);
        await removeDevice(AS_ON, p, p.first, second);
        const left = await db.query<{ n: string }>(`select count(*)::text as n from passkeys where user_id = $1 and kind = 'dashboard'`, [p.userId]);
        expect(left.rows[0].n).toBe('0');
        const r = await http(AS_ON, 'POST', '/api/auth/session', { apiKey: p.apiKey });
        expect(r.status, show(r)).toBe(401);
        expect(r.json.code).toBe('API_KEY_RETIRED');
        expect((await proposalsGet(AS_ON, { apiKey: p.apiKey })).status).toBe(401);
      } finally {
        await b.context.close().catch(() => undefined);
      }
    });
  });

  describe('test 6 (decision 2): an email-link session of a chain account may start a passkey request', () => {
    it('the request waits for a device; nothing signs in until it approves; generate-key answers 410', async () => {
      const p = await chained(AS_ON, db, 'Retire Mail');
      const b = await newBrowser(browser);
      try {
        const token = await emailLinkToken(db, p.userId);
        await b.context.addCookies([{ name: 'hap-session', value: token, url: AS_ON, httpOnly: true, sameSite: 'Strict' }]);
        const { requestId, credId } = await createPasskeyInBrowser(AS_ON, b);
        const stored = await db.query<{ n: string }>(`select count(*)::text as n from passkeys where credential_id = $1`, [credId]);
        expect(stored.rows[0].n).toBe('0');
        const marked = await db.query(`select api_key_retired_at from users where id = $1`, [p.userId]);
        expect(marked.rows[0].api_key_retired_at).toBeNull();
        const ok = await http(AS_ON, 'POST', '/api/passkeys/register', { token: p.first.token, body: await approveEnvelope(p, p.first, requestId, credId) });
        expect(ok.status, show(ok)).toBe(201);
        // Every other email-link write stays refused.
        const team = await http(AS_ON, 'POST', '/api/groups', { cookie: `hap-session=${token}`, body: { name: 'From the email link' } });
        expect(team.status, show(team)).toBe(403);
        expect(code(team)).toBe('EMAIL_LINK_READ_ONLY');
      } finally {
        await b.context.close().catch(() => undefined);
      }
      const gk = await http(AS_ON, 'POST', '/api/auth/generate-key', { cookie: `hap-session=${await emailLinkToken(db, p.userId)}` });
      expect(gk.status, show(gk)).toBe(410);
    });
  });

  describe('test 4 (switch-on half): a chain-less account', () => {
    it('answers as recorded in the switch-off suite below (same snapshot)', async () => {
      snapshots.on = await chainlessSnapshot(AS_ON);
      expect(snapshots.on.length).toBeGreaterThan(0);
    });
  });
});

// ─── test 4: a chain-less account answers the same with the switch on and off ─────

const snapshots: { on?: unknown[]; off?: unknown[] } = {};

/** What an account without a chain sees, with ids, times and tokens scrubbed. generate-key is left out on purpose: the switch makes it 410 for everyone. */
async function chainlessSnapshot(base: string): Promise<unknown[]> {
  const sp = new SPClient(base);
  const r = await sp.register('Chainless Person', `chainless-${randomUUID().slice(0, 8)}@test.local`);
  const scrub = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (k, val) => (['id', 'did', 'email', 'sessionExpiresAt'].includes(k) ? '<scrubbed>' : val)));
  const calls: Array<[string, () => Promise<Res>]> = [
    ['session, no key', () => http(base, 'POST', '/api/auth/session')],
    ['session, wrong key', () => http(base, 'POST', '/api/auth/session', { apiKey: 'not-a-key' })],
    ['session, key, browser', () => http(base, 'POST', '/api/auth/session', { apiKey: r.apiKey })],
    ['session, key, gateway', () => http(base, 'POST', '/api/auth/session', { apiKey: r.apiKey, headers: GATEWAY_HEADER })],
    ['X-API-Key route', () => proposalsGet(base, { apiKey: r.apiKey })],
    ['no auth', () => proposalsGet(base, {})],
  ];
  const out: unknown[] = [];
  for (const [name, call] of calls) {
    const res = await call();
    out.push({ name, status: res.status, body: scrub(res.json), setsCookie: res.setCookie !== null });
  }
  return out;
}

describe.skipIf(!available)('API key retirement: switch off (a second Authority Server, device keys on)', () => {
  const pm = new ProcessManager();
  let db: pg.Client;
  let browser: Browser;

  beforeAll(async () => {
    await pm.startSP(AS_OFF_PORT, { name: 'as-key-retire-off', env: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_API_KEY_RETIRE: '', SUVEREN_DASHBOARD_ORIGIN: AS_OFF, SUVEREN_ALLOW_HTTP_LOCAL_ORIGINS: '1' } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
    browser = await chromium.launch({ headless: true, args: ['--disable-blink-features=AutomationControlled'] });
  }, 240_000);
  afterAll(async () => {
    await browser?.close().catch(() => undefined);
    await db?.end().catch(() => undefined);
    await pm.killAll();
  }, 60_000);

  it('5. after a dashboard passkey, the key still signs in, nothing is marked, nothing ended', async () => {
    const p = await chained(AS_OFF, db, 'Retire Off');
    const b = await newBrowser(browser);
    try {
      await signInWithKeyInBrowser(AS_OFF, b, p.apiKey);
      const keyCookie = (await b.context.cookies()).find((c) => c.name === 'hap-session')!.value;
      const { requestId, credId } = await createPasskeyInBrowser(AS_OFF, b);
      const ok = await http(AS_OFF, 'POST', '/api/passkeys/register', { token: p.first.token, body: await approveEnvelope(p, p.first, requestId, credId) });
      expect(ok.status, show(ok)).toBe(201);
      const marked = await db.query(`select api_key_retired_at from users where id = $1`, [p.userId]);
      expect(marked.rows[0].api_key_retired_at).toBeNull();
      expect((await proposalsGet(AS_OFF, { cookie: `hap-session=${keyCookie}` })).status).toBe(200);
      for (const headers of [undefined, GATEWAY_HEADER]) {
        const r = await http(AS_OFF, 'POST', '/api/auth/session', { apiKey: p.apiKey, headers });
        expect(r.status, show(r)).toBe(200);
      }
      expect((await proposalsGet(AS_OFF, { apiKey: p.apiKey })).status).toBe(200);
      expect(await keySignInRefusedInBrowser(AS_OFF, b, p.apiKey)).toBe(false);
    } finally {
      await b.context.close().catch(() => undefined);
    }
  }, 180_000);

  it('5. an email-link session still cannot start a passkey request; generate-key is not 410', async () => {
    const p = await chained(AS_OFF, db, 'Retire Off Mail');
    const token = await emailLinkToken(db, p.userId);
    const start = await http(AS_OFF, 'POST', '/api/passkeys/register/options', { cookie: `hap-session=${token}` });
    expect(start.status, show(start)).toBe(401);
    expect(code(start)).toBe('BROWSER_SESSION_REQUIRED');
    const gk = await http(AS_OFF, 'POST', '/api/auth/generate-key', { cookie: `hap-session=${token}` });
    expect(gk.status).not.toBe(410);
  });

  it('4. a chain-less account: the same answers as with the switch on', async () => {
    snapshots.off = await chainlessSnapshot(AS_OFF);
    expect(snapshots.on, 'the switch-on suite must run first in this file').toBeDefined();
    expect(snapshots.off).toEqual(snapshots.on);
  });
});
