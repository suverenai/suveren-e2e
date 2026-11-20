/**
 * Notifications to phones, device-keys plan step 15 / stage D4, against the REAL Authority Server over HTTP.
 *
 * The push service is played by this file: a real local HTTP endpoint the Authority Server posts to (the Authority
 * Server accepts it through SUVEREN_PUSH_EXTRA_ORIGINS, a setting for exactly this). Every request it gets is read
 * here: the VAPID header is verified against the key the Authority Server publishes (RFC 8292), and the body is
 * decrypted with the phone's own key by an RFC 8291 implementation in THIS file, independent of the server's code.
 *
 * Cases
 *   1. A waiting request sends one notification per phone that can read it; the payload is the id only, encrypted.
 *   2. A request this phone holds no wrap of sends nothing to it.
 *   3. Grouping (DEC-40): after three in ten minutes the next are held; ten minutes later one notification names them
 *      all (the Authority Server's clock is moved, the proposals are real).
 *   4. A removed phone's subscription is deleted with it; a push service answering 410 deletes it too.
 *   5. Only a phone session may subscribe; an endpoint that is not a push service is refused.
 *   6. With the switch off every new route answers 404.
 *
 * Seams that are not HTTP (each a write into the throwaway database):
 *   - A chain needs an enrolment code that only a dashboard session from an email link may fetch: that session row is
 *     inserted (same as test/team-member-list).
 *   None other. The mandate is granted (plan 4.4) by the person's computer, a test-held device with a check key, before
 *     the Authority Server issues it (src/helpers/mandate-grant.ts, shared with the stage C suite); every request is
 *     then filed under that real granted mandate.
 *
 * Not covered: the hourly cap of 50 (DEC-28; the AS's unit tests seed the counter), a real push service (Apple, Google)
 * and a real phone showing the notice (by hand, plan 12.2), the app's service worker (the app's own tests).
 *
 * Needs: SUVEREN_DB_URL and an Authority Server checkout with the push routes (step 15); otherwise the suite skips.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { createServer, type Server } from 'node:http';
import { createDecipheriv, createECDH, createPublicKey, hkdfSync, randomBytes as nodeRandom, randomUUID, verify } from 'node:crypto';
import pg from 'pg';
import { b64uEncode, randomBytes, type ChainEntry } from '@humanagencyp/hap-core/device-keys';

import { AS_DIR } from '../src/helpers/as-dir.js';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import type { MandatePayload } from '@humanagencyp/hap-core';
import { hashGateContent, computeBoundsHash, computeScopeHash, computeExecutionContextHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';
import { grantMembersOf, newMandateId, signedGrant } from '../src/helpers/mandate-grant.js';
import { shiftedClock } from '../src/helpers/clock.js';
import { genesisEntry, headOf, newDevice, newRoot, signinBody, type Device, type Root } from '../src/helpers/device-chain.js';
import { admitEntry, newPhone, phoneSigninBody, registration, removeEntry, type Phone } from '../src/helpers/phone-passkey.js';

const AS_PORT = 19953;
const AS_OFF_PORT = 19954;
const AS_URL = `http://localhost:${AS_PORT}`;
const APP_ORIGIN = 'https://approve.e2e.test';
const PROFILE_ID = PROFILE_V07.charge;
const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;

const available = !!process.env.SUVEREN_DB_URL && existsSync(join(AS_DIR, 'src', 'app', 'api', 'devices', 'me', 'push', 'route.ts'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const clock = shiftedClock();
let db: pg.Client;

// ─── The push service ────────────────────────────────────────────────────────

interface Got { path: string; headers: Record<string, string | string[] | undefined>; body: Buffer }
let push: Server;
let pushOrigin = '';
const got: Got[] = [];
const answer = new Map<string, number>();

// ─── RFC 8291, the receiving side (what a browser does), written here on its own ─

function decrypt(body: Buffer, uaPrivate: Buffer, auth: Buffer): string {
  const salt = body.subarray(0, 16);
  const idlen = body.readUInt8(20);
  const asPublic = body.subarray(21, 21 + idlen);
  const ct = body.subarray(21 + idlen);
  const ua = createECDH('prime256v1');
  ua.setPrivateKey(uaPrivate);
  const secret = ua.computeSecret(asPublic);
  const ikm = Buffer.from(hkdfSync('sha256', secret, auth, Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPublic]), 32));
  const cek = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const d = createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(ct.subarray(ct.length - 16));
  const plain = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  expect(plain[plain.length - 1]).toBe(0x02); // the last record's delimiter, no padding
  return plain.subarray(0, plain.length - 1).toString('utf8');
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

interface Res { status: number; json: any }
async function http(base: string, method: string, path: string, o: { token?: string; apiKey?: string; cookie?: string; body?: unknown } = {}): Promise<Res> {
  const headers: Record<string, string> = { 'content-type': 'application/json', 'x-forwarded-for': `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}` };
  if (o.token) headers.authorization = `Bearer ${o.token}`;
  if (o.apiKey) headers['x-api-key'] = o.apiKey;
  if (o.cookie) headers.cookie = o.cookie;
  const res = await fetch(`${base}${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  return { status: res.status, json };
}
const as = (method: string, path: string, o?: Parameters<typeof http>[3]) => http(AS_URL, method, path, o);
const show = (r: Res) => JSON.stringify(r.json);
const code = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.code;
const now = () => Math.floor(Date.now() / 1000);

// ─── People and phones ───────────────────────────────────────────────────────

interface PhoneSub { phone: Phone; token: string; ua: ReturnType<typeof createECDH>; auth: Buffer; path: string }
interface Person { userId: string; apiKey: string; authId: string; mandate: Record<string, any>; root: Root; dev: Device; token: string; tip: ChainEntry; phones: PhoneSub[] }

async function person(name: string): Promise<Person> {
  const r = await sp.register(name, `${name.toLowerCase()}-${randomUUID().slice(0, 8)}@test.local`);
  // The chain: genesis on a computer with an enrolment code, then a device session.
  const cookie = randomUUID();
  await db.query(`insert into sessions (token, user_id, kind, created_at, expires_at) values ($1, $2, 'email-link', $3, $4)`, [cookie, r.user.id, now(), now() + 3600]);
  const enrol = await as('POST', '/api/enrolment-codes', { cookie: `hap-session=${cookie}` });
  expect(enrol.status, show(enrol)).toBe(201);
  const root = await newRoot();
  const dev = await newDevice();
  const g = await genesisEntry(root, dev);
  const c = await as('POST', '/api/devices/chain', { body: { entry: g, enrolment_code: enrol.json.code } });
  expect(c.status, show(c)).toBe(201);
  const ch = await as('POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id } });
  const s = await as('POST', '/api/devices/session', { body: await signinBody(root, dev, await headOf(g), ch.json) });
  expect(s.status, show(s)).toBe(200);
  const token = s.json.token as string;

  // The mandate: a review mandate in the person's own workspace, granted on the computer first (plan 4.4), then issued.
  const groupId = await sp.getPersonalGroupId(r.apiKey);
  const bounds = { profile: PROFILE_ID, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 };
  const request = {
    profile_id: PROFILE_ID, profile_hash: profileHashFor(PROFILE_ID, PROFILES_DIR), group_id: groupId, bounds,
    bounds_hash: computeBoundsHash(bounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
    scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
    domain: 'owner', did: root.did, mandate_owners: [{ did: root.did }], commitment_mode: 'review',
    gate_content_hashes: hashGateContent({ intent: 'Notifications e2e.' }),
    execution_context_hash: computeExecutionContextHash(loadProfile(PROFILE_ID, PROFILES_DIR) as { executionContextSchema?: unknown }),
    supported_versions: ['0.8', '0.7'],
  };
  const mandateId = newMandateId();
  const authorization = mintAuthorizationId();
  const expiresAt = now() + 86_400;
  const payload = {
    mandate_id: mandateId, version: '0.8', profile_id: request.profile_id, profile_hash: request.profile_hash,
    bounds_hash: request.bounds_hash, scope_hash: request.scope_hash, execution_context_hash: request.execution_context_hash,
    issuer: 'did:key:z', mandate_owners: [{ did: root.did }], gate_content_hashes: request.gate_content_hashes,
    commitment_mode: request.commitment_mode, issued_at: now(), expires_at: expiresAt,
  } as unknown as MandatePayload;
  const grant = await as('POST', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, {
    token,
    body: await signedGrant({
      dev, ownerDid: root.did, head: await headOf(g), mandateId, version: 1,
      members: grantMembersOf(payload, { authorizationId: authorization, groupId, replaces: null, chainDids: [root.did] }),
    }),
  });
  expect(grant.status, show(grant)).toBe(201);
  const m = await as('POST', '/api/as/mandate', {
    apiKey: r.apiKey, body: { ...request, authorization_id: authorization, mandate_id: mandateId, mandate_version: 1, expires_at: expiresAt },
  });
  expect(m.status, show(m)).toBeLessThan(300);
  const mandate = JSON.parse(Buffer.from(m.json.blob as string, 'base64url').toString('utf8')).payload;
  expect(mandate.mandate_id).toBe(mandateId);
  expect(mandate.mandate_owners[0].did).toBe(root.did);
  return { userId: r.user.id, apiKey: r.apiKey, authId: m.json.authorization_id, mandate, root, dev, token, tip: g, phones: [] };
}

/** The computer admits a phone the way the app does (pairing id + the phone's passkey); the phone signs in and subscribes. */
async function addPhone(p: Person, subscribe = true): Promise<PhoneSub> {
  const phone = await newPhone(APP_ORIGIN);
  const pairingId = b64uEncode(randomBytes(16));
  const open = await as('POST', '/api/devices/pairings', { token: p.token, body: { pairing_id: pairingId, expires_at: now() + 600 } });
  expect(open.status, show(open)).toBe(201);
  const pk = await as('POST', `/api/devices/pairings/${pairingId}/passkey`, { body: registration(phone) });
  expect(pk.status, show(pk)).toBe(201);
  const entry = await admitEntry(p.root, p.tip, p.dev, phone);
  const add = await as('POST', '/api/devices/chain', { token: p.token, body: { entry, pairing_id: pairingId } });
  expect(add.status, show(add)).toBe(201);
  p.tip = entry;
  const ch = await as('POST', '/api/devices/challenge', { body: { key_id: phone.record.key_id } });
  const s = await as('POST', '/api/devices/session', { body: await phoneSigninBody(p.root, phone, await headOf(entry), ch.json) });
  expect(s.status, show(s)).toBe(200);
  const ua = createECDH('prime256v1');
  ua.generateKeys();
  const sub: PhoneSub = { phone, token: s.json.token, ua, auth: nodeRandom(16), path: `/push/${nodeRandom(8).toString('hex')}` };
  if (subscribe) {
    const put = await as('PUT', '/api/devices/me/push', { token: sub.token, body: subBody(sub) });
    expect(put.status, show(put)).toBe(200);
  }
  p.phones.push(sub);
  return sub;
}
const subBody = (s: PhoneSub, endpoint = `${pushOrigin}${s.path}`) => ({
  endpoint, expirationTime: null, keys: { p256dh: s.ua.getPublicKey().toString('base64url'), auth: s.auth.toString('base64url') },
});

/** A waiting request on the person's granted mandate, its content wrapped to `keyIds`. */
async function file(p: Person, keyIds: string[]): Promise<{ status: number; id: string; json: any }> {
  const wrap = () => ({ ct: nodeRandom(48).toString('base64url'), enc: nodeRandom(32).toString('base64url') });
  // The v0.8 content object (Proposals, rule 2): one wrap per reader DID, readers = that key set, plus the step 8
  // wraps per device. The AS never decrypts; random bytes stand in for the ciphertext and the wraps.
  const content = {
    ciphertext: nodeRandom(64).toString('base64url'), encrypted_keys: { [p.root.did]: wrap() },
    readers: [p.root.did], unreadable: [], hash: 'sha256:' + nodeRandom(32).toString('hex'),
    device_keys: Object.fromEntries(keyIds.map((k) => [k, wrap()])),
  };
  const r = await as('POST', '/api/proposals', {
    apiKey: p.apiKey,
    body: {
      authorization_id: p.authId, mandateId: p.mandate.mandate_id, boundsHash: p.mandate.bounds_hash,
      profile_id: PROFILE_ID, tool: 'create_payment_link', action: 'create_payment_link', actionType: 'charge',
      execution_context: { amount: 250 }, executionContext: { amount: 250 }, pending_domains: ['owner'],
      content, proposalContentHash: content.hash,
    },
  });
  return { status: r.status, id: r.json?.proposal?.id, json: r.json };
}

const received = (s: PhoneSub) => got.filter((g) => g.path === s.path).map((g) => JSON.parse(decrypt(g.body, s.ua.getPrivateKey(), s.auth)));
const subRows = async (keyId: string) => (await db.query('select 1 from push_subscriptions where key_id = $1', [keyId])).rowCount;

// ─── The suite ───────────────────────────────────────────────────────────────

describe.skipIf(!available)('notifications to phones (step 15, real Authority Server)', () => {
  let vapidPublic = '';

  beforeAll(async () => {
    push = createServer((rq, rs) => {
      const chunks: Buffer[] = [];
      rq.on('data', (c) => chunks.push(c));
      rq.on('end', () => {
        got.push({ path: rq.url ?? '', headers: rq.headers, body: Buffer.concat(chunks) });
        rs.statusCode = answer.get(rq.url ?? '') ?? 201;
        rs.end();
      });
    });
    await new Promise<void>((r) => push.listen(0, '127.0.0.1', () => r()));
    const a = push.address();
    pushOrigin = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}`;
    const vapid = createECDH('prime256v1');
    vapid.generateKeys();
    await pm.startSP(AS_PORT, {
      name: 'as-push',
      env: {
        ...clock.env,
        SUVEREN_DEVICE_KEYS: 'on', SUVEREN_APP_ORIGIN: APP_ORIGIN,
        SUVEREN_VAPID_PRIVATE_KEY: vapid.getPrivateKey().toString('base64url'), SUVEREN_VAPID_SUBJECT: 'https://as.e2e.test',
        SUVEREN_PUSH_EXTRA_ORIGINS: pushOrigin,
      },
    });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
    const k = await as('GET', '/api/push/key');
    expect(k.status, show(k)).toBe(200);
    vapidPublic = k.json.key;
    expect(vapidPublic).toBe(vapid.getPublicKey().toString('base64url'));
  }, 600_000);

  afterAll(async () => {
    await clock.set(0);
    await db?.end().catch(() => undefined);
    await pm.killAll();
    await new Promise<void>((r) => push?.close(() => r()) ?? r());
  }, 60_000);

  beforeEach(() => { got.length = 0; });

  it('1. a waiting request: one encrypted notification per phone that can read it, the id only, a valid VAPID header', async () => {
    const p = await person('Owner');
    const [a, b] = [await addPhone(p), await addPhone(p)];
    const r = await file(p, [p.dev.record.key_id, a.phone.record.key_id, b.phone.record.key_id]);
    expect(r.status, JSON.stringify(r.json)).toBe(201);
    expect(got).toHaveLength(2);
    expect(received(a)).toEqual([{ ids: [r.id] }]);
    expect(received(b)).toEqual([{ ids: [r.id] }]);
    const pub = Buffer.from(vapidPublic, 'base64url');
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: pub.subarray(1, 33).toString('base64url'), y: pub.subarray(33).toString('base64url') }, format: 'jwk' });
    for (const g of got) {
      expect(g.body.includes(Buffer.from(r.id))).toBe(false);
      expect(g.headers['content-encoding']).toBe('aes128gcm');
      expect(Number(g.headers.ttl)).toBeGreaterThan(0);
      const m = /^vapid t=([^.]+)\.([^.]+)\.([^,]+), k=(.+)$/.exec(String(g.headers.authorization));
      expect(m, String(g.headers.authorization)).not.toBeNull();
      expect(m![4]).toBe(vapidPublic);
      const claims = JSON.parse(Buffer.from(m![2], 'base64url').toString());
      expect(claims.aud).toBe(pushOrigin);
      expect(claims.sub).toBe('https://as.e2e.test');
      expect(claims.exp).toBeGreaterThan(now());
      expect(verify('sha256', Buffer.from(`${m![1]}.${m![2]}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(m![3], 'base64url'))).toBe(true);
    }
  });

  it('2. a request this phone holds no wrap of sends it nothing', async () => {
    const p = await person('NoWrap');
    await addPhone(p);
    const r = await file(p, [p.dev.record.key_id]);
    expect(r.status, JSON.stringify(r.json)).toBe(201);
    expect(got).toHaveLength(0);
  });

  it('3. after three in ten minutes the next are held; ten minutes later one notification names them all', async () => {
    const p = await person('Burst');
    const s = await addPhone(p);
    const k = [s.phone.record.key_id];
    const first: string[] = [];
    const filed = async () => { const r = await file(p, k); expect(r.status, JSON.stringify(r.json)).toBe(201); return r.id; };
    for (let i = 0; i < 3; i++) first.push(await filed());
    const held = [await filed(), await filed()];
    expect(received(s)).toEqual(first.map((id) => ({ ids: [id] })));
    try {
      await clock.set(601);
      got.length = 0;
      const next = await filed();
      expect(received(s)).toEqual([{ ids: [...held].sort().concat(next) }]);
    } finally {
      await clock.set(0);
    }
  });

  it('4a. a removed phone\'s subscription is deleted with it', async () => {
    const p = await person('Remove');
    const [a, b] = [await addPhone(p), await addPhone(p)];
    expect(await subRows(a.phone.record.key_id)).toBe(1);
    const entry = await removeEntry(p.root, p.tip, p.dev, a.phone.record.key_id);
    const r = await as('POST', '/api/devices/chain', { token: p.token, body: { entry } });
    expect(r.status, show(r)).toBe(201);
    p.tip = entry;
    expect(await subRows(a.phone.record.key_id)).toBe(0);
    expect(await subRows(b.phone.record.key_id)).toBe(1);
  });

  it('4b. a push service answering 410 deletes the subscription; the request is stored anyway', async () => {
    const p = await person('Gone');
    const s = await addPhone(p);
    answer.set(s.path, 410);
    const r = await file(p, [s.phone.record.key_id]);
    expect(r.status).toBe(201);
    expect(got).toHaveLength(1);
    expect(await subRows(s.phone.record.key_id)).toBe(0);
  });

  it('5. only a phone session may subscribe; an endpoint that is not a push service is refused', async () => {
    const p = await person('Kinds');
    const s = await addPhone(p, false);
    const asComputer = await as('PUT', '/api/devices/me/push', { token: p.token, body: subBody(s) });
    expect(asComputer.status).toBe(403);
    expect(code(asComputer)).toBe('DEVICE_KIND_NOT_ALLOWED');
    expect((await as('PUT', '/api/devices/me/push', { body: subBody(s) })).status).toBe(401);
    for (const endpoint of ['https://evil.example/push', 'http://127.0.0.1:1/x', `${pushOrigin.replace('127.0.0.1', 'localhost')}/x`]) {
      const r = await as('PUT', '/api/devices/me/push', { token: s.token, body: subBody(s, endpoint) });
      expect(r.status, endpoint).toBe(400);
      expect(code(r)).toBe('PUSH_ENDPOINT_NOT_ALLOWED');
    }
    expect(await subRows(s.phone.record.key_id)).toBe(0);
    const del = await as('DELETE', '/api/devices/me/push', { token: s.token });
    expect(del.status).toBe(200);
  });
});

describe.skipIf(!available)('notifications with the switch off', () => {
  beforeAll(async () => {
    const vapid = createECDH('prime256v1');
    vapid.generateKeys();
    await pm.startSP(AS_OFF_PORT, { name: 'as-push-off', env: { SUVEREN_DEVICE_KEYS: '', SUVEREN_VAPID_PRIVATE_KEY: vapid.getPrivateKey().toString('base64url') } });
  }, 600_000);
  afterAll(async () => { await pm.killAll(); }, 60_000);

  it('6. every new route answers 404', async () => {
    const off = (m: string, path: string) => http(`http://localhost:${AS_OFF_PORT}`, m, path, { token: 'x', body: m === 'GET' || m === 'DELETE' ? undefined : {} });
    expect((await off('GET', '/api/push/key')).status).toBe(404);
    expect((await off('PUT', '/api/devices/me/push')).status).toBe(404);
    expect((await off('DELETE', '/api/devices/me/push')).status).toBe(404);
    expect((await off('POST', '/api/push/flush')).status).toBe(404);
  });
});
