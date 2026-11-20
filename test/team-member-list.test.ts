/**
 * Teams: who is a colleague (DEC-73, design 20.21; Authority Server side), against the REAL Authority Server over HTTP.
 *
 * Every list, anchor and leave is built and signed here, independently of the Authority Server's code, with real
 * device chains, real device keys and real platform checks. The Authority Server verifies and carries them; the
 * "colleague" side is hap-core's `verifyTeamTrust` / `checkTeamPin`, fed only with what the Authority Server served.
 *
 * Needs: SUVEREN_DB_URL (a Postgres, as every Authority Server suite) and an Authority Server checkout that has the
 * team-trust routes (suveren-as PR #146); otherwise the suite skips. The flag SUVEREN_DEVICE_KEYS is switched on for
 * the server under test; a second server WITHOUT it must answer 404 on every new route.
 *
 * One seam is not HTTP: a device chain may only be created with a one-time code that a dashboard session opened from
 * an email link may fetch (POST /api/enrolment-codes). Nothing in a test can click an email, so that session row is
 * inserted into the throwaway database, exactly as the Authority Server's own sign-up link would.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import {
  b64uEncode, buildAnchor, buildLeave, buildMemberList, buildTeamMember, checkTeamPin, memberListHash, objectHash,
  randomBytes, signObject, verifyChain, verifyTeamTrust,
  type ChainEntry, type MemberList,
} from '@humanagencyp/hap-core/device-keys';

import { AS_DIR } from '../src/helpers/as-dir.js';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { checkOver, genesisEntry, headOf, newDevice, newRoot, signinBody, type Device, type Root } from '../src/helpers/device-chain.js';

const AS_PORT = 19930;
const AS_OFF_PORT = 19931;
const AS_URL = `http://localhost:${AS_PORT}`;
const AS_OFF_URL = `http://localhost:${AS_OFF_PORT}`;

const available = !!process.env.SUVEREN_DB_URL
  && existsSync(join(AS_DIR, 'src', 'app', 'api', 'teams', '[id]', 'trust', 'route.ts'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
let db: pg.Client;

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
const as = (method: string, path: string, o?: Parameters<typeof http>[3]) => http(AS_URL, method, path, o);
const show = (r: Res) => JSON.stringify(r.json);
const code = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.code;
const nonce = () => b64uEncode(randomBytes(16));
const now = () => Math.floor(Date.now() / 1000);
const fakeIp = () => `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

// ─── People ──────────────────────────────────────────────────────────────────

interface Person {
  name: string; userId: string; apiKey: string;
  root?: Root; dev?: Device; chain?: ChainEntry[]; token?: string;
}

async function register(name: string): Promise<Person> {
  const r = await sp.register(name, `${name.toLowerCase().replace(/\W+/g, '-')}-${randomUUID().slice(0, 8)}@test.local`);
  return { name, userId: r.user.id, apiKey: r.apiKey };
}

/** Give the person a device chain (genesis with an enrolment code) and a device session. */
async function enrol(p: Person): Promise<Person> {
  const cookieToken = randomUUID();
  await db.query(
    `insert into sessions (token, user_id, kind, created_at, expires_at) values ($1, $2, 'email-link', $3, $4)`,
    [cookieToken, p.userId, now(), now() + 3600],
  );
  const codeRes = await as('POST', '/api/enrolment-codes', { cookie: `hap-session=${cookieToken}` });
  expect(codeRes.status, show(codeRes)).toBe(201);
  p.root = await newRoot();
  p.dev = await newDevice();
  const g = await genesisEntry(p.root, p.dev);
  const chainRes = await as('POST', '/api/devices/chain', { body: { entry: g, enrolment_code: codeRes.json.code } });
  expect(chainRes.status, show(chainRes)).toBe(201);
  p.chain = [g];
  const ch = await as('POST', '/api/devices/challenge', { body: { key_id: p.dev.record.key_id }, ip: fakeIp() });
  expect(ch.status, show(ch)).toBe(200);
  const sess = await as('POST', '/api/devices/session', { body: await signinBody(p.root, p.dev, await headOf(g), ch.json) });
  expect(sess.status, show(sess)).toBe(200);
  p.token = sess.json.token;
  return p;
}
async function chained(name: string): Promise<Person> { return enrol(await register(name)); }

const head = (p: Person) => headOf(p.chain![p.chain!.length - 1]);
const stateOf = (p: Person) => verifyChain({ expectedRootDid: p.root!.did, entries: p.chain! });

// ─── Signed objects ──────────────────────────────────────────────────────────

interface Team { id: string; invite: string; admin: Person }

async function listOf(t: Team, o: { version: number; prev: MemberList | null; members: Person[]; signer?: Person; admin?: Person; handover?: Person }) {
  const admin = o.admin ?? t.admin;
  const signer = o.signer ?? admin;
  const h = await head(signer);
  const members = await Promise.all(o.members.map((m) => buildTeamMember(m.root!.did, `Name of ${m.name}`)));
  members.sort((a, b) => (a.did < b.did ? -1 : 1));
  const old = o.handover;
  const oh = old ? await head(old) : null;
  const list = buildMemberList({
    team_id: t.id, version: o.version, prev: o.prev ? await memberListHash(o.prev) : null, admin_did: admin.root!.did, members,
    handover: old ? { admin_did: old.root!.did, key_id: old.dev!.record.key_id, chain_seq: oh!.seq, chain_head: oh!.hash } : null,
    key_id: signer.dev!.record.key_id, chain_seq: h.seq, chain_head: h.hash, created_at: now(), nonce: nonce(),
  });
  const hash = await objectHash(list);
  const sigs: unknown[] = [{ key_id: signer.dev!.record.key_id, sig: await signObject(list, signer.dev!.seed), check: await checkOver(signer.dev!.checkPriv, hash) }];
  if (old) sigs.push({ key_id: old.dev!.record.key_id, sig: await signObject(list, old.dev!.seed), check: await checkOver(old.dev!.checkPriv, hash) });
  return { list, sigs };
}

async function anchorOf(m: Person, t: Team, o: { version?: number; prev?: string | null } = {}) {
  const h = await head(m);
  const anchor = buildAnchor({
    member_did: m.root!.did, team_id: t.id, admin_did: t.admin.root!.did, version: o.version ?? 1, prev: o.prev ?? null,
    key_id: m.dev!.record.key_id, chain_seq: h.seq, chain_head: h.hash, created_at: now(), nonce: nonce(),
  });
  return { anchor, sig: await signObject(anchor, m.dev!.seed), check: await checkOver(m.dev!.checkPriv, await objectHash(anchor)) };
}

async function leaveOf(m: Person, t: Team, listVersion: number) {
  const h = await head(m);
  const leave = buildLeave({ member_did: m.root!.did, team_id: t.id, list_version: listVersion, key_id: m.dev!.record.key_id, chain_seq: h.seq, chain_head: h.hash, created_at: now(), nonce: nonce() });
  return { leave, sig: await signObject(leave, m.dev!.seed) };
}

// ─── Team steps ──────────────────────────────────────────────────────────────

async function teamOf(admin: Person): Promise<Team> {
  const r = await as('POST', '/api/groups', { apiKey: admin.apiKey, body: { name: `Team ${randomUUID().slice(0, 6)}` } });
  expect(r.status, show(r)).toBeLessThan(300);
  return { id: r.json.group.id, invite: r.json.inviteCode ?? r.json.group.inviteCode, admin };
}

/** A team whose admin (alone) is stored as version 1. */
async function teamWithV1(name = 'Admin'): Promise<{ t: Team; v1: MemberList }> {
  const t = await teamOf(await chained(name));
  const v1 = await listOf(t, { version: 1, prev: null, members: [t.admin] });
  const res = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: v1 });
  expect(res.status, show(res)).toBe(201);
  return { t, v1: v1.list };
}

async function requestJoin(t: Team, m: Person): Promise<void> {
  const jr = await as('POST', '/api/groups/join', { token: m.token, body: { inviteCode: t.invite } });
  expect(jr.status, show(jr)).toBe(202);
}

/** The member requests, anchors, and the admin adds them in the next version. Returns the new list. */
async function admit(t: Team, prev: MemberList, existing: Person[], m: Person): Promise<MemberList> {
  await requestJoin(t, m);
  const ar = await as('POST', `/api/teams/${t.id}/anchor`, { token: m.token, body: await anchorOf(m, t) });
  expect(ar.status, show(ar)).toBe(201);
  const next = await listOf(t, { version: prev.version + 1, prev, members: [t.admin, ...existing, m] });
  const res = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: { ...next, request_user_id: m.userId } });
  expect(res.status, show(res)).toBe(201);
  return next.list;
}

const trustOf = (t: Team, p: Person, query = '') => as('GET', `/api/teams/${t.id}/trust${query}`, { token: p.token });

/** What a colleague does: read from the Authority Server, verify everything with hap-core, no trust in the server. */
async function verifyAs(t: Team, reader: Person, adminChains: Record<string, Awaited<ReturnType<typeof stateOf>>>, extra: { pin?: { version: number; hash: string }; leavers?: Person[] } = {}) {
  const tr = await trustOf(t, reader);
  expect(tr.status, show(tr)).toBe(200);
  const own = await as('GET', `/api/teams/${t.id}/anchor`, { token: reader.token });
  expect(own.status, show(own)).toBe(200);
  const leaves = await Promise.all((tr.json.leaves as Array<{ leave: unknown; sig: unknown; member_did: string }>).map(async (l) => {
    const who = (extra.leavers ?? []).find((p) => p.root!.did === l.member_did)!;
    return { env: { leave: l.leave, sig: l.sig }, chain: await stateOf(who) };
  }));
  return verifyTeamTrust({
    team_id: t.id, anchor: own.json.anchor, anchorChain: await stateOf(reader),
    versions: tr.json.lists.map((l: { list: unknown; sigs: unknown }) => ({ list: l.list, sigs: l.sigs })),
    adminChains, pin: extra.pin ?? null, leaves,
  });
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe.skipIf(!available)('team trust: who is a colleague (real Authority Server, device keys on)', () => {
  beforeAll(async () => {
    await pm.startSP(AS_PORT, { name: 'as-team', env: { SUVEREN_DEVICE_KEYS: 'on' } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();
  }, 180_000);
  afterAll(async () => {
    await db?.end().catch(() => undefined);
    await pm.killAll();
  });

  it('admin creates version 1 alone; a requester joins, anchors, is added in version 2; a member reads and hap-core verifies', async () => {
    const { t, v1 } = await teamWithV1();
    const m = await chained('Maria');

    // version 1 is the admin and nobody else
    const first = await trustOf(t, t.admin);
    expect(first.json.head.version).toBe(1);
    expect(first.json.lists).toHaveLength(1);
    expect(first.json.lists[0].list.members.map((x: { did: string }) => x.did)).toEqual([t.admin.root!.did]);

    await requestJoin(t, m);
    // the admin cannot add her before she anchored
    const early = await listOf(t, { version: 2, prev: v1, members: [t.admin, m] });
    const no = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: { ...early, request_user_id: m.userId } });
    expect(no.status, show(no)).toBe(409);
    expect(code(no)).toBe('ANCHOR_REQUIRED');

    const anchor = await anchorOf(m, t);
    expect((await as('POST', `/api/teams/${t.id}/anchor`, { token: m.token, body: anchor })).status).toBe(201);
    const seen = await as('GET', `/api/teams/${t.id}/anchors/${m.userId}`, { token: t.admin.token });
    expect(seen.json.member_did).toBe(m.root!.did);

    const added = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: { ...early, request_user_id: m.userId } });
    expect(added.status, show(added)).toBe(201);
    expect(added.json.added).toEqual([m.root!.did]);

    const trust = await verifyAs(t, m, { [t.admin.root!.did]: await stateOf(t.admin) });
    expect(trust.version).toBe(2);
    expect(trust.members.map((x) => x.did).sort()).toEqual([t.admin.root!.did, m.root!.did].sort());
    expect(trust.rejected).toBeNull();
  });

  it('checkTeamPin flags ROLLBACK when the Authority Server serves an older head than the verifier pinned', async () => {
    const { t, v1 } = await teamWithV1();
    const m = await chained('Pinner');
    const v2 = await admit(t, v1, [], m);
    const adminChains = { [t.admin.root!.did]: await stateOf(t.admin) };
    const trust = await verifyAs(t, m, adminChains);
    const pin = trust.pin;
    expect(pin).toEqual({ version: 2, hash: await memberListHash(v2) });

    // the same version again is fine
    expect(() => checkTeamPin(2, pin.hash, pin)).not.toThrow();
    // a server that answers from version 1 on (a rollback to an older head) is caught by the pin
    const older = await trustOf(t, m, '?from=1');
    const first = older.json.lists[0];
    expect(first.version).toBe(1);
    let err: { code?: string } | undefined;
    try { checkTeamPin(first.version, first.hash, pin); } catch (e) { err = e as { code?: string }; }
    expect(err?.code).toBe('ROLLBACK');
    // and a fork (same version, other hash) is caught as well
    let fork: { code?: string } | undefined;
    try { checkTeamPin(2, first.hash, pin); } catch (e) { fork = e as { code?: string }; }
    expect(fork?.code).toBe('FORK');
    // the real server never moves the head back: a stale write is refused and the head stays 2
    const stale = await listOf(t, { version: 2, prev: v1, members: [t.admin] });
    const refused = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: stale });
    expect(refused.status).toBe(409);
    expect(code(refused)).toBe('LIST_HEAD_MOVED');
    expect((await trustOf(t, m)).json.head.version).toBe(2);
  });

  it('leave: the next read shows the leave and verifyTeamTrust drops the member; the leaver then sees no history', async () => {
    const { t, v1 } = await teamWithV1();
    const stays = await chained('Stays');
    const leaver = await chained('Leaver');
    const v2 = await admit(t, v1, [], stays);
    const v3 = await admit(t, v2, [stays], leaver);
    const adminChains = { [t.admin.root!.did]: await stateOf(t.admin) };
    const before = await verifyAs(t, stays, adminChains, { leavers: [leaver] });
    expect(before.members.map((x) => x.did)).toContain(leaver.root!.did);

    const res = await as('POST', `/api/teams/${t.id}/leave`, { token: leaver.token, body: await leaveOf(leaver, t, v3.version) });
    expect(res.status, show(res)).toBe(201);

    const after = await verifyAs(t, stays, adminChains, { leavers: [leaver], pin: before.pin });
    expect(after.left).toEqual([leaver.root!.did]);
    expect(after.members.map((x) => x.did)).not.toContain(leaver.root!.did);
    expect(after.members.map((x) => x.did).sort()).toEqual([t.admin.root!.did, stays.root!.did].sort());
    expect(after.skipped_leaves).toEqual([]);

    // the person who left is a requester again: admin and head only
    const view = await trustOf(t, leaver);
    expect(Object.keys(view.json).sort()).toEqual(['admin_did', 'head', 'team_id']);
  });

  it('a re-add on the old anchor is refused (ANCHOR_REQUIRED); a new anchor works', async () => {
    const { t, v1 } = await teamWithV1();
    const m = await chained('Again');
    const v2 = await admit(t, v1, [], m);
    const first = await as('GET', `/api/teams/${t.id}/anchor`, { token: m.token });
    expect((await as('POST', `/api/teams/${t.id}/leave`, { token: m.token, body: await leaveOf(m, t, 2) })).status).toBe(201);
    const v3 = await listOf(t, { version: 3, prev: v2, members: [t.admin] });
    expect((await as('POST', `/api/teams/${t.id}/members/remove`, { token: t.admin.token, body: v3 })).status).toBe(201);

    const v4 = await listOf(t, { version: 4, prev: v3.list, members: [t.admin, m] });
    const no = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: v4 });
    expect(no.status, show(no)).toBe(409);
    expect(code(no)).toBe('ANCHOR_REQUIRED');

    const second = await anchorOf(m, t, { version: 2, prev: first.json.anchor.hash });
    expect((await as('POST', `/api/teams/${t.id}/anchor`, { token: m.token, body: second })).status).toBe(201);
    const ok = await as('POST', `/api/teams/${t.id}/members`, { token: t.admin.token, body: v4 });
    expect(ok.status, show(ok)).toBe(201);
    expect((await trustOf(t, m)).json.head.version).toBe(4);
  });

  it('a requester sees the admin and the head, no history; a member sees the history', async () => {
    const { t, v1 } = await teamWithV1();
    const r = await chained('Requester');
    await requestJoin(t, r);
    const view = await trustOf(t, r);
    expect(view.status, show(view)).toBe(200);
    expect(Object.keys(view.json).sort()).toEqual(['admin_did', 'head', 'team_id']);
    expect(view.json.admin_did).toBe(t.admin.root!.did);
    expect(view.json.head.hash).toBe(await memberListHash(v1));
    const mem = await trustOf(t, t.admin);
    expect(mem.json.lists).toHaveLength(1);
    // a stranger reads nothing
    const stranger = await chained('Stranger');
    expect((await trustOf(t, stranger)).status).toBe(403);
  });

  it('an existing team moves onto the list by anchors: the anchored member is added, the unanchored one stays active', async () => {
    // A team as it exists today: no device chains yet, members confirmed the old way.
    const admin = await register('Adopter');
    const m1 = await register('Existing one');
    const m2 = await register('Existing two');
    const created = await as('POST', '/api/groups', { apiKey: admin.apiKey, body: { name: `Old team ${randomUUID().slice(0, 6)}` } });
    expect(created.status, show(created)).toBeLessThan(300);
    const teamId: string = created.json.group.id;
    const invite: string = created.json.inviteCode ?? created.json.group.inviteCode;
    for (const m of [m1, m2]) {
      const jr = await as('POST', '/api/groups/join', { apiKey: m.apiKey, body: { inviteCode: invite } });
      expect(jr.status, show(jr)).toBe(202);
      const ok = await as('POST', `/api/groups/${teamId}/requests/${m.userId}`, { apiKey: admin.apiKey, body: { action: 'confirm' } });
      expect(ok.status, show(ok)).toBe(200);
    }
    // everybody gets a device chain; the team then moves to the list
    await enrol(admin); await enrol(m1); await enrol(m2);
    const t: Team = { id: teamId, invite, admin };
    const status = async (m: Person) => (await db.query<{ status: string | null }>(
      'select status from group_members where group_id = $1 and user_id = $2', [teamId, m.userId])).rows[0]?.status ?? 'active';

    // m1 anchors (existing members may); m2 does not
    expect((await as('POST', `/api/teams/${teamId}/anchor`, { token: m1.token, body: await anchorOf(m1, t) })).status).toBe(201);

    const v1 = await listOf(t, { version: 1, prev: null, members: [admin] });
    const r1 = await as('POST', `/api/teams/${teamId}/members`, { token: admin.token, body: v1 });
    expect(r1.status, show(r1)).toBe(201);
    expect(await status(m1)).toBe('active');
    expect(await status(m2)).toBe('active');

    const v2 = await listOf(t, { version: 2, prev: v1.list, members: [admin, m1] });
    const r2 = await as('POST', `/api/teams/${teamId}/members`, { token: admin.token, body: v2 });
    expect(r2.status, show(r2)).toBe(201);
    expect(await status(m2)).toBe('active');
    const used = await db.query('select admitted_in_version from team_anchors where team_id = $1 and user_id = $2', [teamId, m1.userId]);
    expect(used.rows[0].admitted_in_version).toBe(2);

    // the unanchored one cannot be added to a list
    const early = await listOf(t, { version: 3, prev: v2.list, members: [admin, m1, m2] });
    const no = await as('POST', `/api/teams/${teamId}/members`, { token: admin.token, body: early });
    expect(code(no)).toBe('ANCHOR_REQUIRED');
    // after she anchors she is added in version 3
    expect((await as('POST', `/api/teams/${teamId}/anchor`, { token: m2.token, body: await anchorOf(m2, t) })).status).toBe(201);
    const r3 = await as('POST', `/api/teams/${teamId}/members`, { token: admin.token, body: early });
    expect(r3.status, show(r3)).toBe(201);
    const trust = await verifyAs(t, m1, { [admin.root!.did]: await stateOf(admin) });
    expect(trust.members.map((x) => x.did).sort()).toEqual([admin.root!.did, m1.root!.did, m2.root!.did].sort());
  });

  it('hands the team over with two signatures; one signature is refused', async () => {
    const { t, v1 } = await teamWithV1('Old admin');
    const b = await chained('New admin');
    const v2 = await admit(t, v1, [], b);
    const transfer = (body: Record<string, unknown>) => as('POST', `/api/groups/${t.id}/admin-transfer`, { token: t.admin.token, body: { newAdminUserId: b.userId, ...body } });

    const noList = await transfer({});
    expect(noList.status).toBe(409);
    expect(code(noList)).toBe('LIST_REQUIRED');

    const one = await listOf(t, { version: 3, prev: v2, members: [t.admin, b], admin: b });
    expect((await transfer(one)).status).toBeGreaterThanOrEqual(400);
    expect((await trustOf(t, b)).json.admin_did).toBe(t.admin.root!.did);

    const both = await listOf(t, { version: 3, prev: v2, members: [t.admin, b], admin: b, handover: t.admin });
    const ok = await transfer(both);
    expect(ok.status, show(ok)).toBe(200);
    const tr = await trustOf(t, b);
    expect(tr.json.admin_did).toBe(b.root!.did);
    expect(tr.json.head.version).toBe(3);
  });
});

describe.skipIf(!available)('team trust: flag off', () => {
  beforeAll(async () => {
    await pm.startSP(AS_OFF_PORT, { name: 'as-team-off', env: { SUVEREN_DEVICE_KEYS: '' } }); // explicitly off, also when the run itself has the switch on
  }, 180_000);
  afterAll(async () => { await pm.killAll(); });

  it('every new route answers 404', async () => {
    const id = 'x';
    for (const [method, path] of [
      ['GET', `/api/teams/${id}/trust`], ['GET', `/api/teams/${id}/anchor`], ['POST', `/api/teams/${id}/anchor`],
      ['POST', `/api/teams/${id}/members`], ['POST', `/api/teams/${id}/members/remove`], ['POST', `/api/teams/${id}/leave`],
      ['GET', `/api/teams/${id}/anchors/y`],
    ] as const) {
      const r = await http(AS_OFF_URL, method, path, { body: method === 'POST' ? {} : undefined });
      expect(r.status, `${method} ${path}`).toBe(404);
    }
  });
});
