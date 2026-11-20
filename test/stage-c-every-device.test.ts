/**
 * Device keys, stage C, step 8: "encrypt to every device; re-wrap; card context" (device-keys plan, section 9),
 * against the REAL Authority Server and REAL gateways. No connector is involved: the proposal is built by the
 * gateway's own control plane (POST /internal/encrypt-content, the call its MCP server makes under a 0.8 mandate)
 * and filed at the Authority Server exactly as the MCP server would; it is opened by the gateways' own
 * /internal/decrypt-content and by hap-core on the approver's side.
 *
 * People
 *   P  the Mandate Owner. Two real gateways of P (A and B) and, later, a third (C). A sets up device keys by the
 *      gateway's own set-up (password, recovery code, genesis, device sign-in). B and C are real gateways signed in
 *      to P's account; they enter P's chain by an `add` entry (see "Seams" below).
 *   Q  a team approver with a device chain made here (a real X25519 reading key, so it can open what is wrapped).
 *   L  a team member WITHOUT a chain. Since DEC-52 a mandate does not mix accounts with and without a chain, so L is
 *      never an approver of P's mandate; case 2 checks that the Authority Server refuses such a mandate.
 *
 * Cases (the done-when of step 8, then the security review)
 *   1. A proposal opens on both gateways and for the approver; the proposal row holds no readable content.
 *   2. A mandate naming an approver without a chain is refused (MIXED_CHAIN_ACCOUNTS, plan 9.2). This replaces the
 *      former "a reader without a chain opens it through the legacy wrap": DEC-52 voided that requirement.
 *   3. A card context moved to another proposal fails to open (the arguments stay shown).
 *   4. A wrap for another person's device is refused (WRAP_NOT_YOURS) and nothing is stored.
 *   5. A forged chain for an approver in the AS database: the gateway lists the approver as unreadable, gives them no
 *      wrap, and raises the alarm (the page's doorbell event).
 *   6. Downgrade: the AS answers 404 for the chain of an approver this gateway verified before: alarm, no wrap, and
 *      no legacy wrap either.
 *   7. A gateway added to P's chain later opens an OPEN proposal after the re-wrap; wraps already stored are
 *      never replaced.
 *
 * Seams that are not HTTP (each is a database write into the throwaway database; the gateway verifies everything
 * itself, it never trusts what the AS database says):
 *   - A chain may be created only with an enrolment code, which a dashboard session opened from an email link may
 *     fetch. Nothing in a test can click an email, so that session row is inserted (same as test/team-member-list).
 *   - Adding a device to a chain whose devices hold no check key needs the recovery code's root key, and the AS refuses
 *     a root-signed entry on /api/devices/chain (the recovery hand-off owns those). A gateway cannot yet add itself to
 *     an existing chain (the "add this computer" flow is step 11), so the root-signed `add` entry for B and for C, built
 *     here from the recovery code that A's set-up showed once, is inserted into device_chain_entries and devices.
 *     The device record carries the REAL reading public key of that gateway (read back from the AS after its sign-in);
 *     the signing key is the test's. B and C therefore have no chain store of their own: they open a proposal from
 *     the single wrap an AS serves a device session ("a device session reads back its own wrap only"), which is how
 *     the gateway's decrypt picks a wrap when it has no key id.
 *   - The wraps a gateway's own device session would be served are taken from the proposal row (`content_device_keys`,
 *     the entry of that key id), because the test holds no bearer token of A, B or C. Q's view is the real one: Q's
 *     own device session reads the proposal from the AS.
 *   - Cases 5 and 6 forge and withhold a chain in the database (a changed entry; users.root_did cleared), restored after.
 *   - P's mandate is granted (plan 4.4) by device B, which the test holds (its signing key and check key are the test's,
 *     see above): B signs in to the AS as a device and stores the grant; the mandate request then names it.
 *
 * Not covered here: the approval page in a browser; the MCP server's own call into the control plane (needs a
 * connector); a grant made by a gateway's own check key (CI computers have no Touch ID; the grant is signed here).
 *
 * Needs: SUVEREN_DB_URL (Postgres admin URL), sibling checkouts ../suveren-as (with migration 029 and
 * POST /api/proposals/:id/wraps), ../suveren-gateway (stage C: lib/{device-readers,content-wraps,proposal-rewrap}.ts),
 * ../hap-profiles. Otherwise the suite skips.
 * Run: npx vitest run test/stage-c-every-device.test.ts
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { decryptProposalContent } from '@humanagencyp/hap-core';
import { deriveRootKey, entryHash, parseRecoveryCode, type ChainEntry } from '@humanagencyp/hap-core/device-keys';

import { AS_DIR } from '../src/helpers/as-dir.js';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient, mintAuthorizationId } from '../src/helpers/sp-client.js';
import { hashGateContent, computeBoundsHash, computeScopeHash, computeExecutionContextHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor, loadProfile } from '../src/helpers/profiles.js';
import {
  ControlPlaneClient, GW_DIR, PROFILES_DIR, newSecret, startControlPlane, startMcpServer, type StackOptions,
} from '../src/helpers/gateway-stack.js';
import {
  addEntryByRoot, genesisEntry, headOf, newDevice, newReadKey, newRoot, signinBody, withReadPub, type Device, type Root,
} from '../src/helpers/device-chain.js';
import { grantMembersOf, newMandateId, signedGrant } from '../src/helpers/mandate-grant.js';
import type { MandatePayload } from '@humanagencyp/hap-core';

const AS_PORT = 19950;
const AS_URL = `http://localhost:${AS_PORT}`;
const PORTS = {
  A: { cp: 19951, mcp: 19952 }, B: { cp: 19953, mcp: 19954 }, C: { cp: 19955, mcp: 19956 },
};

const available = !!process.env.SUVEREN_DB_URL
  && existsSync(join(AS_DIR, 'src', 'app', 'api', 'proposals', '[id]', 'wraps', 'route.ts'))
  && existsSync(join(GW_DIR, 'apps', 'control-plane', 'src', 'lib', 'proposal-rewrap.ts'));

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const dirs: string[] = [];
let db: pg.Client;

const MARK = `STAGEC-${Date.now()}`;
const PASSWORD = 'correct horse battery staple';

// ─── HTTP ────────────────────────────────────────────────────────────────────

interface Res { status: number; json: any }
async function http(base: string, method: string, path: string, o: { token?: string; apiKey?: string; cookie?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<Res> {
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(o.headers ?? {}) };
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
const code = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.error?.code ?? r.json?.code;
const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until<T>(fn: () => Promise<T | undefined>, what: string, ms = 30_000): Promise<T> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v !== undefined) return v;
    await sleep(500);
  }
  throw new Error(`timed out: ${what}`);
}

// ─── Gateways ────────────────────────────────────────────────────────────────

interface Gw {
  name: string;
  cp: number;
  url: string;
  secret: string;
  /** The page session after the unlock password was set: cookie + header token. */
  session?: { cookie: string; token: string };
}

/** A whole gateway (control plane + MCP server), its own data directory. `deviceKeys: false` is the unchanged mechanism. */
async function startGw(name: string, ports: { cp: number; mcp: number }, deviceKeys: boolean): Promise<Gw> {
  const dataDir = mkdtempSync(join(tmpdir(), `hap-e2e-stagec-${name}-`));
  dirs.push(dataDir);
  const stack: StackOptions = {
    dataDir, ports, secret: newSecret(), asUrl: AS_URL,
    // Explicitly off for the stand-in of a released gateway, also when the run itself has the switch on.
    extraEnv: { SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_DEVICE_KEYS: deviceKeys ? 'on' : '' },
  };
  await startControlPlane(pm, stack, `${name}-cp`);
  await startMcpServer(pm, stack, `${name}-mcp`);
  return { name, cp: ports.cp, url: `http://localhost:${ports.cp}`, secret: stack.secret };
}

function pageHeaders(gw: Gw): Record<string, string> {
  expect(gw.session, `${gw.name} has no page session`).toBeTruthy();
  return { origin: gw.url, cookie: `suveren_page_session=${gw.session!.cookie}`, 'x-suveren-session': gw.session!.token };
}

/** The gateway's internal routes (what its MCP server calls). */
const internal = (gw: Gw, path: string, body: unknown) =>
  http(gw.url, 'POST', `/internal${path}`, { body, headers: { 'x-internal-secret': gw.secret } });

/** A gateway of P with device keys: sign in with the account key, set the unlock password, open the page session. */
async function loginAndLock(gw: Gw, apiKey: string): Promise<void> {
  expect((await new ControlPlaneClient(gw.url).login(apiKey)).status).toBe(200);
  const res = await fetch(`${gw.url}/auth/password/set`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: gw.url, 'x-api-key': apiKey },
    body: JSON.stringify({ password: PASSWORD }),
  });
  const body = (await res.json()) as { sessionToken?: string; rekeyPending?: boolean };
  expect(res.status, JSON.stringify(body)).toBe(200);
  const cookie = /suveren_page_session=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1];
  expect(cookie, 'no page-session cookie').toBeTruthy();
  gw.session = { cookie: cookie!, token: body.sessionToken! };
}

/** The doorbell stream (GET /events): payloads are stripped there, the event TYPE is the alarm. */
async function watchEvents(gw: Gw): Promise<{ text: () => string; stop: () => void }> {
  const ac = new AbortController();
  const res = await fetch(`${gw.url}/events`, { headers: pageHeaders(gw), signal: ac.signal });
  expect(res.status).toBe(200);
  let buf = '';
  void (async () => {
    try {
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value);
      }
    } catch { /* aborted */ }
  })();
  return { text: () => buf, stop: () => ac.abort() };
}

// ─── People ──────────────────────────────────────────────────────────────────

interface Person { name: string; id: string; did: string; apiKey: string }

async function register(name: string): Promise<Person> {
  const r = await sp.register(name, `${name.toLowerCase().replace(/\W+/g, '-')}-${randomUUID().slice(0, 8)}@test.local`);
  return { name, id: r.user.id, did: r.user.did, apiKey: r.apiKey };
}

/** One-time enrolment code for a person's genesis: needs a dashboard session opened from an email link (a database row, see the header). */
async function enrolmentCodeFor(p: Person): Promise<string> {
  const cookieToken = randomUUID();
  await db.query(`insert into sessions (token, user_id, kind, created_at, expires_at) values ($1, $2, 'email-link', $3, $4)`, [cookieToken, p.id, now(), now() + 3600]);
  const r = await as('POST', '/api/enrolment-codes', { cookie: `hap-session=${cookieToken}` });
  expect(r.status, show(r)).toBe(201);
  return r.json.code;
}

interface Chained extends Person {
  root: Root; dev: Device; chain: ChainEntry[]; token: string; readPriv: Uint8Array;
}

/** A person with a chain made here: one device with a REAL reading key, a genesis, a device session. */
async function chained(name: string): Promise<Chained> {
  const p = await register(name);
  const root = await newRoot();
  const read = newReadKey();
  const dev = withReadPub(await newDevice(), read.pub);
  const g = await genesisEntry(root, dev);
  const r = await as('POST', '/api/devices/chain', { body: { entry: g, enrolment_code: await enrolmentCodeFor(p) } });
  expect(r.status, show(r)).toBe(201);
  const ch = await as('POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id }, headers: { 'x-forwarded-for': `10.${Math.floor(Math.random() * 250)}.1.1` } });
  expect(ch.status, show(ch)).toBe(200);
  const sess = await as('POST', '/api/devices/session', { body: await signinBody(root, dev, await headOf(g), ch.json) });
  expect(sess.status, show(sess)).toBe(200);
  return { ...p, did: root.did, root, dev, chain: [g], token: sess.json.token, readPriv: read.priv };
}

/** The reading public key (raw 32 bytes) the AS holds for an account: what a gateway registered when it signed in. */
async function registeredReadPub(apiKey: string, different: string | null): Promise<{ b64: string; raw: Uint8Array }> {
  return until(async () => {
    const r = await as('GET', '/api/users/me/pubkey', { apiKey });
    if (r.status !== 200 || r.json.pubkey === different) return undefined;
    const raw = new Uint8Array(Buffer.from(r.json.pubkey, 'base64'));
    return raw.length === 32 ? { b64: r.json.pubkey as string, raw } : undefined;
  }, 'the gateway registered its reading key', 30_000);
}

// ─── P's chain, as the AS database holds it ──────────────────────────────────

async function chainEntriesOf(userId: string): Promise<ChainEntry[]> {
  const r = await db.query('select entry from device_chain_entries where user_id = $1 order by seq', [userId]);
  return r.rows.map((x) => x.entry as ChainEntry);
}

/** Store a root-signed `add` (seam, see the header): the entry and the device row the AS derives from it. */
async function storeAdd(userId: string, entry: ChainEntry): Promise<void> {
  const d = entry.device!;
  await db.query(
    `insert into device_chain_entries (user_id, seq, entry_hash, entry, stored_at) values ($1, $2, $3, $4::jsonb, $5)`,
    [userId, entry.seq, await entryHash(entry), JSON.stringify(entry), now()],
  );
  await db.query(
    `insert into devices (key_id, user_id, sign_pub, read_pub, kind, label, "check", added_seq, removed_seq) values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, null)`,
    [d.key_id, userId, d.sign_pub, d.read_pub, d.kind, d.label, d.check ? JSON.stringify(d.check) : null, entry.seq],
  );
}

// ─── Proposals ───────────────────────────────────────────────────────────────

interface Wrap { ct: string; enc: string }
interface Filed { id: string; args: Record<string, unknown>; sealed: any }

const proposalRow = async (id: string) => {
  const r = await db.query('select * from proposals where id = $1', [id]);
  expect(r.rows.length, `proposal ${id} not in the AS database`).toBe(1);
  return r.rows[0] as Record<string, any>;
};

const contextFor = (tag: string) => ({
  display: { title: `Charge ${tag}` }, execution_mapping: {}, linked_record: { title: `LINKED-${MARK}-${tag}` }, gateway_version: 'e2e-stage-c',
});

/** The wire a gateway opens: what the AS serves an API-key caller, plus the device wrap and context a device session of that gateway is served. */
async function wireFor(id: string, keyId: string | null, reader: Person) {
  const view = await as('GET', `/api/proposals/${id}`, { apiKey: reader.apiKey });
  expect(view.status, show(view)).toBe(200);
  const c = view.json.proposal.content;
  const row = await proposalRow(id);
  const own = keyId ? (row.content_device_keys as Record<string, Wrap> | null)?.[keyId] : undefined;
  return {
    ciphertext: c.ciphertext, keys: c.keys, encrypted_keys: c.encrypted_keys, hash: c.hash,
    device_keys: own ? { [keyId!]: own } : {},
    ...(row.content_context ? { context: row.content_context as string } : {}),
  };
}

// ─── Suite ───────────────────────────────────────────────────────────────────

describe.skipIf(!available)('step 8: encrypt to every device, re-wrap, card context (real Authority Server + real gateways)', () => {
  let P: Person & { rootDid?: string };
  let Q: Chained;
  let L: Person;
  let A: Gw, B: Gw, C: Gw;
  let rootOfP: Root;
  let devA = '';
  let devB: Device, devC: Device;
  let teamId = '';
  let authorizationId = '';
  let mandate: Record<string, any>;
  let p1: Filed, p2: Filed;

  const CHARGE = PROFILE_V07.charge;
  let tokenB = '';
  /** The mandate request without its identity (authorization, mandate id and version, expiry), set in beforeAll. */
  let request: Record<string, any>;

  /**
   * Grant P's mandate on device B (plan 4.4), then ask the AS for it. The grant's members are the mandate as the AS
   * will sign it: the request's fields, the expiry, and the above-cap fields the request names. `grantFirst: false`
   * only names a mandate id and version, with no grant stored.
   */
  async function grantAndRequest(o: { chainDids: string[]; approvers?: string[]; grantFirst?: boolean }) {
    const mandateId = newMandateId();
    const authorization = mintAuthorizationId();
    const expiresAt = now() + 86_400;
    const approvers = [...(o.approvers ?? request.above_cap_approvers)].sort();
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: request.profile_id, profile_hash: request.profile_hash,
      bounds_hash: request.bounds_hash, scope_hash: request.scope_hash, execution_context_hash: request.execution_context_hash,
      issuer: 'did:key:z', mandate_owners: [{ did: P.rootDid }], gate_content_hashes: request.gate_content_hashes,
      commitment_mode: request.commitment_mode,
      above_cap_caps: request.above_cap_caps, above_cap_approvers: approvers, above_cap_approvals: request.above_cap_approvals,
      issued_at: now(), expires_at: expiresAt,
    } as unknown as MandatePayload;
    let grant: Res | null = null;
    if (o.grantFirst !== false) {
      const [, addB] = await chainEntriesOf(P.id);
      const body = await signedGrant({
        dev: devB, ownerDid: P.rootDid!, head: await headOf(addB), mandateId, version: 1,
        members: grantMembersOf(payload, { authorizationId: authorization, groupId: teamId, replaces: null, chainDids: o.chainDids }),
      });
      grant = await as('POST', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, { token: tokenB, body });
    }
    const m = await as('POST', '/api/as/mandate', {
      apiKey: P.apiKey,
      body: { ...request, above_cap_approvers: approvers, authorization_id: authorization, mandate_id: mandateId, mandate_version: 1, expires_at: expiresAt },
    });
    return { mandateId, grant: grant as Res, mandate: m };
  }

  /** The signed deciders of P's mandate, and the card context, for a proposal filed by A. */
  async function file(tag: string): Promise<Filed> {
    const args = { amount: 250, description: `Licence ${tag} ${MARK}`, customer_id: 'cus_1' };
    const sealed = await internal(A, '/encrypt-content', {
      toolArgs: args,
      recipientUserIds: [P.id, Q.id],
      readers: { ownerDid: P.rootDid, deciders: mandate.above_cap_approvers },
      context: contextFor(tag),
    });
    expect(sealed.status, show(sealed)).toBe(200);
    const content = sealed.json.content;
    const created = await as('POST', '/api/proposals', {
      apiKey: P.apiKey,
      body: {
        authorization_id: authorizationId, mandateId: mandate.mandate_id, boundsHash: mandate.bounds_hash,
        profile_id: CHARGE, tool: 'create_payment_link', action: 'create_payment_link', actionType: 'charge',
        execution_context: { amount: 250 }, executionContext: { amount: 250 },
        content, proposalContentHash: content.hash, pending_approvers: [Q.id],
      },
    });
    expect(created.status, show(created)).toBe(201);
    return { id: created.json.proposal.id, args, sealed: sealed.json };
  }

  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT, { name: 'as-stage-c', env: { SUVEREN_DEVICE_KEYS: 'on' } });
    db = new pg.Client({ connectionString: pm.asDatabaseUrl()! });
    await db.connect();

    P = await register('Owner');
    L = await register('Legacy reader');
    const q0 = await register('Approver');

    // The team first, while nobody has a chain (a team and its members switch together; no member list is published).
    const team = await sp.createGroup(P.apiKey, `Stage C Team ${Date.now()}`);
    teamId = team.group.id;
    await sp.joinGroup(q0.apiKey, team.inviteCode, P.apiKey);
    await sp.joinGroup(L.apiKey, team.inviteCode, P.apiKey);
    const cfg = await as('PUT', `/api/groups/${teamId}/profile-config/${encodeURIComponent(CHARGE)}`, {
      apiKey: P.apiKey,
      body: { grantors: [P.id], approvers: [q0.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } } },
    });
    expect(cfg.status, show(cfg)).toBeLessThan(300);

    // Three real gateways of P.
    A = await startGw('gw-a', PORTS.A, true);
    B = await startGw('gw-b', PORTS.B, true);
    C = await startGw('gw-c', PORTS.C, true);

    // Q: a chain made here (test-held device with a real reading key). Its person is the one q0 registered.
    Q = await (async () => {
      const root = await newRoot();
      const read = newReadKey();
      const dev = withReadPub(await newDevice(), read.pub);
      const g = await genesisEntry(root, dev);
      const r = await as('POST', '/api/devices/chain', { body: { entry: g, enrolment_code: await enrolmentCodeFor(q0) } });
      expect(r.status, show(r)).toBe(201);
      const ch = await as('POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id }, headers: { 'x-forwarded-for': '10.9.1.1' } });
      const sess = await as('POST', '/api/devices/session', { body: await signinBody(root, dev, await headOf(g), ch.json) });
      expect(sess.status, show(sess)).toBe(200);
      return { ...q0, did: root.did, root, dev, chain: [g], token: sess.json.token, readPriv: read.priv };
    })();

    // P's three gateways sign in with the account key BEFORE any chain exists; each one's reading key is read back
    // from the AS right after its own sign-in (the AS keeps one per account, the last writer's).
    await loginAndLock(A, P.apiKey);
    const aPub = await registeredReadPub(P.apiKey, null);
    await loginAndLock(B, P.apiKey);
    const bPub = await registeredReadPub(P.apiKey, aPub.b64);
    await loginAndLock(C, P.apiKey);
    const cPub = await registeredReadPub(P.apiKey, bPub.b64);

    // A runs the gateway's own set-up. The recovery code is shown once; the test keeps it to build the root-signed
    // `add` entries for B and C (seam, see the header).
    const start = await http(A.url, 'POST', '/auth/device/setup/start', { body: { label: 'Computer A' }, headers: pageHeaders(A) });
    expect(start.status, show(start)).toBe(200);
    rootOfP = await deriveRootKey(await parseRecoveryCode(start.json.recoveryCode));
    expect(rootOfP.did).toBe(start.json.rootDid);
    devA = start.json.deviceKeyId;
    const fin = await http(A.url, 'POST', '/auth/device/setup/finish', { body: { setupId: start.json.setupId, enrolmentCode: await enrolmentCodeFor(P) }, headers: pageHeaders(A) });
    expect(fin.status, show(fin)).toBe(200);
    expect(fin.json.signedIn, show(fin)).toBe(true);
    P.rootDid = start.json.rootDid;

    devB = withReadPub(await newDevice('Computer B'), bPub.raw);
    devC = withReadPub(await newDevice('Computer C'), cPub.raw);
    const [genesis] = await chainEntriesOf(P.id);
    const addB = await addEntryByRoot(rootOfP, genesis, devB);
    await storeAdd(P.id, addB);

    // B signs in to the AS as a device of P's chain: the device that grants P's mandate (see the header).
    const chB = await as('POST', '/api/devices/challenge', { body: { key_id: devB.record.key_id }, headers: { 'x-forwarded-for': '10.8.1.1' } });
    expect(chB.status, show(chB)).toBe(200);
    const sessB = await as('POST', '/api/devices/session', { body: await signinBody(rootOfP, devB, await headOf(addB), chB.json) });
    expect(sessB.status, show(sessB)).toBe(200);
    tokenB = sessB.json.token;

    // The mandate: P grants charge in the team. The team's approval cap (100) is below amount_max, so the mandate is
    // review_above_cap with Q as the approver; a chain account names that itself and grants it on a device first.
    const bounds = { profile: CHARGE, amount_max: 500, amount_daily_max: 5000, amount_monthly_max: 50_000, transaction_count_daily_max: 50 };
    request = {
      profile_id: CHARGE,
      profile_hash: profileHashFor(CHARGE, PROFILES_DIR),
      group_id: teamId,
      bounds,
      bounds_hash: computeBoundsHash(bounds, ['profile', 'amount_max', 'amount_daily_max', 'amount_monthly_max', 'transaction_count_daily_max']),
      scope_hash: computeScopeHash({ currency: 'EUR', action_type: 'charge' }, ['currency', 'action_type']),
      domain: 'owner', did: P.rootDid, mandate_owners: [{ did: P.rootDid }],
      commitment_mode: 'review_above_cap',
      above_cap_caps: { amount_max: 100 }, above_cap_approvers: [Q.root.did], above_cap_approvals: 1,
      gate_content_hashes: hashGateContent({ intent: 'Stage C: encrypt to every device.' }),
      execution_context_hash: computeExecutionContextHash(loadProfile(CHARGE, PROFILES_DIR) as { executionContextSchema?: unknown }),
      supported_versions: ['0.8', '0.7'],
    };
    const g = await grantAndRequest({ chainDids: [P.rootDid!, Q.root.did] });
    expect(g.grant.status, show(g.grant)).toBe(201);
    const m = g.mandate;
    expect(m.status, show(m)).toBeLessThan(300);
    authorizationId = m.json.authorization_id as string;
    mandate = JSON.parse(Buffer.from(m.json.blob as string, 'base64url').toString('utf8')).payload;
    expect(mandate.version).toBe('0.8');
    expect(mandate.mandate_id).toBe(g.mandateId);
    expect(mandate.mandate_owners[0].did).toBe(P.rootDid);
    expect([...mandate.above_cap_approvers]).toEqual([Q.root.did]);
  }, 900_000);

  afterAll(async () => {
    await db?.end().catch(() => undefined);
    await pm.killAll();
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }, 60_000);

  // ── 1 ──────────────────────────────────────────────────────────────────────
  it('a proposal opens on both gateways of the owner and for the approver; the proposal row holds no readable content', async () => {
    p1 = await file('one');
    const content = p1.sealed.content;
    // One wrap per active device of each reader with a chain; nothing for the reader without one.
    expect(Object.keys(content.device_keys).sort()).toEqual([devA, devB.record.key_id, Q.dev.record.key_id].sort());
    expect(content.readers.sort()).toEqual([P.rootDid, Q.root.did].sort());
    expect(content.unreadable).toEqual([]);
    expect(p1.sealed.unreadableReaders).toEqual([]);
    expect(typeof content.context).toBe('string');

    // The AS stores ciphertext, wraps and an opaque context: not a word of the content, the linked record or the context.
    const row = await proposalRow(p1.id);
    const stored = JSON.stringify(row);
    expect(stored).not.toContain(MARK);
    expect(stored).not.toContain('LINKED');
    expect(stored).not.toContain('Licence');
    expect(row.tool_args ?? null).toBeNull();
    expect(Object.keys(row.content_device_keys).sort()).toEqual(Object.keys(content.device_keys).sort());
    expect(String(row.content_context).length).toBeGreaterThan(20);
    expect(JSON.stringify((await as('GET', `/api/proposals/${p1.id}`, { apiKey: P.apiKey })).json)).not.toContain(MARK);

    // Gateway A opens it, with its card context.
    const onA = await internal(A, '/decrypt-content', await wireFor(p1.id, devA, P));
    expect(onA.status, show(onA)).toBe(200);
    expect(JSON.parse(onA.json.plaintext)).toEqual(p1.args);
    expect(onA.json.context.linked_record).toEqual(contextFor('one').linked_record);
    expect(onA.json.contextError).toBeUndefined();

    // Gateway B, a second computer of the same person, opens it from its own wrap.
    const onB = await internal(B, '/decrypt-content', await wireFor(p1.id, devB.record.key_id, P));
    expect(onB.status, show(onB)).toBe(200);
    expect(JSON.parse(onB.json.plaintext)).toEqual(p1.args);
    expect(onB.json.context.gateway_version).toBe('e2e-stage-c');

    // The approver reads it as a device session of the AS does: its own wrap only, then hap-core opens it.
    const asQ = await as('GET', `/api/proposals/${p1.id}`, { token: Q.token });
    expect(asQ.status, show(asQ)).toBe(200);
    const qc = asQ.json.proposal.content;
    expect(Object.keys(qc.device_keys)).toEqual([Q.dev.record.key_id]);
    const opened = await decryptProposalContent(
      { ciphertext: qc.ciphertext, encrypted_keys: { [Q.root.did]: qc.device_keys[Q.dev.record.key_id] }, readers: [Q.root.did], unreadable: [] } as never,
      Q.root.did, Q.readPriv,
    );
    expect(opened.arguments).toEqual(p1.args);
    expect(opened.proposalContentHash).toBe(content.hash);
  }, 120_000);

  // ── 2 ──────────────────────────────────────────────────────────────────────
  it('a mandate naming an approver without a device chain is refused (no mixing, plan 9.2)', async () => {
    // L becomes an approver of the team's charge settings; L has no chain.
    const mixed = await as('PUT', `/api/groups/${teamId}/profile-config/${encodeURIComponent(CHARGE)}`, {
      apiKey: P.apiKey,
      body: { grantors: [P.id], approvers: [Q.id, L.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } } },
    });
    expect(mixed.status, show(mixed)).toBeLessThan(300);
    try {
      const r = await grantAndRequest({ chainDids: [P.rootDid!, Q.root.did], approvers: [Q.root.did, L.did], grantFirst: false });
      expect(r.mandate.status, show(r.mandate)).toBe(409);
      expect(code(r.mandate)).toBe('MIXED_CHAIN_ACCOUNTS');
      expect(r.mandate.json?.authorization_id).toBeUndefined();
    } finally {
      const back = await as('PUT', `/api/groups/${teamId}/profile-config/${encodeURIComponent(CHARGE)}`, {
        apiKey: P.apiKey,
        body: { grantors: [P.id], approvers: [Q.id], approvals: 1, caps: { amount_max: { value: 100, kind: 'approval' } } },
      });
      expect(back.status, show(back)).toBeLessThan(300);
    }
  }, 60_000);

  // ── 3 ──────────────────────────────────────────────────────────────────────
  it('a card context moved to another proposal fails to open; the arguments stay shown', async () => {
    p2 = await file('two');
    const own = await internal(A, '/decrypt-content', await wireFor(p2.id, devA, P));
    expect(own.status, show(own)).toBe(200);
    expect(own.json.context.linked_record).toEqual(contextFor('two').linked_record);

    // The AS (or anyone with its database) puts proposal two's context on proposal one.
    const r1 = await proposalRow(p1.id);
    const r2 = await proposalRow(p2.id);
    await db.query('update proposals set content_context = $1 where id = $2', [r2.content_context, p1.id]);
    try {
      const moved = await internal(A, '/decrypt-content', await wireFor(p1.id, devA, P));
      expect(moved.status, show(moved)).toBe(200);
      expect(JSON.parse(moved.json.plaintext)).toEqual(p1.args);   // the arguments are shown in full
      expect(moved.json.context).toBeUndefined();                  // the context is not
      expect(moved.json.contextError).toBe('context_unreadable');
    } finally {
      await db.query('update proposals set content_context = $1 where id = $2', [r1.content_context, p1.id]);
    }
    const back = await internal(A, '/decrypt-content', await wireFor(p1.id, devA, P));
    expect(back.json.context.linked_record).toEqual(contextFor('one').linked_record);
  }, 120_000);

  // ── 4 ──────────────────────────────────────────────────────────────────────
  it('a wrap for another person\'s device is refused and nothing is stored', async () => {
    const before = (await proposalRow(p1.id)).content_device_keys as Record<string, Wrap>;
    // Q holds a wrap of p1 (it is a reader) and may add wraps for its OWN other devices only.
    const shape = { ct: 'AAAAAAAAAAAAAAAAAAAAAAAA', enc: 'AAAAAAAAAAAAAAAAAAAAAAAA' };
    const foreign = await as('POST', `/api/proposals/${p1.id}/wraps`, { token: Q.token, body: { device_keys: { [devB.record.key_id]: shape } } });
    expect(foreign.status, show(foreign)).toBe(409);
    expect(code(foreign)).toBe('WRAP_NOT_YOURS');
    const unknown = await as('POST', `/api/proposals/${p1.id}/wraps`, { token: Q.token, body: { device_keys: { [Buffer.alloc(32, 7).toString('base64url')]: shape } } });
    expect(unknown.status, show(unknown)).toBe(409);
    expect(code(unknown)).toBe('DEVICE_KEYS_INVALID');
    expect((await proposalRow(p1.id)).content_device_keys).toEqual(before);
  }, 60_000);

  // ── 5 ──────────────────────────────────────────────────────────────────────
  it('a forged chain for an approver in the AS database: unreadable, no wrap, the alarm', async () => {
    const forged = await chained('Forged approver');
    // Change the stored genesis: another reading key in the device record. Its signatures no longer match.
    const other = Buffer.from(newReadKey().pub).toString('base64url');
    const changed = await db.query(`update device_chain_entries set entry = jsonb_set(entry, '{device,read_pub}', to_jsonb($1::text)) where user_id = $2 and seq = 0`, [other, forged.id]);
    expect(changed.rowCount).toBe(1);

    const events = await watchEvents(A);
    try {
      const r = await internal(A, '/encrypt-content', {
        toolArgs: { amount: 250, description: `forged ${MARK}`, customer_id: 'cus_1' },
        recipientUserIds: [P.id, forged.id],
        readers: { ownerDid: P.rootDid, deciders: [forged.root.did] },
        context: contextFor('forged'),
      });
      expect(r.status, show(r)).toBe(200);
      expect(r.json.unreadableReaders).toEqual([{ did: forged.root.did, code: 'chain_invalid' }]);
      const content = r.json.content;
      expect(content.unreadable).toEqual([forged.root.did]);
      expect(content.readers).toEqual([P.rootDid]);
      // No wrap for the forged device in any set; the owner's devices still read.
      expect(Object.keys(content.device_keys)).not.toContain(forged.dev.record.key_id);
      expect(Object.keys(content.encrypted_keys)).not.toContain(forged.root.did);
      expect(Object.keys(content.device_keys).sort()).toEqual([devA, devB.record.key_id].sort());
      await until(async () => (events.text().includes('event: reader-chain-alarm') ? true : undefined), 'the alarm event on the page stream', 10_000);
    } finally { events.stop(); }
  }, 90_000);

  // ── 6 ──────────────────────────────────────────────────────────────────────
  it('downgrade: the AS answers 404 for the chain of an approver this gateway verified before: alarm, no wrap, no legacy wrap', async () => {
    // Case 1 made gateway A verify and pin Q's chain. Now the AS "has no chain" for Q.
    const saved = await db.query('select root_did from users where id = $1', [Q.id]);
    expect(saved.rows[0].root_did).toBe(Q.root.did);
    const gone = await as('GET', `/api/devices/chain?did=${encodeURIComponent(Q.root.did)}`, { token: Q.token });
    expect(gone.status).toBe(200);
    await db.query('update users set root_did = null where id = $1', [Q.id]);
    const events = await watchEvents(A);
    try {
      expect((await as('GET', `/api/devices/chain?did=${encodeURIComponent(Q.root.did)}`, { token: Q.token })).status).toBe(404);
      const r = await internal(A, '/encrypt-content', {
        toolArgs: { amount: 250, description: `downgrade ${MARK}`, customer_id: 'cus_1' },
        recipientUserIds: [P.id, Q.id],
        readers: { ownerDid: P.rootDid, deciders: [Q.root.did] },
        context: contextFor('downgrade'),
      });
      expect(r.status, show(r)).toBe(200);
      expect(r.json.unreadableReaders).toEqual([{ did: Q.root.did, code: 'chain_missing' }]);
      const content = r.json.content;
      expect(content.unreadable).toEqual([Q.root.did]);
      expect(content.readers).toEqual([P.rootDid]);
      // Neither a device wrap nor a legacy wrap (by DID or by account id) for Q.
      expect(Object.keys(content.device_keys)).not.toContain(Q.dev.record.key_id);
      expect(Object.keys(content.encrypted_keys)).not.toContain(Q.root.did);
      expect(Object.keys(content.keys ?? {})).not.toContain(Q.id);
      await until(async () => (events.text().includes('event: reader-chain-alarm') ? true : undefined), 'the alarm event on the page stream', 10_000);
    } finally {
      events.stop();
      await db.query('update users set root_did = $1 where id = $2', [Q.root.did, Q.id]);
    }
    expect((await as('GET', `/api/devices/chain?did=${encodeURIComponent(Q.root.did)}`, { token: Q.token })).status).toBe(200);
  }, 90_000);

  // ── 7 ──────────────────────────────────────────────────────────────────────
  it('a gateway added to the chain later opens an open proposal after the re-wrap; stored wraps are never replaced', async () => {
    const [genesis, addB] = await chainEntriesOf(P.id);
    await storeAdd(P.id, await addEntryByRoot(rootOfP, addB, devC));
    expect((await chainEntriesOf(P.id)).length).toBe(3);

    const before1 = (await proposalRow(p1.id)).content_device_keys as Record<string, Wrap>;
    const before2 = (await proposalRow(p2.id)).content_device_keys as Record<string, Wrap>;
    expect(Object.keys(before1)).not.toContain(devC.record.key_id);

    // C holds no wrap yet: it cannot read.
    const early = await internal(C, '/decrypt-content', await wireFor(p1.id, devC.record.key_id, P));
    expect(early.status, show(early)).toBeGreaterThanOrEqual(400);

    // What the re-wrap reads: the AS lists the owner's open proposals to a device session of the owner, each with that
    // device's OWN wrap (and no other). Checked here with device B's session, the one this test holds.
    for (const q of ['creator=me', 'domain=owner']) {
      const listed = await as('GET', `/api/proposals?${q}`, { token: tokenB });
      expect(listed.status, `${q}: ${show(listed)}`).toBe(200);
      const open = (listed.json.proposals as any[]).filter((x) => x.id === p1.id || x.id === p2.id);
      expect(open.map((x) => x.id).sort(), `${q}: ${show(listed)}`).toEqual([p1.id, p2.id].sort());
      for (const x of open) expect(Object.keys(x.content?.device_keys ?? {}), `${q}: ${JSON.stringify(x.content ? Object.keys(x.content) : x.content)} status=${x.status}`).toEqual([devB.record.key_id]);
    }

    // A, which can open the content key, wraps it for the devices of the chain it verified, and hands the wraps to the AS.
    const run = await internal(A, '/rewrap-proposals', {});
    expect(run.status, show(run)).toBe(200);
    expect(run.json.failed, show(run)).toBe(0);
    expect(run.json.rewrapped, show(run)).toBeGreaterThanOrEqual(2);
    expect(run.json.skippedProposals ?? []).toEqual([]);

    for (const [p, before] of [[p1, before1], [p2, before2]] as const) {
      const after = (await proposalRow(p.id)).content_device_keys as Record<string, Wrap>;
      expect(Object.keys(after)).toContain(devC.record.key_id);
      for (const [k, w] of Object.entries(before)) expect(after[k], `wrap of ${k} was replaced`).toEqual(w);
    }

    // C opens both, with the card context.
    for (const p of [p1, p2]) {
      const onC = await internal(C, '/decrypt-content', await wireFor(p.id, devC.record.key_id, P));
      expect(onC.status, show(onC)).toBe(200);
      expect(JSON.parse(onC.json.plaintext)).toEqual(p.args);
      expect(onC.json.contextError).toBeUndefined();
      expect(onC.json.context.gateway_version).toBe('e2e-stage-c');
    }
    // The approver's wrap is unchanged and its own device session still reads only that one.
    const asQ = await as('GET', `/api/proposals/${p1.id}`, { token: Q.token });
    expect(Object.keys(asQ.json.proposal.content.device_keys)).toEqual([Q.dev.record.key_id]);
    void genesis;
  }, 120_000);
});
