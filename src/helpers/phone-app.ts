/**
 * Helpers for the phone approval app suite (device-keys plan step 11): the parts of the stack the test plays itself.
 *
 * Nothing here is a mock. The Authority Server is the real one over HTTP. The phone is the real app in a real browser.
 * The "computer" (a gateway that shows or scans the pairing QR) is played by this file, because the gateway side of
 * pairing ("Add this computer", admitting a phone) is not built in the gateway page yet: it makes real device keys,
 * real platform checks and real pairing messages with hap-core's device-keys module, and the Authority Server and the
 * phone verify them themselves.
 */
import { createHash, webcrypto } from 'node:crypto';
import pg from 'pg';
import qrcode from 'qrcode-generator';
import {
  b64uDecode, b64uEncode, buildDeviceRecord, buildEntry, comparisonCode, derivePairing, ed25519PublicKey, encodeCoseEc2,
  ecdsaRawToDer, encodePairingQr, entryHash, identityCode, pairingCommitment, randomBytes, signEntry, verifyPairingMessage,
  buildPairingMessage, verifyChain,
  type ChainEntry, type CheckKey, type DeviceRecord, type PairingKind, type PairingMessage, type WebauthnProof,
} from '@humanagencyp/hap-core/device-keys';
import { checkOver, genesisEntry, headOf, newDevice, newRoot, signinBody, type Device, type Root } from './device-chain';

// ─── The stack, as global setup left it ─────────────────────────────────────────────

export interface PhoneStack {
  asUrl: string;
  appUrl: string;
  /** An origin that serves a blank page on the same host and another port: a look-alike of the app's address. */
  lookalikeUrl: string;
  dbUrl: string;
}

/** Read what e2e/phone/global-setup.ts wrote into the environment; throws when it was not run. */
export function stackFromEnv(): PhoneStack {
  const e = process.env;
  if (!e.HAP_E2E_PHONE_AS_URL || !e.HAP_E2E_PHONE_APP_URL || !e.HAP_E2E_PHONE_LOOKALIKE_URL || !e.HAP_E2E_PHONE_DB_URL) {
    throw new Error('the phone suite needs its global setup (playwright.phone.config.ts)');
  }
  return { asUrl: e.HAP_E2E_PHONE_AS_URL, appUrl: e.HAP_E2E_PHONE_APP_URL, lookalikeUrl: e.HAP_E2E_PHONE_LOOKALIKE_URL, dbUrl: e.HAP_E2E_PHONE_DB_URL };
}

// ─── HTTP ──────────────────────────────────────────────────────────────────────────

export interface Res { status: number; json: any }

export async function http(base: string, method: string, path: string, o: { token?: string; apiKey?: string; cookie?: string; body?: unknown; ip?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (o.token) headers.authorization = `Bearer ${o.token}`;
  if (o.apiKey) headers['x-api-key'] = o.apiKey;
  if (o.cookie) headers.cookie = o.cookie;
  // The Authority Server rate-limits per caller address; a test that makes many calls names a fresh one.
  headers['x-forwarded-for'] = o.ip ?? fakeIp();
  const res = await fetch(`${base}${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) });
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  return { status: res.status, json };
}

export const show = (r: Res): string => `${r.status} ${JSON.stringify(r.json)}`;
export const codeOf = (r: Res): string | undefined => r.json?.errors?.[0]?.code ?? r.json?.code;
export const nowSec = (): number => Math.floor(Date.now() / 1000);
export const fakeIp = (): string => `10.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

/** Poll `fn` until it returns something other than undefined, or fail with `what`. */
export async function until<T>(what: string, fn: () => Promise<T | undefined>, ms = 30_000, every = 300): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, every));
  }
}

// ─── People and chains ───────────────────────────────────────────────────────────

export interface Person { userId: string; apiKey: string; name: string }

export async function newPerson(s: PhoneStack, name = 'Test person'): Promise<Person> {
  const email = `${name.toLowerCase().replace(/\W+/g, '-')}-${randomBytesHex(4)}@test.local`;
  const r = await http(s.asUrl, 'POST', '/api/auth/register', { body: { name, email } });
  if (r.status !== 200 && r.status !== 201) throw new Error(`register failed: ${show(r)}`);
  return { userId: r.json.user.id, apiKey: r.json.apiKey, name };
}

const randomBytesHex = (n: number): string => Buffer.from(randomBytes(n)).toString('hex');

export async function connectDb(s: PhoneStack): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: s.dbUrl });
  await c.connect();
  return c;
}

/**
 * A one-time enrolment code. The Authority Server hands one out only to a dashboard session opened from an email link, and
 * nothing in a test can click an email, so that session row is inserted into the throwaway database, exactly as the sign-up
 * link would.
 */
export async function enrolmentCode(s: PhoneStack, db: pg.Client, p: Person): Promise<string> {
  const token = b64uEncode(randomBytes(24));
  await db.query(
    `insert into sessions (token, user_id, kind, created_at, expires_at) values ($1, $2, 'email-link', $3, $4)`,
    [token, p.userId, nowSec(), nowSec() + 3600],
  );
  const r = await http(s.asUrl, 'POST', '/api/enrolment-codes', { cookie: `hap-session=${token}` });
  if (r.status !== 201) throw new Error(`enrolment code refused: ${show(r)}`);
  return r.json.code as string;
}

export interface Computer extends Person {
  root: Root;
  dev: Device;
  entries: ChainEntry[];
  token: string;
}

/** A person whose chain was made on a computer with a check key (a gateway): genesis, then a device session. */
export async function computerWithChain(s: PhoneStack, db: pg.Client, label: string): Promise<Computer> {
  const p = await newPerson(s, 'Computer owner');
  const code = await enrolmentCode(s, db, p);
  const root = await newRoot();
  const dev = await newDevice(label);
  const g = await genesisEntry(root, dev);
  const res = await http(s.asUrl, 'POST', '/api/devices/chain', { body: { entry: g, enrolment_code: code } });
  if (res.status !== 201) throw new Error(`computer genesis refused: ${show(res)}`);
  const token = await sessionFor(s, root, dev, await headOf(g));
  return { ...p, root, dev, entries: [g], token };
}

export async function sessionFor(s: PhoneStack, root: Root, dev: Device, head: { seq: number; hash: string }): Promise<string> {
  const ch = await http(s.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: dev.record.key_id } });
  if (ch.status !== 200) throw new Error(`challenge refused: ${show(ch)}`);
  const r = await http(s.asUrl, 'POST', '/api/devices/session', { body: await signinBody(root, dev, head, ch.json) });
  if (r.status !== 200) throw new Error(`sign-in refused: ${show(r)}`);
  return r.json.token as string;
}

/** The chain as the Authority Server serves it (the person's account key reads it). */
export async function chainOf(s: PhoneStack, p: Person, rootDid: string): Promise<{ entries: ChainEntry[]; head: { seq: number; hash: string } }> {
  const r = await http(s.asUrl, 'GET', `/api/devices/chain?did=${encodeURIComponent(rootDid)}`, { apiKey: p.apiKey });
  if (r.status !== 200) throw new Error(`chain read refused: ${show(r)}`);
  return { entries: r.json.entries, head: r.json.head };
}

/** hap-core's own check of the served chain, from the genesis on, against the root DID; returns its state. */
export async function verifiedChain(s: PhoneStack, p: Person, rootDid: string) {
  const { entries } = await chainOf(s, p, rootDid);
  return verifyChain({ expectedRootDid: rootDid, entries });
}

export async function asKeyHex(s: PhoneStack): Promise<string> {
  const r = await http(s.asUrl, 'GET', '/api/as/pubkey');
  if (r.status !== 200 || typeof r.json?.publicKey !== 'string') throw new Error(`pubkey: ${show(r)}`);
  return r.json.publicKey as string;
}

/** The identity code of a root DID, derived here from hap-core: what both screens must show. */
export const identityCodeOf = (rootDid: string): Promise<string> => identityCode(rootDid);

// ─── The pairing, played by a computer ─────────────────────────────────────────────

export interface Pairing { secret: Uint8Array; pairingId: string; macKey: Uint8Array }

export async function newPairing(): Promise<Pairing> {
  const secret = randomBytes(32);
  return { secret, ...(await derivePairing(secret)) };
}

export interface QrFacts {
  asUrl: string;
  asKey: string;
  expiresAt?: number;
  /** For `admitter`: the chain facts the QR carries. */
  admitter?: { root_did: string; head: { seq: number; hash: string }; key_id: string };
}

/** The text a QR holds (`SUVEREN-PAIR-1:` + base64url of the canonical JSON), shown by `admitter` or by `joiner`. */
export function pairingQr(p: Pairing, f: QrFacts): string {
  return encodePairingQr({
    v: 1, as_url: f.asUrl, as_key: f.asKey, shown_by: f.admitter ? 'admitter' : 'joiner', secret: b64uEncode(p.secret),
    root_did: f.admitter?.root_did ?? null, head: f.admitter?.head ?? null, key_id: f.admitter?.key_id ?? null,
    expires_at: f.expiresAt ?? nowSec() + 600,
  });
}

export async function postRaw(s: PhoneStack, p: Pairing, msg: unknown): Promise<Res> {
  return http(s.asUrl, 'POST', `/api/devices/pairings/${p.pairingId}/messages`, { body: msg });
}

export async function postMessage(s: PhoneStack, p: Pairing, kind: PairingKind, body: Record<string, unknown>): Promise<Res> {
  return postRaw(s, p, await buildPairingMessage(p.macKey, kind, body));
}

/** A message whose MAC is not the pairing's: the Authority Server cannot tell (it holds no MAC key), the phone can. */
export async function postWrongMac(s: PhoneStack, p: Pairing, kind: PairingKind, body: Record<string, unknown>): Promise<Res> {
  const good = await buildPairingMessage(p.macKey, kind, body);
  return postRaw(s, p, { ...good, mac: b64uEncode(randomBytes(32)) });
}

export interface Box { messages: Partial<Record<PairingKind, PairingMessage>>; raw: unknown[]; chain?: { root_did: string; entries: ChainEntry[]; head: { seq: number; hash: string } } }

/** Read the mailbox and verify every message's MAC, as the two devices do (a message that does not verify is left out of `messages`). */
export async function readBox(s: PhoneStack, p: Pairing): Promise<Box | null> {
  const r = await http(s.asUrl, 'GET', `/api/devices/pairings/${p.pairingId}`);
  if (r.status === 404) return null;
  if (r.status !== 200) throw new Error(`mailbox read: ${show(r)}`);
  const messages: Box['messages'] = {};
  for (const raw of r.json.messages as unknown[]) {
    // A message with a wrong MAC is the one a test planted: it is in `raw`, and not in `messages`.
    const m = await verifyPairingMessage(p.macKey, raw).catch(() => null);
    if (m) messages[m.kind] = m;
  }
  return { messages, raw: r.json.messages, chain: r.json.chain };
}

export async function waitForMessage(s: PhoneStack, p: Pairing, kind: PairingKind, ms = 30_000): Promise<PairingMessage> {
  return until(`the ${kind} message`, async () => (await readBox(s, p))?.messages[kind], ms);
}

/** The computer opens the mailbox (needs a device session with a check key). */
export async function openMailbox(s: PhoneStack, c: Computer, p: Pairing, expiresAt = nowSec() + 600): Promise<Res> {
  return http(s.asUrl, 'POST', '/api/devices/pairings', { token: c.token, body: { pairing_id: p.pairingId, expires_at: expiresAt } });
}

/**
 * The computer admits a phone that has joined: it answers the phone's `commit` with a `challenge`, reads the `open`, checks it
 * against the commitment, signs, appends the `add` together with the phone's passkey (stored under the pairing id) and says
 * `done`. Returns the comparison code the computer would show, and a `confirm` that finishes the pairing.
 */
export async function computerAnswersJoin(s: PhoneStack, c: Computer, p: Pairing) {
  const commit = await waitForMessage(s, p, 'commit');
  const rA = randomBytes(32);
  const sent = await postMessage(s, p, 'challenge', { r_a: b64uEncode(rA) });
  if (sent.status !== 201 && sent.status !== 200) throw new Error(`challenge: ${show(sent)}`);
  const open = await waitForMessage(s, p, 'open');
  const entry = open.body.entry as ChainEntry;
  const sig = b64uDecode(open.body.sig as string);
  const rJ = b64uDecode(open.body.r_j as string);
  const matches = (await pairingCommitment(entry, sig, rJ)) === commit.body.c;
  const code = await comparisonCode(p.macKey, entry, rJ, rA);
  const confirm = async (): Promise<Res> => {
    const h = await entryHash(entry);
    const mine = await signEntry(entry, c.dev.record.key_id, c.dev.seed);
    const final: ChainEntry = {
      ...entry,
      sigs: [mine, { by: (entry.device as DeviceRecord).key_id, sig: open.body.sig as string }],
      checks: [...entry.checks, { by: c.dev.record.key_id, check: await checkOver(c.dev.checkPriv, h) }],
    };
    const res = await http(s.asUrl, 'POST', '/api/devices/chain', { token: c.token, body: { entry: final, pairing_id: p.pairingId } });
    if (res.status === 201) await postMessage(s, p, 'done', { entry_hash: h });
    return res;
  };
  return { entry, code, matches, confirm };
}

/** The new gateway that the phone admits (`shown_by: joiner`). The test is that gateway. */
export interface Joiner {
  device: Device;
  pairing: Pairing;
  qr: string;
  /** Say `hello` was answered: build the entry, commit, answer the challenge with `open`. Returns what the screens must show. */
  run: (o?: JoinerOptions) => Promise<{ entry: ChainEntry; code: string; commitStatus: number; secondCommitStatus?: number }>;
}

export interface JoinerOptions {
  /** Send the `commit` with a MAC that is not the pairing's. The run stops there (the phone ends the pairing). */
  wrongMacCommit?: boolean;
  /** Send a second `commit` after the first; its status is returned. */
  secondCommit?: boolean;
  /** Send an `open` for another entry (another label) than the one committed to. */
  openOtherEntry?: boolean;
}

export async function newJoiner(s: PhoneStack, label: string): Promise<Joiner> {
  const pairing = await newPairing();
  const device = await newDevice(label);
  const qr = pairingQr(pairing, { asUrl: s.asUrl, asKey: await asKeyHex(s) });
  const run: Joiner['run'] = async (o = {}) => {
    const hello = await waitForMessage(s, pairing, 'hello');
    const head = hello.body.head as { seq: number; hash: string };
    // As the real gateway joiner does (control-plane device-pairing.ts): a device that brings a check key proves it in its own
    // entry (`checks`), because the chain check refuses an add of a device with a check and no proof of it (NO_POSSESSION).
    const make = async (rec: DeviceRecord): Promise<ChainEntry> => {
      const e = buildEntry({ root_did: hello.body.root_did as string, seq: head.seq + 1, prev: head.hash, op: 'add', created_at: nowSec(), signer: hello.body.key_id as string, device: rec });
      if (rec.check) e.checks = [{ by: rec.key_id, check: await checkOver(device.checkPriv, await entryHash(e)) }];
      return e;
    };
    const entry = await make(device.record);
    const sig = b64uDecode((await signEntry(entry, device.record.key_id, device.seed)).sig);
    const rJ = randomBytes(32);
    const c = await pairingCommitment(entry, sig, rJ);
    const commitRes = o.wrongMacCommit ? await postWrongMac(s, pairing, 'commit', { c }) : await postMessage(s, pairing, 'commit', { c });
    let second: number | undefined;
    if (o.secondCommit) second = (await postMessage(s, pairing, 'commit', { c: await pairingCommitment(entry, sig, randomBytes(32)) })).status;
    if (o.wrongMacCommit) return { entry, code: '', commitStatus: commitRes.status };
    const challenge = await waitForMessage(s, pairing, 'challenge');
    const rA = b64uDecode(challenge.body.r_a as string);
    let opened = entry;
    let openSig = sig;
    if (o.openOtherEntry) {
      // Same device, same keys, another label: a perfectly signed entry, but not the one the commitment names.
      opened = await make({ ...device.record, label: `${device.record.label} (other)` });
      openSig = b64uDecode((await signEntry(opened, device.record.key_id, device.seed)).sig);
    }
    await postMessage(s, pairing, 'open', { entry: opened, sig: b64uEncode(openSig), r_j: b64uEncode(rJ) });
    return { entry: opened, code: await comparisonCode(pairing.macKey, opened, rJ, rA), commitStatus: commitRes.status, secondCommitStatus: second };
  };
  return { device, pairing, qr, run };
}

// ─── What is stored in the mailbox table ────────────────────────────────────────────

export async function mailboxRow(db: pg.Client, p: Pairing): Promise<{ columns: string[]; text: string } | null> {
  const r = await db.query(`select * from pairing_mailboxes where pairing_id = $1`, [p.pairingId]);
  if (r.rows.length === 0) return null;
  return { columns: r.fields.map((f) => f.name), text: JSON.stringify(r.rows[0]) };
}

/** A person may hold five open pairings; a suite that makes many frees them between cases. */
export async function clearMailboxes(db: pg.Client, userId: string): Promise<void> {
  await db.query(`delete from pairing_mailboxes where user_id = $1`, [userId]);
}

// ─── A QR the phone's camera "sees" ──────────────────────────────────────────────────

/** The modules of a QR code (true = dark). Error correction M, like the app's own encoder. */
export function qrMatrix(text: string): boolean[][] {
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  const n = q.getModuleCount();
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => q.isDark(r, c)));
}

// ─── A fabricated phone genesis (for the refusals that need a hand-made request) ─────

const sha = (b: Uint8Array | string): Buffer => createHash('sha256').update(b).digest();

export interface NodePasskey { credId: Uint8Array; priv: webcrypto.CryptoKey; x: Uint8Array; y: Uint8Array }

export async function newNodePasskey(): Promise<NodePasskey> {
  const kp = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey));
  return { credId: randomBytes(32), priv: kp.privateKey, x: raw.slice(1, 33), y: raw.slice(33, 65) };
}

/** A passkey assertion over `hash` (`sha256:<hex>`), made here with a node key, for an entry the test built by hand. */
export async function nodeAssertion(pk: NodePasskey, rpId: string, origin: string, hash: string): Promise<WebauthnProof> {
  const digest = Buffer.from(hash.slice('sha256:'.length), 'hex');
  const authData = Buffer.concat([sha(rpId), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const cdj = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64uEncode(new Uint8Array(digest)), origin }));
  const sig = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pk.priv, Buffer.concat([authData, sha(cdj)])));
  return { authenticatorData: b64uEncode(new Uint8Array(authData)), clientDataJSON: b64uEncode(new Uint8Array(cdj)), signature: b64uEncode(ecdsaRawToDer(sig)) };
}

/** A phone-kind genesis (root + phone sign, the phone's passkey checks it) with a check key the caller names. */
export async function phoneGenesisWith(root: Root, label: string, check: CheckKey, checkFor: (hash: string) => Promise<WebauthnProof>): Promise<{ entry: ChainEntry; keyId: string }> {
  const seed = randomBytes(32);
  const signPub = await ed25519PublicKey(seed);
  const record = await buildDeviceRecord(
    { sign_pub: b64uEncode(signPub), read_pub: b64uEncode(randomBytes(32)), kind: 'approve-app', label, keystore: 'platform', check },
    signPub,
  );
  const e = buildEntry({ root_did: root.did, seq: 0, prev: null, op: 'genesis', created_at: nowSec(), signer: 'root', device: record });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, 'root', root.privateSeed), await signEntry(e, record.key_id, seed)];
  e.checks = [{ by: record.key_id, check: await checkFor(h) }];
  return { entry: e, keyId: record.key_id };
}

export const webauthnCheckKey = (rpId: string, credId: Uint8Array, x: Uint8Array, y: Uint8Array): CheckKey =>
  ({ type: 'webauthn', rp_id: rpId, cred_id: b64uEncode(credId), pub: b64uEncode(encodeCoseEc2(x, y)) });

export { newRoot, newDevice, headOf, signinBody, checkOver, b64uEncode, b64uDecode, randomBytes, entryHash, sha };
export type { Root, Device, ChainEntry };
