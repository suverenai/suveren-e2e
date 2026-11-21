/**
 * "Give on your phone" on the gateway page (DEC-90), against the REAL stack: a real gateway with the switch on and NO check key
 * (no native helper in CI: it cannot grant a mandate itself), the real Authority Server, a real browser on the gateway page.
 *
 * What is real: the gateway (control plane + MCP server, built from the checkout, its own data folder: e2e/phone/global-setup.ts),
 * its set-up (genesis with the enrolment code), the gateway page's give screen and its "Give on your phone" footer, the sealing
 * to the phone, the Authority Server's grant check, the gateway's own check of the phone's grant, the mandate request.
 *
 * What the test plays itself: the PHONE (its device key, reading key, passkey): it opens the sealed give with its own reading key,
 * rebuilds the grant members from what it shows, and signs the grant with its key and a WebAuthn assertion at the app's origin,
 * as the app does (the app's own give screens are covered by phone-app.spec.ts). Seams:
 *   - The phone joins the chain by a root-signed `add` written straight into the throwaway database (the same seam as
 *     test/stage-c-every-device.test.ts): the real path is the recovery code plus an emailed link, which a gateway without a
 *     check key needs; the entry itself is a valid one (root, the phone's signature and its passkey check over the entry hash).
 *   - The give page is opened with the wizard's hand-over (sessionStorage `agentAuth` / `agentGate`) set by the test, by an
 *     in-app navigation (a reload would lock the page again: its session token lives in the page); the wizard itself is
 *     covered by the default browser suite.
 *
 * Not covered: a connector's tool call under the phone-given mandate (this gateway runs no connector); the mandate is shown as
 * live in the gateway's own list, which the MCP server fills only with mandates whose owner's grant it verified.
 */
import { test, expect } from '@playwright/test';
import type pg from 'pg';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildEntry, entryHash, signEntry, rootKeyFromRecoveryCode, buildGrant, signObject, objectHash, verifyChain, type ChainEntry } from '@humanagencyp/hap-core/device-keys';
import { decryptProposalContent, type MandatePayload } from '@humanagencyp/hap-core';
import { grantMembersOf } from '../../src/helpers/mandate-grant';
import { newPhone, assertion, phoneSigninBody, type Phone } from '../../src/helpers/phone-passkey';
import { newReadKey } from '../../src/helpers/device-chain';
import { connectDb, enrolmentCode, http, newPerson, nowSec, show, stackFromEnv, until, b64uEncode, type PhoneStack, type Person } from '../../src/helpers/phone-app';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the gateway page is the same in every browser; one engine is enough here');

const PROFILES_DIR = process.env.HAP_E2E_PROFILES_DIR ?? join(import.meta.dirname, '..', '..', '..', 'hap-profiles');
const PASSWORD = 'correct horse battery staple 42';

/** The newest sales profile on disk (what the gateway and the Authority Server load). */
function salesProfileId(): string {
  const dir = join(PROFILES_DIR, 'sales');
  const versions = readdirSync(dir).filter((f) => f.endsWith('.profile.json')).map((f) => f.replace('.profile.json', ''));
  versions.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const v = versions.at(-1)!;
  return JSON.parse(readFileSync(join(dir, `${v}.profile.json`), 'utf8')).id as string;
}

let stack: PhoneStack;
let db: pg.Client;
let gw: string;
test.beforeAll(async () => {
  if (unavailable) return;
  stack = stackFromEnv();
  db = await connectDb(stack);
  gw = process.env.HAP_E2E_PHONE_GW_URL!;
});
test.afterAll(async () => { await db?.end().catch(() => undefined); });

/** Sign the gateway in with the account key once, set the unlock password, return the page-session headers for API calls. */
async function setUpGateway(p: Person): Promise<{ headers: Record<string, string> }> {
  const login = await fetch(`${gw}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': p.apiKey }, body: '{}' });
  expect(login.status, await login.clone().text()).toBe(200);
  const set = await fetch(`${gw}/auth/password/set`, { method: 'POST', headers: { 'content-type': 'application/json', origin: gw, 'x-api-key': p.apiKey }, body: JSON.stringify({ password: PASSWORD }) });
  const body = (await set.json()) as { sessionToken?: string };
  expect(set.status, JSON.stringify(body)).toBe(200);
  const cookie = /suveren_page_session=([^;]+)/.exec(set.headers.get('set-cookie') ?? '')?.[1];
  expect(cookie, 'no page-session cookie').toBeTruthy();
  return { headers: { 'content-type': 'application/json', origin: gw, cookie: `suveren_page_session=${cookie}`, 'x-suveren-session': body.sessionToken! } };
}

async function chainEntries(userId: string): Promise<ChainEntry[]> {
  const r = await db.query(`select entry from device_chain_entries where user_id = $1 order by seq`, [userId]);
  return r.rows.map((x: { entry: ChainEntry }) => x.entry);
}

/** The phone joins by a root-signed `add` (seam, see the header): root, the phone's own signature, its passkey check. */
async function admitPhone(p: Person, recoveryCode: string, phone: Phone): Promise<void> {
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const entries = await chainEntries(p.userId);
  const state = await verifyChain({ expectedRootDid: root.did, entries });
  const e = buildEntry({ root_did: root.did, seq: state.head.seq + 1, prev: state.head.hash, op: 'add', created_at: nowSec(), signer: 'root', device: phone.record });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, 'root', root.privateSeed), await signEntry(e, phone.record.key_id, phone.seed)];
  e.checks = [{ by: phone.record.key_id, check: await assertion(phone, h) }];
  await verifyChain({ expectedRootDid: root.did, entries: [...entries, e] });
  const d = e.device!;
  await db.query(`insert into device_chain_entries (user_id, seq, entry_hash, entry, stored_at) values ($1, $2, $3, $4::jsonb, $5)`, [p.userId, e.seq, h, JSON.stringify(e), nowSec()]);
  await db.query(
    `insert into devices (key_id, user_id, sign_pub, read_pub, kind, label, "check", added_seq, removed_seq) values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, null)`,
    [d.key_id, p.userId, d.sign_pub, d.read_pub, d.kind, d.label, d.check ? JSON.stringify(d.check) : null, e.seq],
  );
}

/** The phone's device session at the Authority Server (its key and passkey). */
async function phoneSession(p: Person, recoveryCode: string, phone: Phone): Promise<string> {
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const ch = await http(stack.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: phone.record.key_id } });
  expect(ch.status, show(ch)).toBe(200);
  const s = await http(stack.asUrl, 'POST', '/api/devices/session', { body: await phoneSigninBody(root, phone, state.head, ch.json) });
  expect(s.status, show(s)).toBe(200);
  return s.json.token as string;
}

test('a computer without Touch ID: the give page sends the mandate to the phone, waits, and shows "Signed" once the phone gave it', async ({ page }) => {
  test.setTimeout(180_000);
  const p = await newPerson(stack, 'Give on phone');
  const { headers } = await setUpGateway(p);

  // HAP_E2E_EXPECT_PLATFORM (JSON): what the gateway's native helper must report here, e.g. the Windows CI leg that runs the
  // gateway with the real release helper (SUVEREN_HELPER_APP): it is found, hashed, accepts the gateway as its caller, and
  // says it has no secure hardware, so the journey below takes the password path with a real helper in place.
  if (process.env.HAP_E2E_EXPECT_PLATFORM) {
    const cap = await fetch(`${gw}/auth/platform/capabilities`, { headers });
    const cb = await cap.json();
    expect(cap.status, JSON.stringify(cb)).toBe(200);
    expect(cb).toMatchObject(JSON.parse(process.env.HAP_E2E_EXPECT_PLATFORM));
  }

  // The gateway's own set-up (no check key: CI has no native helper).
  const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office PC' }) });
  const sb = (await start.json()) as { setupId: string; recoveryCode: string; rootDid: string };
  expect(start.status, JSON.stringify(sb)).toBe(200);
  const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
  expect(fin.status, await fin.clone().text()).toBe(200);

  // The phone, with a reading key it holds, joins the chain.
  const phone = await newPhone(stack.appUrl, 'My phone');
  const read = newReadKey();
  phone.record.read_pub = b64uEncode(read.pub);
  await admitPhone(p, sb.recoveryCode, phone);

  // The gateway page: unlock with the password, then the give screen with the wizard's hand-over.
  await page.goto(gw);
  await page.locator('#unlock-password').fill(PASSWORD);
  await page.locator('#unlock-password').press('Enter');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 20_000 });
  const groups = await (await fetch(`${gw}/api/groups`, { headers })).json() as { groups?: Array<{ id: string; name?: string; isPersonal?: boolean }> };
  const personal = (groups.groups ?? []).find((g) => g.isPersonal);
  expect(personal, JSON.stringify(groups)).toBeTruthy();
  const profileId = salesProfileId();
  const bounds = { profile: profileId, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
  await page.evaluate(({ auth, gate }) => {
    sessionStorage.setItem('agentAuth', JSON.stringify(auth));
    sessionStorage.setItem('agentGate', JSON.stringify(gate));
  }, {
    auth: { profileId, groupId: personal!.id, groupName: personal!.name ?? null, domain: 'owner', isPersonal: true },
    gate: { bounds, context: { currency: 'EUR' }, gateContent: { intent: 'Quotes wait two days.' }, ttlConfig: { max: 86400 } },
  });
  // In-app navigation, not a reload: the page session's header token lives in the page's memory, so a reload locks it again.
  await page.evaluate(() => { window.history.pushState({}, '', '/mandates/new/sign'); window.dispatchEvent(new PopStateEvent('popstate')); });
  await page.waitForURL((u) => u.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
  await page.locator('input[placeholder*="e.g."]').fill('Quotes');
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();

  // This computer cannot give it: the footer offers the phone.
  const send = page.getByTestId('give-phone-send');
  await expect(send).toBeEnabled({ timeout: 30_000 });
  await send.click();
  await expect(page.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 30_000 });

  // Nothing is requested before the phone gives it.
  const rows = await db.query(`select count(*)::int as n from mandate_issuances where user_id = $1`, [p.userId]).catch(() => ({ rows: [{ n: 0 }] }));
  expect(rows.rows[0].n).toBe(0);

  // The phone: its session, the prepared give sealed to it, the members rebuilt from what it shows, one touch.
  const token = await phoneSession(p, sb.recoveryCode, phone);
  const prepared = await until('the give reaches the phone', async () => {
    const r = await http(stack.asUrl, 'GET', '/api/mandates/prepared', { token });
    const row = (r.json?.prepared ?? [])[0];
    return row ?? undefined;
  });
  const opened = await decryptProposalContent(
    { ciphertext: prepared.ciphertext, encrypted_keys: { [phone.record.key_id]: prepared.device_key }, readers: [phone.record.key_id], unreadable: [] },
    phone.record.key_id, read.priv,
  );
  const c = opened.arguments as Record<string, any>;
  expect(c.give.op).toBe('grant');
  expect(c.give.bounds.value_max).toBe(1000);
  expect(c.intent).toBe('Quotes wait two days.');
  const members = grantMembersOf(c.give.payload as MandatePayload, { authorizationId: c.give.place.authorization_id, groupId: c.give.place.group_id, replaces: c.give.place.replaces, chainDids: c.give.place.chain_dids });
  const root = await rootKeyFromRecoveryCode(sb.recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const grant = buildGrant({
    op: 'grant', owner_did: root.did, key_id: phone.record.key_id, chain_seq: state.head.seq, chain_head: state.head.hash,
    mandate_id: c.mandate_id, mandate_version: c.mandate_version, granted_at: nowSec(), nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
  }, members);
  const stored = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(c.mandate_id)}/grants`, {
    token, body: { grant, sig: await signObject(grant, phone.seed), check: await assertion(phone, await objectHash(grant)) },
  });
  expect(stored.status, show(stored)).toBe(201);

  // The page hears it: the gateway checked the phone's grant against its own chain and requested the mandate.
  await expect(page.getByTestId('give-phone-given')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('give-phone-done').click();
  await page.waitForURL((u) => u.toString().includes('/mandates'), { timeout: 15_000 });
  await expect(page.getByText('Quotes').first()).toBeVisible({ timeout: 30_000 });
});
