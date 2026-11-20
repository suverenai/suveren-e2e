/**
 * A passkey for the suveren.ai dashboard (AS step 17), approved on one of the person's devices — against the REAL stack: the real
 * Authority Server (dashboard address = its own, test opt-in for http on localhost), a real gateway with the switch on, a real
 * browser on the dashboard (a CDP virtual authenticator makes and uses the passkey) and on the gateway page.
 *
 * What is real: the dashboard's "Create a passkey" and its code; the Authority Server's list of waiting passkeys; the gateway page's
 * Devices row and the shared card (packages/approval-card DashboardPasskeyCard) showing the same code; the approval checked by the
 * Authority Server; the dashboard sign-in with the approved passkey.
 *
 * What the test plays itself: the PHONE that approves (its device key and a WebAuthn assertion at the app's origin, as the app does;
 * the app's own card is the shared component, unit-tested in packages/approval-card and apps/approve). This CI gateway has no check
 * key (no native helper in CI), so its card must say "approve on your phone" — that is asserted. The phone joins the chain by a
 * root-signed `add` written into the throwaway database (the same seam as gateway-give-on-phone.spec.ts).
 *
 * Screenshots of every step are attached to the report.
 */
import { test, expect, type Page, type TestInfo } from '@playwright/test';
import type pg from 'pg';
import { buildEntry, entryHash, signEntry, rootKeyFromRecoveryCode, signObject, objectHash, verifyChain, type ChainEntry } from '@humanagencyp/hap-core/device-keys';
import { newPhone, assertion, phoneSigninBody, type Phone } from '../../src/helpers/phone-passkey';
import { connectDb, enrolmentCode, http, newPerson, nowSec, show, stackFromEnv, until, type PhoneStack, type Person } from '../../src/helpers/phone-app';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the CDP virtual authenticator is Chromium only');

const PASSWORD = 'correct horse battery staple 42';
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

let shot = 0;
async function snap(page: Page, info: TestInfo, name: string): Promise<void> {
  shot += 1;
  await info.attach(`${String(shot).padStart(2, '0')}-${name}`, { body: await page.screenshot({ fullPage: true }), contentType: 'image/png' });
}

async function chainEntries(userId: string): Promise<ChainEntry[]> {
  const r = await db.query(`select entry from device_chain_entries where user_id = $1 order by seq`, [userId]);
  return r.rows.map((x: { entry: ChainEntry }) => x.entry);
}

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

async function phoneSession(p: Person, recoveryCode: string, phone: Phone): Promise<string> {
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const ch = await http(stack.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: phone.record.key_id } });
  expect(ch.status, show(ch)).toBe(200);
  const s = await http(stack.asUrl, 'POST', '/api/devices/session', { body: await phoneSigninBody(root, phone, state.head, ch.json) });
  expect(s.status, show(s)).toBe(200);
  return s.json.token as string;
}

test('a dashboard passkey: made on the dashboard, shown with the same code on the gateway page, approved by a device, then it signs in', async ({ browser }, info) => {
  test.setTimeout(240_000);
  const p = await newPerson(stack, 'Dashboard passkey');

  // The gateway: account key once, unlock password, set-up (no check key: CI has no native helper).
  const login = await fetch(`${gw}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': p.apiKey }, body: '{}' });
  expect(login.status, await login.clone().text()).toBe(200);
  const set = await fetch(`${gw}/auth/password/set`, { method: 'POST', headers: { 'content-type': 'application/json', origin: gw, 'x-api-key': p.apiKey }, body: JSON.stringify({ password: PASSWORD }) });
  const sbody = (await set.json()) as { sessionToken?: string };
  expect(set.status, JSON.stringify(sbody)).toBe(200);
  const cookie = /suveren_page_session=([^;]+)/.exec(set.headers.get('set-cookie') ?? '')?.[1];
  const headers = { 'content-type': 'application/json', origin: gw, cookie: `suveren_page_session=${cookie}`, 'x-suveren-session': sbody.sessionToken! };
  const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office PC' }) });
  const sb = (await start.json()) as { setupId: string; recoveryCode: string };
  expect(start.status, JSON.stringify(sb)).toBe(200);
  const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
  expect(fin.status, await fin.clone().text()).toBe(200);
  const phone = await newPhone(stack.appUrl, 'My phone');
  await admitPhone(p, sb.recoveryCode, phone);

  // 1. The dashboard: sign in with the API key, make a passkey with a virtual authenticator, read the code it shows.
  const dashCtx = await browser.newContext();
  const dash = await dashCtx.newPage();
  const cdp = await dashCtx.newCDPSession(dash);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await dash.goto(`${stack.asUrl}/login`);
  await dash.locator('#apiKey').fill(p.apiKey);
  await dash.getByRole('button', { name: 'Sign in', exact: true }).click();
  await dash.waitForURL((u) => u.pathname.startsWith('/dashboard'), { timeout: 30_000 });
  await dash.goto(`${stack.asUrl}/dashboard/passkeys`);
  await snap(dash, info, 'dashboard-passkey-page');
  await dash.getByRole('button', { name: 'Create a passkey' }).click();
  const codeEl = dash.getByTestId('passkey-code');
  await expect(codeEl).toBeVisible({ timeout: 30_000 });
  const code = (await codeEl.innerText()).replace(/\s+/g, '');
  expect(code).toMatch(/^[0-9]{6}$/);
  await snap(dash, info, 'dashboard-shows-code');

  // 2. The gateway page: unlock, open Devices (in-app), the row, the shared card with the SAME code; no check key → "approve on your phone".
  const gwPage = await (await browser.newContext()).newPage();
  await gwPage.goto(gw);
  await gwPage.locator('#unlock-password').fill(PASSWORD);
  await gwPage.locator('#unlock-password').press('Enter');
  await expect(gwPage.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
  await gwPage.evaluate(() => { window.history.pushState({}, '', '/devices'); window.dispatchEvent(new PopStateEvent('popstate')); });
  await expect(gwPage.getByTestId('passkey-waiting-row')).toBeVisible({ timeout: 30_000 });
  await snap(gwPage, info, 'gateway-devices-row');
  const urlBefore = gwPage.url();
  await gwPage.getByTestId('passkey-open').click();
  await expect(gwPage.getByTestId('passkey-card')).toBeVisible();
  expect(gwPage.url()).toBe(urlBefore);
  expect((await gwPage.getByTestId('passkey-card-code').innerText()).replace(/\s+/g, '')).toBe(code);
  await expect(gwPage.getByTestId('passkey-card-account')).toBeVisible();
  await expect(gwPage.getByTestId('passkey-no-check')).toBeVisible();
  await expect(gwPage.getByTestId('passkey-approve')).toHaveCount(0);
  await snap(gwPage, info, 'gateway-card-same-code-no-touch-id');

  // Not yet approved: the passkey cannot sign in.
  // 3. The phone approves: the list names the same request and code; signed with its key and its passkey check.
  const token = await phoneSession(p, sb.recoveryCode, phone);
  const listed = await until('the passkey is listed for the phone', async () => {
    const r = await http(stack.asUrl, 'GET', '/api/passkeys/register/pending', { token });
    return (r.json?.pending ?? []).find((x: { code: string }) => x.code === code);
  });
  const root = await rootKeyFromRecoveryCode(sb.recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const register = {
    typ: 'suveren-passkey-register', v: 1, root_did: root.did, key_id: phone.record.key_id, chain_seq: state.head.seq, chain_head: state.head.hash,
    request_id: listed.request_id, cred_id: listed.cred_id, rp_id: listed.rp_id, issued_at: nowSec(),
  };
  const ok = await http(stack.asUrl, 'POST', '/api/passkeys/register', {
    token, body: { register, sig: await signObject(register as never, phone.seed), check: await assertion(phone, await objectHash(register as never)) },
  });
  expect(ok.status, show(ok)).toBe(201);

  // The gateway page: the request is no longer waiting.
  await gwPage.getByRole('button', { name: 'Close' }).click();
  await expect(gwPage.getByTestId('passkey-waiting-row')).toHaveCount(0, { timeout: 30_000 });
  await snap(gwPage, info, 'gateway-row-gone-after-approval');

  // 4. The dashboard: sign out, sign in with the approved passkey (the same virtual authenticator).
  await dashCtx.clearCookies();
  await dash.goto(`${stack.asUrl}/login`);
  await dash.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await dash.waitForURL((u) => u.pathname.startsWith('/dashboard'), { timeout: 30_000 });
  await snap(dash, info, 'dashboard-signed-in-with-passkey');
});
