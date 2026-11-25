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
import { test, expect, type Page } from '@playwright/test';
import { titleField, typeTitle } from '../../src/helpers/give-page';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type pg from 'pg';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildEntry, entryHash, signEntry, rootKeyFromRecoveryCode, buildGrant, signObject, objectHash, verifyChain, type ChainEntry } from '@humanagencyp/hap-core/device-keys';
import { decryptProposalContent, type MandatePayload } from '@humanagencyp/hap-core';
import { grantMembersOf } from '../../src/helpers/mandate-grant';
import { newPhone, assertion, phoneSigninBody, type Phone } from '../../src/helpers/phone-passkey';
import { newReadKey } from '../../src/helpers/device-chain';
import { connectDb, enrolmentCode, http, newPerson, nowSec, show, stackFromEnv, until, b64uEncode, type PhoneStack, type Person } from '../../src/helpers/phone-app';
import { expectStampCentred, expectStampCentredAtSizes, expectButtonTextFits } from './stamp-centre';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the gateway page is the same in every browser; one engine is enough here');

const PROFILES_DIR = process.env.HAP_E2E_PROFILES_DIR ?? join(import.meta.dirname, '..', '..', '..', 'hap-profiles');
const PASSWORD = 'correct horse battery staple 42';
const MCP_URL = `http://localhost:${process.env.HAP_E2E_PHONE_GW_MCP_PORT ?? 19944}`;

/** The newest sales profile on disk (what the gateway and the Authority Server load). */
function salesProfileId(): string {
  const dir = join(PROFILES_DIR, 'sales');
  const versions = readdirSync(dir).filter((f) => f.endsWith('.profile.json')).map((f) => f.replace('.profile.json', ''));
  versions.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const v = versions.at(-1)!;
  return JSON.parse(readFileSync(join(dir, `${v}.profile.json`), 'utf8')).id as string;
}

function newestProfileId(area: string): string {
  const dir = join(PROFILES_DIR, area);
  const versions = readdirSync(dir).filter((f) => f.endsWith('.profile.json')).map((f) => f.replace('.profile.json', ''));
  versions.sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  return JSON.parse(readFileSync(join(dir, `${versions.at(-1)!}.profile.json`), 'utf8')).id as string;
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

/** The phone grants the one prepared give it has not granted yet, over exactly what it opened. Returns what it opened.
 *  `done` holds `<mandate id>:<version>`: a change keeps the mandate id and moves the version. */
async function phoneGrantsNext(p: Person, recoveryCode: string, phone: Phone, readPriv: Uint8Array, done: Set<string>, what: string, tamper?: (m: Record<string, any>) => Record<string, any>): Promise<Record<string, any>> {
  const token = await phoneSession(p, recoveryCode, phone);
  const c = await until(`${what} reaches the phone`, async () => {
    const r = await http(stack.asUrl, 'GET', '/api/mandates/prepared', { token });
    for (const row of (r.json?.prepared ?? []) as Array<Record<string, any>>) {
      const opened = await decryptProposalContent(
        { ciphertext: row.ciphertext, encrypted_keys: { [phone.record.key_id]: row.device_key }, readers: [phone.record.key_id], unreadable: [] },
        phone.record.key_id, readPriv,
      );
      const args = opened.arguments as Record<string, any>;
      if (!done.has(`${args.mandate_id}:${args.mandate_version}`)) return args;
    }
    return undefined;
  }, 60_000);
  expect(['grant', 'change']).toContain(c.give.op);
  const members = grantMembersOf(c.give.payload as MandatePayload, { authorizationId: c.give.place.authorization_id, groupId: c.give.place.group_id, replaces: c.give.place.replaces, chainDids: c.give.place.chain_dids });
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const grant = buildGrant({
    op: c.give.op, owner_did: root.did, key_id: phone.record.key_id, chain_seq: state.head.seq, chain_head: state.head.hash,
    mandate_id: c.mandate_id, mandate_version: c.mandate_version, granted_at: nowSec(), nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
  }, tamper ? tamper(members as Record<string, any>) as typeof members : members);
  const stored = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(c.mandate_id)}/grants`, {
    token, body: { grant, sig: await signObject(grant, phone.seed), check: await assertion(phone, await objectHash(grant)) },
  });
  if (!tamper) expect(stored.status, show(stored)).toBe(201);
  done.add(`${c.mandate_id}:${c.mandate_version}`);
  return c;
}

/** Go to a page of the gateway WITHOUT a reload: the page session lives in the page's memory (a reload would lock it). */
async function goInPage(page: Page, path: string): Promise<void> {
  await page.evaluate((to) => { window.history.pushState({}, '', to); window.dispatchEvent(new PopStateEvent('popstate')); }, path);
}

async function callTool(agent: Client, name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const r = await agent.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
  const content = (r.content ?? []) as Array<{ type: string; text?: string }>;
  return { text: content.map((x) => x.text ?? '').join('\n'), isError: r.isError === true };
}

test('a computer without Touch ID: the give page sends the mandate to the phone, waits, and shows "Signed" once the phone gave it', async ({ page }, testInfo) => {
  /** A screenshot of each step of the card path, kept with the run (test-results and the HTML report). */
  const shot = async (name: string) => {
    const path = testInfo.outputPath(`${name}.png`);
    await page.screenshot({ path, fullPage: true });
    await testInfo.attach(name, { path, contentType: 'image/png' });
  };
  test.setTimeout(360_000);
  const p = await newPerson(stack, 'Give on phone');
  const { headers } = await setUpGateway(p);

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

  // DEC-95: a reload ends the page session (the header token lives only in the page's memory). The gateway itself keeps
  // running, so the unlock screen must say that, never "the computer restarted".
  await page.reload();
  await expect(page.locator('#unlock-password')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText('The gateway is still running and your AI can keep working. Unlock to use this page again.')).toBeVisible({ timeout: 10_000 });
  await expect(page.getByText('The computer restarted')).toHaveCount(0);
  await page.screenshot({ path: test.info().outputPath('unlock-after-reload.png'), fullPage: true });
  await test.info().attach('unlock-after-reload', { path: test.info().outputPath('unlock-after-reload.png'), contentType: 'image/png' });
  await page.locator('#unlock-password').fill(PASSWORD);
  await page.locator('#unlock-password').press('Enter');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 20_000 });

  // DEC-96: Devices is its own menu entry (device keys on), and it opens the Devices page with this computer and the phone.
  // The sidebar's link (the mobile menu holds a hidden copy of the same link).
  const devicesLink = page.locator('a[href="/devices"]:visible').first();
  await expect(devicesLink).toBeVisible();
  await page.screenshot({ path: test.info().outputPath('dec96-5-gateway-menu.png'), fullPage: true });
  await devicesLink.click();
  await page.waitForURL((u) => u.pathname === '/devices', { timeout: 10_000 });
  await expect(page.getByText('My phone', { exact: true }).first()).toBeVisible({ timeout: 15_000 });
  await page.screenshot({ path: test.info().outputPath('dec96-6-gateway-devices.png'), fullPage: true });

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
  await typeTitle(page, 'Quotes');
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();

  // This computer cannot give it: the footer offers the phone.
  const send = page.getByTestId('give-phone-send');
  await expect(send).toBeEnabled({ timeout: 30_000 });
  // The button says how it is given (maintainer 2026-11-22), the same words as on the card.
  await expect(send).toHaveText('Give this mandate on your phone');
  await expectButtonTextFits(send, 'give page, phone button');
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
  // The give page ends with the one shared result (whichever device gave it): "Signed", then Close to the mandate list.
  await expect(page.getByTestId('give-done')).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId('give-done').getByText('Signed')).toBeVisible();
  await page.getByTestId('give-done').getByTestId('give-touch-close').click();
  await page.waitForURL((u) => u.toString().includes('/mandates'), { timeout: 15_000 });
  // The list opens on THIS mandate: Close carries its authorization id, and the list marks that card. (The card shows
  // the profile, not the title, so the title is no identity here.)
  expect(new URL(page.url()).searchParams.get('highlight')).toBe(c.give.place.authorization_id);
  await expect(page.locator('[data-testid="mandate-card"].card-highlight')).toHaveCount(1, { timeout: 30_000 });

  // ── An AI-PROPOSED mandate on the same gateway (found on the dev lane 2026-11-20: every one was refused at execution with
  // "nothing was approved under that fingerprint", because the executor's ticket_id was hashed into the approval fingerprint).
  // Same person, same gateway, same phone: one chain gateway per run.
  const granted = new Set<string>([`${c.mandate_id}:${c.mandate_version}`]);
  // 1. The Setup mandate the AI needs: given on the page, granted on the phone (the path above).
  const delegation = newestProfileId('delegation');
  await page.evaluate(({ auth, gate }) => {
    sessionStorage.setItem('agentAuth', JSON.stringify(auth));
    sessionStorage.setItem('agentGate', JSON.stringify(gate));
  }, {
    auth: { profileId: delegation, groupId: personal!.id, groupName: personal!.name ?? null, domain: 'owner', isPersonal: true },
    gate: { bounds: { profile: delegation, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 30 }, context: { allowed_profiles: 'records', allowed_modes: 'review' }, gateContent: { intent: 'The AI prepares the mandates its work needs.' }, ttlConfig: { max: 86400 } },
  });
  await goInPage(page, '/mandates/new/sign');
  await typeTitle(page, 'Setup');
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  await expect(page.getByTestId('give-phone-send')).toBeEnabled({ timeout: 30_000 });
  await page.getByTestId('give-phone-send').click();
  await expect(page.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 30_000 });
  await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the Setup give');
  // The give page ends with the one shared result (whichever device gave it): "Signed", then Close to the mandate list.
  await expect(page.getByTestId('give-done')).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId('give-done').getByText('Signed')).toBeVisible();
  await page.getByTestId('give-done').getByTestId('give-touch-close').click();

  // 2. The AI, over the gateway's own MCP endpoint, proposes a Records mandate.
  const agent = new Client({ name: 'ai-proposed-mandate', version: '1.0.0' }, { capabilities: {} });
  await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  try {
    await until('the Setup mandate is live for the AI', async () => {
      const r = await callTool(agent, 'list-authorizations', {});
      return /delegation@/.test(r.text) ? true : undefined;
    }, 60_000);
    const cardOf = (id: string) => page.locator(`[data-testid="approval-card"][data-proposal-id="${id}"]`);
    const openCard = async (id: string) => {
      // The panel may open by itself and slide over the list; the same card also exists hidden in the list behind it.
      const card = page.locator(`[data-testid="approval-card"][data-proposal-id="${id}"]`).filter({ visible: true });
      for (let k = 0; k < 20 && !(await card.isVisible({ timeout: 2_000 }).catch(() => false)); k++) {
        const next = page.getByTestId('approval-next');
        if (await next.isVisible().catch(() => false)) {
          if (await next.isEnabled().catch(() => false)) { await next.click(); continue; }
          await page.getByTestId('approval-later').click().catch(() => undefined);
        }
        await goInPage(page, '/approvals');
        await page.waitForTimeout(1_500);
        const row = page.locator(`[data-testid="approval-row"][data-proposal-id="${id}"] button`).first();
        if (!(await card.isVisible().catch(() => false)) && (await row.isVisible({ timeout: 3_000 }).catch(() => false))) await row.click({ timeout: 5_000 }).catch(() => undefined);
      }
      await expect(card).toBeVisible({ timeout: 30_000 });
      return card;
    };

    // 3. FAILURE first: a give the phone grants over OTHER values. The card shows the refusal (or keeps waiting), never "Signed".
    const bad = await callTool(agent, 'setup__create_mandate', {
      profile: 'records', limits: { read_access: 'unlimited', write_daily_max: 10, delete_access: 'none', archive_access: 'none' },
      intent: 'Keep a few notes.', mode: 'review', duration_hours: 24, title: 'Few notes',
    });
    const badId = /Proposal ID: (\S+?)\./.exec(bad.text)?.[1];
    expect(badId, bad.text).toBeTruthy();
    const badCard = await openCard(badId!);
    await shot('f1-card-before');
    const badUrl = page.url();
    await badCard.getByTestId('btn-approve').click();
    await expect(badCard.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 60_000 });
    expect(page.url()).toBe(badUrl);
    await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the give to refuse', (m) => ({ ...m, bounds_hash: `sha256:${'0'.repeat(64)}` }));
    // The refusal is a result that stays (DEC-88): the reason at the top of the card, the mandate readable below it, ONE full-width
    // pinned button. Never "Signed".
    const refusedTop = badCard.getByTestId('card-give-refused');
    await expect(refusedTop).toBeVisible({ timeout: 60_000 });
    await expect(refusedTop).toContainText('does not match');
    await expect(badCard.locator('article.av3-body')).not.toHaveAttribute('aria-hidden', 'true');
    await expect(badCard.getByText('Keep a few notes.').first()).toBeVisible();
    const top = await refusedTop.boundingBox();
    const bodyText = await badCard.getByText('Keep a few notes.').first().boundingBox();
    expect(top && bodyText && top.y < bodyText.y, 'the reason sits above the mandate').toBe(true);
    const closeBtn = badCard.getByTestId('result-dismiss');
    await expect(closeBtn).toBeVisible();
    await expect(badCard.locator('footer.av3-foot button')).toHaveCount(1);
    const foot = await badCard.locator('footer.av3-foot').boundingBox();
    const btn = await closeBtn.boundingBox();
    expect(foot && btn && btn.width >= foot.width * 0.85, 'one full-width button').toBe(true);
    await shot('f2-card-after-wrong-grant');
    await expect(badCard.getByTestId('give-touch-given')).toHaveCount(0);
    await expect(badCard.getByTestId('give-phone-given')).toHaveCount(0);
    await expect(badCard.getByText('Signed')).toHaveCount(0);
    // The person closes the failed give (back to the card's buttons) and rejects that proposal, so the next one comes up.
    await closeBtn.click();
    await expect(badCard.getByTestId('btn-reject')).toBeVisible({ timeout: 15_000 });
    await badCard.getByTestId('btn-reject').click();
    await expect(cardOf(badId!)).toHaveCount(0, { timeout: 30_000 });

    // 4. SUCCESS: the AI proposes; the person presses "Give this mandate" ON THE CARD. The give runs in place: same URL, no edit form,
    //    the give's own footer on the card. This computer has no check key (CI has no native helper), so it goes to the phone (DEC-90).
    const proposed = await callTool(agent, 'setup__create_mandate', {
      profile: 'records', limits: { read_access: 'unlimited', write_daily_max: 50, delete_access: 'none', archive_access: 'none' },
      intent: 'Keep the notes of the quotes.', mode: 'review', duration_hours: 24, title: 'Notes',
    });
    expect(proposed.isError, proposed.text).toBe(false);
    const proposalId = /Proposal ID: (\S+?)\./.exec(proposed.text)?.[1];
    expect(proposalId, proposed.text).toBeTruthy();
    const card = await openCard(proposalId!);
    // The summary line under the title: every value with the profile's own label (UI review; generic from the schema).
    const summary = card.getByTestId('mandate-summary');
    await expect(summary).toBeVisible();
    await expect(summary).toContainText(':');
    expect(await summary.textContent(), 'no bare values').not.toMatch(/^none · none/);
    // No check key here: the card's button says the mandate is given on the phone (maintainer 2026-11-22).
    await expect(card.getByTestId('btn-approve')).toHaveText('Give this mandate on your phone', { timeout: 30_000 });
    await expectButtonTextFits(card.getByTestId('btn-approve'), 'card, phone give button');
    await shot('s1-card-before');
    const urlBefore = page.url();
    await card.getByTestId('btn-approve').click();
    await expect(card.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 60_000 });
    await shot('s2-card-waiting-for-phone');
    expect(page.url(), 'the give runs on the card, no navigation').toBe(urlBefore);
    await expect(titleField(page), 'no edit form').toHaveCount(0);

    // 5. The phone grants exactly what the AI proposed and the card showed.
    const opened2 = await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the AI-proposed give');
    expect(opened2.give.bounds.write_daily_max).toBe(50);
    expect(opened2.intent).toBe('Keep the notes of the quotes.');
    await expect(card.getByTestId('give-touch-given')).toBeVisible({ timeout: 60_000 });
    await expect(card.getByTestId('give-touch-given').getByText('Signed')).toBeVisible();
    await shot('s3-card-given');
    // The stamp sits in the middle of the card above Close, not at its bottom (maintainer, dev test 2026-11-22).
    await expectStampCentredAtSizes(page, card.getByTestId('give-touch-given').locator('.av3-stamp'), 'card, given on the phone', shot, 's3-stamp');
    expect(page.url()).toBe(urlBefore);
    // The person closes the result, as on the dev lane (the card stays with its stamp until Close, DEC-88).
    await card.getByTestId('give-touch-close').click();
    await expect(cardOf(proposalId!).filter({ visible: true })).toHaveCount(0, { timeout: 30_000 });

    // The proposal is closed as replaced by the person's own mandate (never executed as a second one), and nothing was refused.
    const closed = await until('the proposal is closed', async () => {
      const r = await callTool(agent, 'check-pending-commitments', { proposal_id: proposalId });
      return /pending|awaiting/i.test(r.text) ? undefined : r;
    }, 60_000);
    expect(closed.text).not.toMatch(/nothing was approved under that fingerprint|setup refused to run it/);

    // 6. The mandate is listed under Mandates and live for the AI (the MCP server lists only mandates whose owner's grant it verified).
    await goInPage(page, '/mandates');
    await expect(page.getByText('Notes').first()).toBeVisible({ timeout: 30_000 });
    await shot('s4-mandates-list');
    await until('the Records mandate is live for the AI', async () => {
      const r = await callTool(agent, 'list-authorizations', {});
      return /records@/.test(r.text) ? true : undefined;
    }, 90_000);

    // 7. An AI-proposed CHANGE, given ONLY on the phone (dev lane 2026-11-23: approved on the phone, the change proposal was executed
    //    and refused — "setup refused to run it" — and the mandate stayed as it was). Nothing is pressed on this computer.
    const notesId = await until('the Records mandate id', async () => {
      const r = await callTool(agent, 'list-authorizations', { domain: 'records' });
      return /Mandate id: (authz_[0-9a-f-]{36})/.exec(r.text)?.[1];
    }, 60_000);
    const asked = await callTool(agent, 'setup__change_mandate', {
      mandate_id: notesId, limits: { archive_access: 'allowed' }, intent: 'Keep the notes of the quotes. Archive test notes once done.',
    });
    expect(asked.isError, asked.text).toBe(false);
    const changeId = /Proposal ID: (\S+?)\./.exec(asked.text)?.[1];
    expect(changeId, asked.text).toBeTruthy();
    // On this computer the card offers only the give (this computer has no check key: on the phone), never an Approve that would run it.
    const changeCard = await openCard(changeId!);
    await expect(changeCard.getByTestId('btn-approve')).toHaveText('Give this mandate on your phone', { timeout: 30_000 });
    await shot('c1-change-card-on-computer');

    // The phone already holds the changed mandate: prepared by the gateway when the proposal arrived, naming it, with the version it
    // continues (the phone shows the old value crossed out from that). The phone gives it with its touch.
    const changeGive = await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the AI-proposed change');
    expect(changeGive.give.op).toBe('change');
    expect(changeGive.give.proposal_id).toBe(changeId);
    expect(changeGive.give.bounds.archive_access).toBe('allowed');
    expect(changeGive.give.previous?.bounds?.archive_access).toBe('none');
    expect(changeGive.intent).toBe('Keep the notes of the quotes. Archive test notes once done.');

    // The computer takes the phone's grant in (it checks every second while a give waits), puts the change in force and closes the
    // AI's request as `replaced` itself: the card on the computer is gone within 3 s (dev lane 2026-11-23: it stayed ~10 s).
    // Measured: grant stored -> request closed at the Authority Server -> card gone on the computer.
    const tGranted = Date.now();
    const cardGone = expect(cardOf(changeId!).filter({ visible: true })).toHaveCount(0, { timeout: 10_000 }).then(() => Date.now() - tGranted);
    const phoneToken = await phoneSession(p, sb.recoveryCode, phone);
    let closedMs = -1;
    const closedWatch = (async () => {
      while (Date.now() - tGranted < 15_000) {
        const g = await http(stack.asUrl, 'GET', `/api/proposals/${encodeURIComponent(changeId!)}`, { token: phoneToken });
        if (g.status === 200 && (g.json.proposal as Record<string, any>).status !== 'pending') { closedMs = Date.now() - tGranted; return; }
        await new Promise((r) => setTimeout(r, 100));
      }
    })();
    const goneMs = await cardGone;
    await closedWatch;
    test.info().annotations.push({ type: 'grant-to-closed-ms', description: String(closedMs) }, { type: 'grant-to-card-gone-ms', description: String(goneMs) });
    console.log(`[GIVE-TIMING] grant -> request closed: ${closedMs} ms; grant -> computer card gone: ${goneMs} ms`);
    expect(goneMs, `the computer card was gone ${goneMs} ms after the grant (closed at ${closedMs} ms)`).toBeLessThanOrEqual(3_000);
    await until('the changed mandate is live for the AI', async () => {
      const r = await callTool(agent, 'list-authorizations', { domain: 'records' });
      return /archive_access: allowed/.test(r.text) ? r : undefined;
    }, 30_000);
    // The request is already closed when the phone would close it (the app then leaves it as it is).
    const token = await phoneSession(p, sb.recoveryCode, phone);
    const got = await http(stack.asUrl, 'GET', `/api/proposals/${encodeURIComponent(changeId!)}`, { token });
    expect(got.status, show(got)).toBe(200);
    expect((got.json.proposal as Record<string, any>).status).not.toBe('pending');

    // The Approvals list and the nav badge say the same, at the same moment (dev lane 2026-11-23: "Nothing waiting" beside a 1).
    await goInPage(page, '/approvals');
    await expect(page.getByTestId('queue-empty')).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId('nav-count-proposals')).toHaveCount(0, { timeout: 2_000 });
    await shot('c2-computer-after-phone-gave');
    // The AI hears that ITS change is in force, with the new mandate's id — never "the person signed their own version".
    const changeClosed = await until('the change proposal is closed', async () => {
      const r = await callTool(agent, 'check-pending-commitments', { proposal_id: changeId });
      return /pending|awaiting/i.test(r.text) ? undefined : r;
    }, 60_000);
    expect(changeClosed.text).not.toMatch(/setup refused to run it|nothing was done|own version/);
    expect(changeClosed.text).toMatch(new RegExp(`Proposal ${changeId} was GIVEN: the person gave the change you proposed with their touch, exactly as proposed\\. It is in force now as authz_[0-9a-f-]{36}\\.`));

    // ── On hold (approved mockup v2, DEC-109/110/111): what the gateway holds back, each card with its button. Provoked in the
    // throwaway database (seams): the Quotes mandate's grants removed ("given without your touch"); the Setup mandate's stored grant
    // altered ("does not match what you confirmed", the alarm). The verdicts are the gateway's own.
    const quotesAuthz = c.give.place.authorization_id as string;
    const quotesMandate = c.mandate_id as string;
    const setupRow = (await db.query(
      `select authorization_id, mandate_id from mandate_grants where user_id = $1 and mandate_id <> $2 and op in ('grant','change')
         and authorization_id in (select authorization_id from mandate_grants g2 where g2.user_id = $1) order by stored_at asc limit 1`,
      [p.userId, quotesMandate],
    )).rows[0] as { authorization_id: string; mandate_id: string };
    expect(setupRow, 'a second mandate to tamper with').toBeTruthy();
    await db.query(`delete from mandate_grants where authorization_id = $1`, [quotesAuthz]);
    // The Setup mandate's stored grant now names another authorization (what the server holds is not what was granted): the
    // gateway's own check refuses it as `grant_other_authorization`. (The sealed body is kept on the computer once read, so a
    // server-side body swap would not reach the check.)
    await db.query(
      `update mandate_grants set "grant" = jsonb_set("grant", '{authorization_id}', to_jsonb('authz_00000000-0000-4000-8000-000000000000'::text)) where mandate_id = $1`,
      [setupRow.mandate_id],
    );
    const heldNow = async () => {
      await fetch(`${gw}/resync-gates`, { method: 'POST', headers }).catch(() => undefined);
      const r = await fetch(`${gw}/api/mandate/held-back`, { headers });
      return r.ok ? ((await r.json()) as { held: Array<{ authorizationId: string; code: string; workspace?: string; ownerIsYou: boolean }> }).held : [];
    };
    const verdicts = await until('the gateway holds both back', async () => {
      const h = await heldNow();
      return h.some((x) => x.authorizationId === quotesAuthz) && h.some((x) => x.authorizationId === setupRow.authorization_id) ? h : undefined;
    }, 90_000);
    test.info().annotations.push({ type: 'held-verdicts', description: JSON.stringify(verdicts) });
    await goInPage(page, '/mandates');
    const touchCard = page.locator('[data-testid="held-card"][data-reason="touch_missing"]');
    await expect(touchCard).toBeVisible({ timeout: 30_000 });
    await expect(touchCard.getByTestId('held-reason')).toHaveText('This was given without your touch. Give it again so your AI can use it.');
    await expect(touchCard.getByTestId('held-give-again')).toHaveText('Give again');
    await expect(touchCard.getByTestId('held-end')).toHaveCount(0);
    const alarmCard = page.locator('[data-testid="held-card"][data-reason="alarm"]');
    await expect(alarmCard).toBeVisible({ timeout: 30_000 });
    await expect(alarmCard.getByTestId('held-reason')).toHaveText('✕ This mandate does not match what you confirmed.');
    // A Personal workspace: no admin line.
    await expect(alarmCard.getByTestId('held-step')).toHaveText('Your AI cannot use it. If you did not change it yourself, end it.');
    await expect(alarmCard.getByTestId('held-give-again')).toBeVisible();
    await expect(alarmCard.getByTestId('held-end')).toBeVisible();
    await expect(page.getByText('On hold: Your AI cannot use these yet')).toBeVisible();
    // The card carries the mandate's own title; a mandate on hold is not also listed or counted as Active (only Notes is).
    await expect(touchCard.locator('strong').first()).toHaveText('Quotes');
    await expect(alarmCard.locator('strong').first()).toHaveText('Setup');
    await expect(page.getByText(/^Active \(1\)$/)).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('[data-testid="mandate-card"]').filter({ hasText: 'Quotes' })).toHaveCount(0);
    await page.getByTestId('held-list').scrollIntoViewIfNeeded();
    await shot('h1-on-hold-desktop');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByTestId('held-list').scrollIntoViewIfNeeded();
    await shot('h2-on-hold-phone-width');
    await page.setViewportSize({ width: 1280, height: 900 });
    // End on the alarm card opens the gateway's End screen for that mandate (Keep leaves it).
    await alarmCard.getByTestId('held-end').click();
    await expect(page.getByTestId('end-mandate')).toBeVisible({ timeout: 15_000 });
    await shot('h3-on-hold-end');
    await page.getByTestId('end-keep').click();
    await expect(page.getByTestId('end-mandate')).toHaveCount(0, { timeout: 15_000 });
    // Give again (touch missing): the give flow opens with ONLY what this gateway verified when it was given — the intent —
    // and none of the server's limits; it replaces the held mandate once given.
    await goInPage(page, '/mandates');
    await expect(touchCard).toBeVisible({ timeout: 30_000 });
    await touchCard.getByTestId('held-give-again').click();
    await page.waitForURL((u) => u.pathname === '/mandates/new/intent', { timeout: 15_000 });
    const handed = await page.evaluate(() => ({ gate: JSON.parse(sessionStorage.getItem('agentGate') ?? '{}'), replaces: sessionStorage.getItem('agentEditReplaces') }));
    expect(handed.replaces).toBe(quotesAuthz);
    expect(handed.gate.gateContent?.intent).toBe('Quotes wait two days.');
    expect(Object.keys(handed.gate.bounds ?? {}).filter((k) => k !== 'profile')).toEqual([]);
    await shot('h4-give-again-opened');
  } finally {
    await agent.close().catch(() => undefined);
  }
});
