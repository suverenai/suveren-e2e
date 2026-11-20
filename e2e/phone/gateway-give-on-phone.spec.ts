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
 *   - The give page is opened with the wizard's hand-over (sessionStorage `agentAuth` / `agentGate`) set by the test; the wizard
 *     itself is covered by the default browser suite.
 *
 * Not covered: a connector's tool call under the phone-given mandate (this gateway runs no connector); the mandate is shown as
 * live in the gateway's own list, which the MCP server fills only with mandates whose owner's grant it verified.
 */
import { test, expect, type Page } from '@playwright/test';
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

/** The phone grants the one prepared give it has not granted yet, over exactly what it opened. Returns what it opened. */
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
      if (!done.has(args.mandate_id)) return args;
    }
    return undefined;
  }, 60_000);
  expect(c.give.op).toBe('grant');
  const members = grantMembersOf(c.give.payload as MandatePayload, { authorizationId: c.give.place.authorization_id, groupId: c.give.place.group_id, replaces: c.give.place.replaces, chainDids: c.give.place.chain_dids });
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const grant = buildGrant({
    op: 'grant', owner_did: root.did, key_id: phone.record.key_id, chain_seq: state.head.seq, chain_head: state.head.hash,
    mandate_id: c.mandate_id, mandate_version: c.mandate_version, granted_at: nowSec(), nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
  }, tamper ? tamper(members as Record<string, any>) as typeof members : members);
  const stored = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(c.mandate_id)}/grants`, {
    token, body: { grant, sig: await signObject(grant, phone.seed), check: await assertion(phone, await objectHash(grant)) },
  });
  if (!tamper) expect(stored.status, show(stored)).toBe(201);
  done.add(c.mandate_id);
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
  // In-page: a reload drops the page session (it lives in the page), and the unlock screen would show.
  await goInPage(page, "/mandates/new/sign");
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
  // One result screen after a give, on the phone path too (DEC-86/88, changed 2026-11-20): the gateway's stamp, then Close.
  const stamp = page.getByTestId('give-touch-given');
  await expect(stamp).toBeVisible({ timeout: 60_000 });
  await expect(stamp.getByText('Signed')).toBeVisible();
  await page.getByTestId('give-touch-close').click();
  await page.waitForURL((u) => u.toString().includes('/mandates'), { timeout: 15_000 });
  await expect(page.getByText('Quotes').first()).toBeVisible({ timeout: 30_000 });

  // ── An AI-PROPOSED mandate on the same gateway (found on the dev lane 2026-11-20: every one was refused at execution with
  // "nothing was approved under that fingerprint", because the executor's ticket_id was hashed into the approval fingerprint).
  // Same person, same gateway, same phone: one chain gateway per run.
  const granted = new Set<string>([c.mandate_id]);
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
  await page.locator('input[placeholder*="e.g."]').fill('Setup');
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  await expect(page.getByTestId('give-phone-send')).toBeEnabled({ timeout: 30_000 });
  await page.getByTestId('give-phone-send').click();
  await expect(page.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 30_000 });
  await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the Setup give');
  await expect(page.getByTestId('give-touch-given')).toBeVisible({ timeout: 60_000 });
  await page.getByTestId('give-touch-close').click();

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
      const card = cardOf(id);
      // The panel opens by itself when the setting is on; otherwise the card is on the Approvals page.
      if (!(await card.isVisible({ timeout: 15_000 }).catch(() => false))) await goInPage(page, '/approvals');
      await expect(card).toBeVisible({ timeout: 60_000 });
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
    await expect.poll(async () => (await badCard.getByTestId('give-phone-refused').isVisible()) || (await badCard.getByTestId('give-phone-waiting').isVisible()), { timeout: 30_000 }).toBe(true);
    await page.waitForTimeout(8_000);
    await shot('f2-card-after-wrong-grant');
    await expect(badCard.getByTestId('give-touch-given')).toHaveCount(0);
    await expect(badCard.getByTestId('give-phone-given')).toHaveCount(0);
    await expect(badCard.getByText('Signed')).toHaveCount(0);
    if (await badCard.getByTestId('give-phone-stop').isVisible().catch(() => false)) await badCard.getByTestId('give-phone-stop').click();

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
    await shot('s1-card-before');
    const urlBefore = page.url();
    await card.getByTestId('btn-approve').click();
    await expect(card.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 60_000 });
    await shot('s2-card-waiting-for-phone');
    expect(page.url(), 'the give runs on the card, no navigation').toBe(urlBefore);
    await expect(page.locator('input[placeholder*="e.g."]'), 'no edit form').toHaveCount(0);

    // 5. The phone grants exactly what the AI proposed and the card showed.
    const opened2 = await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the AI-proposed give');
    expect(opened2.give.bounds.write_daily_max).toBe(50);
    expect(opened2.intent).toBe('Keep the notes of the quotes.');
    await expect(card.getByTestId('give-touch-given')).toBeVisible({ timeout: 60_000 });
    await expect(card.getByTestId('give-touch-given').getByText('Signed')).toBeVisible();
    await shot('s3-card-given');
    expect(page.url()).toBe(urlBefore);

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
  } finally {
    await agent.close().catch(() => undefined);
  }
});
