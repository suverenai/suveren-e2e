/**
 * A mandate the AI PROPOSES (setup__create_mandate) on a gateway with a device chain, approved by the person on the card, against the
 * REAL stack: the chain gateway of e2e/phone/global-setup.ts (switch on, no check key: CI has no native helper), the real Authority
 * Server, the real gateway page in a real browser, the real MCP server over its own SSE endpoint as the AI.
 *
 * Found on the dev lane (2026-11-20): every AI-proposed mandate was refused at execution with "nothing was approved under that
 * fingerprint". The committed executor adds `ticket_id` to the arguments before the setup tool runs, and the tool hashed them WITH it,
 * so the fingerprint it named never equalled the one the person signed. This journey goes the whole way: proposal → the person
 * approves on the card (a device-signed decision) → execution names the approved fingerprint → this computer has no check key, so the
 * grant goes to the phone (DEC-90) → the phone grants exactly what was approved → the mandate is live for the AI.
 *
 * What the test plays itself, as gateway-give-on-phone.spec.ts does: the PHONE (key, reading key, passkey), and its joining of the
 * chain (a root-signed `add` written into the throwaway database). The Setup (delegation) mandate the AI needs is given through the
 * gateway page's give screen and granted on the phone, the same path.
 *
 * Not covered: a connector's tool call under the new mandate (this gateway runs no connector); the mandate is checked as live in the
 * MCP server's own list, which holds only mandates whose owner's grant it verified.
 */
import { test, expect, type Page } from '@playwright/test';
import type pg from 'pg';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
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
const MCP_URL = `http://localhost:${process.env.HAP_E2E_PHONE_GW_MCP_PORT ?? 19944}`;
const PASSWORD = 'correct horse battery staple 42';

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

/** The phone grants the one prepared give it has not granted yet, over exactly what it opened. Returns what it opened. */
async function phoneGrantsNext(p: Person, recoveryCode: string, phone: Phone, readPriv: Uint8Array, done: Set<string>, what: string): Promise<Record<string, any>> {
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
  });
  expect(c.give.op).toBe('grant');
  const members = grantMembersOf(c.give.payload as MandatePayload, { authorizationId: c.give.place.authorization_id, groupId: c.give.place.group_id, replaces: c.give.place.replaces, chainDids: c.give.place.chain_dids });
  const root = await rootKeyFromRecoveryCode(recoveryCode);
  const state = await verifyChain({ expectedRootDid: root.did, entries: await chainEntries(p.userId) });
  const grant = buildGrant({
    op: 'grant', owner_did: root.did, key_id: phone.record.key_id, chain_seq: state.head.seq, chain_head: state.head.hash,
    mandate_id: c.mandate_id, mandate_version: c.mandate_version, granted_at: nowSec(), nonce: b64uEncode(crypto.getRandomValues(new Uint8Array(16))),
  }, members);
  const stored = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(c.mandate_id)}/grants`, {
    token, body: { grant, sig: await signObject(grant, phone.seed), check: await assertion(phone, await objectHash(grant)) },
  });
  expect(stored.status, show(stored)).toBe(201);
  done.add(c.mandate_id);
  return c;
}

async function callTool(agent: Client, name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const r = await agent.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
  const content = (r.content ?? []) as Array<{ type: string; text?: string }>;
  return { text: content.map((x) => x.text ?? '').join('\n'), isError: r.isError === true };
}

async function giveOnPage(page: Page, headers: Record<string, string>, profileId: string, bounds: Record<string, unknown>, context: Record<string, unknown>, intent: string, title: string): Promise<void> {
  const groups = await (await fetch(`${gw}/api/groups`, { headers })).json() as { groups?: Array<{ id: string; name?: string; isPersonal?: boolean }> };
  const personal = (groups.groups ?? []).find((g) => g.isPersonal);
  expect(personal, JSON.stringify(groups)).toBeTruthy();
  await page.evaluate(({ auth, gate }) => {
    sessionStorage.setItem('agentAuth', JSON.stringify(auth));
    sessionStorage.setItem('agentGate', JSON.stringify(gate));
  }, {
    auth: { profileId, groupId: personal!.id, groupName: personal!.name ?? null, domain: 'owner', isPersonal: true },
    gate: { bounds: { profile: profileId, ...bounds }, context, gateContent: { intent }, ttlConfig: { max: 86400 } },
  });
  await page.goto(`${gw}/mandates/new/sign`);
  await page.locator('input[placeholder*="e.g."]').fill(title);
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  const send = page.getByTestId('give-phone-send');
  await expect(send).toBeEnabled({ timeout: 30_000 });
  await send.click();
  await expect(page.getByTestId('give-phone-waiting')).toBeVisible({ timeout: 30_000 });
}

test('an AI-proposed mandate: approved on the card, executed under the approved fingerprint, granted on the phone, live for the AI', async ({ page }) => {
  test.setTimeout(300_000);
  const p = await newPerson(stack, 'AI proposes');
  const { headers } = await setUpGateway(p);

  const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office PC' }) });
  const sb = (await start.json()) as { setupId: string; recoveryCode: string };
  expect(start.status, JSON.stringify(sb)).toBe(200);
  const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
  expect(fin.status, await fin.clone().text()).toBe(200);

  const phone = await newPhone(stack.appUrl, 'My phone');
  const read = newReadKey();
  phone.record.read_pub = b64uEncode(read.pub);
  await admitPhone(p, sb.recoveryCode, phone);
  const granted = new Set<string>();

  await page.goto(gw);
  await page.locator('#unlock-password').fill(PASSWORD);
  await page.locator('#unlock-password').press('Enter');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 20_000 });

  // 1. The Setup mandate the AI needs to propose mandates: given on the page, granted on the phone.
  await giveOnPage(page, headers, newestProfileId('delegation'),
    { read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 30 },
    { allowed_profiles: 'sales', allowed_modes: 'automatic' }, 'The AI prepares the mandates its work needs.', 'Setup');
  await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the Setup give');
  await expect(page.getByTestId('give-phone-given')).toBeVisible({ timeout: 60_000 });

  // 2. The AI, over the gateway's own MCP endpoint, proposes a sales mandate.
  const agent = new Client({ name: 'ai-proposed-mandate', version: '1.0.0' }, { capabilities: {} });
  await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  try {
    await until('the Setup mandate is live for the AI', async () => {
      const r = await callTool(agent, 'list-authorizations', {});
      return /delegation@/.test(r.text) && /Active authorizations/.test(r.text) ? true : undefined;
    });
    const salesLimits = { read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const proposed = await callTool(agent, 'setup__create_mandate', {
      profile: 'sales', limits: salesLimits, scope: { currency: 'EUR' }, intent: 'Follow up quotes for existing customers.', mode: 'automatic', duration_hours: 24, title: 'Quotes',
    });
    expect(proposed.isError, proposed.text).toBe(false);
    const proposalId = /Proposal ID: (\S+?)\./.exec(proposed.text)?.[1];
    expect(proposalId, proposed.text).toBeTruthy();

    // 3. The person approves it on the card (the gateway signs the decision with this computer's device key).
    await page.goto(gw);
    const approve = page.getByTestId('btn-approve');
    await expect(approve).toBeVisible({ timeout: 60_000 });
    await approve.click();
    await until('the approval is committed', async () => {
      const r = await callTool(agent, 'check-pending-commitments', { proposal_id: proposalId });
      return /approved|committed|phone|Mandate created/i.test(r.text) ? r : undefined;
    }, 60_000);

    // 4. Execution names the approved fingerprint: no "nothing was approved"; this computer has no check key, so the grant goes to the phone.
    const executed = await callTool(agent, 'check-pending-commitments', { proposal_id: proposalId });
    expect(executed.text).not.toMatch(/nothing was approved under that fingerprint/);
    expect(executed.text).not.toMatch(/setup refused to run it/);
    const opened = await phoneGrantsNext(p, sb.recoveryCode, phone, read.priv, granted, 'the AI-proposed give');
    // What the phone grants is exactly what the AI proposed and the person approved.
    expect(opened.give.bounds.value_max).toBe(1000);
    expect(opened.intent).toBe('Follow up quotes for existing customers.');

    // 5. The mandate is live for the AI (the MCP server lists only mandates whose owner's grant it verified).
    await until('the sales mandate is live for the AI', async () => {
      const r = await callTool(agent, 'list-authorizations', {});
      return /sales@/.test(r.text) ? true : undefined;
    }, 90_000);
  } finally {
    await agent.close().catch(() => undefined);
  }
});
