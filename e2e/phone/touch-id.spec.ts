/**
 * The Touch ID path on the gateway page, in a real browser, with the REAL gateway code driving the unlock helper's DEBUG build
 * (software backend, DESIGN.md section 9; never shipped). Runs only where HAP_E2E_HELPER_APP names that build: the macOS CI job.
 *
 * What is real: the Authority Server, the gateway (control plane + MCP server, built), the helper process the gateway starts
 * (hash-checked, its protocol, its check key and unlock wrap — only the key store is software instead of the Secure Enclave),
 * the gateway page, the AI side as MCP calls through the gateway's own MCP endpoint, the records connector.
 * Seams: the account-key sign-in and the set-up run through the gateway's API (the set-up screens have their own journey); no
 * person touches a sensor (the software backend signs without a prompt).
 *
 * Scenarios (Andreas, 2026-11-20 "real-world tests"):
 *   S1 set-up with a check key, Touch ID unlock on, the page unlocked with Touch ID
 *   S2 the Setup mandate given on the give page with Touch ID
 *   S3 the AI proposes a Records mandate; the person gives it ON THE CARD in place with Touch ID; it is live for the AI
 *   S4 the AI writes a note; the person approves on the card; the note exists in the connector
 *   S5 a write over the daily limit is refused before anything happens, with a plain reason
 *   S6 a new page session (sign-out) is opened with Touch ID; the AI continues under its mandates
 *   S7 "Add a phone" names the phone app address the gateway holds
 */
import { test, expect, type Page } from '@playwright/test';
import { titleField, typeTitle } from '../../src/helpers/give-page';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type pg from 'pg';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { connectDb, enrolmentCode, newPerson, until, stackFromEnv, type PhoneStack, type Person } from '../../src/helpers/phone-app';
import { GatewayClient } from '../../src/helpers/gateway-client';
import { RECORDS_INTEGRATION, recordTitles } from '../../src/helpers/gateway-stack';
import { expectStampCentred, expectStampCentredAtSizes, expectButtonTextFits } from './stamp-centre';

const helper = process.env.HAP_E2E_HELPER_APP;
const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
test.skip(!helper, 'Touch ID journeys need the debug unlock helper (HAP_E2E_HELPER_APP): the macOS CI job');
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the gateway page is the same in every browser');
// The gateway refuses approvals from a browser that announces automation (navigator.webdriver); the person-side test runs
// Chromium without that flag, as the default browser suite does (playwright.config.ts).
test.use({ launchOptions: { args: ['--disable-blink-features=AutomationControlled'] } });

const PROFILES_DIR = process.env.HAP_E2E_PROFILES_DIR ?? join(import.meta.dirname, '..', '..', '..', 'hap-profiles');
const PASSWORD = 'correct horse battery staple 42';
const MCP_URL = `http://localhost:${process.env.HAP_E2E_PHONE_GW_MCP_PORT ?? 19944}`;

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
  if (!helper || unavailable) return;
  stack = stackFromEnv();
  db = await connectDb(stack);
  gw = process.env.HAP_E2E_PHONE_GW_URL!;
});
test.afterAll(async () => { await db?.end().catch(() => undefined); });

async function goInPage(page: Page, path: string): Promise<void> {
  await page.evaluate((to) => { window.history.pushState({}, '', to); window.dispatchEvent(new PopStateEvent('popstate')); }, path);
}

async function callTool(agent: Client, name: string, args: Record<string, unknown>): Promise<{ text: string; isError: boolean }> {
  const r = await agent.callTool({ name, arguments: args }, undefined, { timeout: 120_000 });
  const content = (r.content ?? []) as Array<{ type: string; text?: string }>;
  return { text: content.map((x) => x.text ?? '').join('\n'), isError: r.isError === true };
}

async function signInAndSetPassword(p: Person): Promise<Record<string, string>> {
  const login = await fetch(`${gw}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': p.apiKey }, body: '{}' });
  expect(login.status, await login.clone().text()).toBe(200);
  const set = await fetch(`${gw}/auth/password/set`, { method: 'POST', headers: { 'content-type': 'application/json', origin: gw, 'x-api-key': p.apiKey }, body: JSON.stringify({ password: PASSWORD }) });
  const body = (await set.json()) as { sessionToken?: string };
  expect(set.status, JSON.stringify(body)).toBe(200);
  const cookie = /suveren_page_session=([^;]+)/.exec(set.headers.get('set-cookie') ?? '')?.[1];
  expect(cookie).toBeTruthy();
  return { 'content-type': 'application/json', origin: gw, cookie: `suveren_page_session=${cookie}`, 'x-suveren-session': body.sessionToken! };
}

test('Touch ID on the gateway page: set-up, unlock, give, the card in place, an approved action, the limit, a new session', async ({ page }, testInfo) => {
  test.setTimeout(480_000);
  const shot = async (name: string) => {
    const path = testInfo.outputPath(`${name}.png`);
    await page.screenshot({ path, fullPage: true });
    await testInfo.attach(name, { path, contentType: 'image/png' });
  };
  const p = await newPerson(stack, 'Touch ID');
  const headers = await signInAndSetPassword(p);

  // S1: the helper is there, the set-up makes this computer's check key, Touch ID unlock is turned on.
  const caps = await (await fetch(`${gw}/auth/platform/capabilities`, { headers })).json() as { available?: boolean };
  expect(caps.available, JSON.stringify(caps)).toBe(true);
  const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office Mac', checkKey: true }) });
  const sb = (await start.json()) as { setupId: string; recoveryCode: string };
  expect(start.status, JSON.stringify(sb)).toBe(200);
  const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
  expect(fin.status, await fin.clone().text()).toBe(200);
  const chain = await db.query(`select entry from device_chain_entries where user_id = $1 order by seq`, [p.userId]);
  expect(JSON.stringify(chain.rows[0].entry)).toContain('"type":"platform"');
  const en = await fetch(`${gw}/auth/platform/enable`, { method: 'POST', headers, body: JSON.stringify({ password: PASSWORD }) });
  expect(en.status, await en.clone().text()).toBe(200);

  // The records connector, so the AI has something to do.
  const internal = new GatewayClient(MCP_URL, process.env.HAP_E2E_PHONE_GW_SECRET);
  await internal.addIntegration(RECORDS_INTEGRATION as Parameters<GatewayClient['addIntegration']>[0]);

  // The page: unlocked with Touch ID (no password typed).
  await page.goto(gw);
  await expect(page.getByRole('button', { name: 'Unlock with Touch ID' })).toBeVisible({ timeout: 30_000 });
  await shot('t1-unlock-screen');
  // DEC-100: between the touch and the dashboard, the dashboard greyed out (no turning mark). The sign-in request is
  // held a moment so that step is on screen long enough to be seen.
  const holdSignIn = async (route: import('@playwright/test').Route) => { await new Promise((r) => setTimeout(r, 1_500)); await route.fallback(); };
  await page.route(`${gw}/auth/device/signin`, holdSignIn);
  // The page asks the status first and calls sign-in only when the gateway has not signed in by itself in the background
  // meanwhile (unlock-driver.ts afterSession): hold the status too, or the step can be too short to be seen (a race).
  await page.route(`${gw}/auth/device/status`, holdSignIn);
  await page.getByRole('button', { name: 'Unlock with Touch ID' }).click();
  await expect(page.getByTestId('shell-skeleton-dashboard'), 'DEC-100: the dashboard greyed out after the touch').toBeVisible({ timeout: 15_000 });
  await expect(page.locator('.brand-spin'), 'DEC-100: no turning mark').toHaveCount(0);
  await shot('t1b-between-touch-and-dashboard');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
  await page.unroute(`${gw}/auth/device/signin`, holdSignIn);
  await page.unroute(`${gw}/auth/device/status`, holdSignIn);
  await shot('t2-unlocked-with-touch');

  // S2: the Setup mandate, given on the give page with Touch ID.
  const groups = await (await fetch(`${gw}/api/groups`, { headers })).json() as { groups?: Array<{ id: string; name?: string; isPersonal?: boolean }> };
  const personal = (groups.groups ?? []).find((g) => g.isPersonal)!;
  const delegation = newestProfileId('delegation');
  await page.evaluate(({ auth, gate }) => {
    sessionStorage.setItem('agentAuth', JSON.stringify(auth));
    sessionStorage.setItem('agentGate', JSON.stringify(gate));
  }, {
    auth: { profileId: delegation, groupId: personal.id, groupName: personal.name ?? null, domain: 'owner', isPersonal: true },
    gate: { bounds: { profile: delegation, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 30 }, context: { allowed_profiles: 'records', allowed_modes: 'review' }, gateContent: { intent: 'The AI prepares the mandates its work needs.' }, ttlConfig: { max: 86400 } },
  });
  await goInPage(page, '/mandates/new/sign');
  await typeTitle(page, 'Setup');
  if (await page.getByTestId('duration-needed').isVisible().catch(() => false)) await page.locator('button', { hasText: /^24 hours$/ }).click();
  const giveTouch = page.getByTestId('give-touch-button');
  await expect(giveTouch).toBeEnabled({ timeout: 30_000 });
  await expect(giveTouch).toHaveText('Give this mandate with Touch ID');
  await shot('t3-give-page');
  await giveTouch.click();
  await expect(page.getByTestId('give-touch-given')).toBeVisible({ timeout: 60_000 });
  // The result replaces the long form: the page is back at its top, the result card whole below the header.
  await expect.poll(async () => page.evaluate(() => {
    const card = document.querySelector('[data-testid="give-done"]');
    const header = document.querySelector('nav, header');
    if (!card) return 'no result card';
    const top = card.getBoundingClientRect().top;
    const below = header ? header.getBoundingClientRect().bottom : 0;
    return top >= below - 1 && top < window.innerHeight ? 'in view' : `card top ${Math.round(top)} vs header ${Math.round(below)}`;
  }), { timeout: 5_000 }).toBe('in view');
  await shot('t4-give-signed');
  await expectStampCentred(page.getByTestId('give-touch-given').locator('.av3-stamp'), 'give page, given with Touch ID');
  await page.getByTestId('give-touch-close').click();

  const agent = new Client({ name: 'touch-id-scenarios', version: '1.0.0' }, { capabilities: {} });
  await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  try {
    await until('the Setup mandate is live for the AI', async () => (/delegation@/.test((await callTool(agent, 'list-authorizations', {})).text) ? true : undefined), 60_000);
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

    // S3: the AI proposes; the person gives it on the card in place with Touch ID.
    const proposed = await callTool(agent, 'setup__create_mandate', {
      profile: 'records', limits: { read_access: 'unlimited', write_daily_max: 1, delete_access: 'none', archive_access: 'none' },
      intent: 'Keep the notes of the quotes.', mode: 'review', duration_hours: 24, title: 'Notes',
    });
    expect(proposed.isError, proposed.text).toBe(false);
    const mandateProposal = /Proposal ID: (\S+?)\./.exec(proposed.text)![1];
    const card = await openCard(mandateProposal);
    // A check key here: the card's button names Touch ID, the same words as the give page (Andreas 2026-11-22).
    await expect(card.getByTestId('btn-approve')).toHaveText('Give this mandate with Touch ID', { timeout: 30_000 });
    await expectButtonTextFits(card.getByTestId('btn-approve'), 'card, Touch ID give button');
    await shot('t5-card-mandate');
    const urlBefore = page.url();
    await card.getByTestId('btn-approve').click();
    // After the give the card shows the gateway's stamp ("Signed") and stays until the person presses Close (DEC-86/88, like any decision).
    await expect(card.getByTestId('give-touch-given')).toBeVisible({ timeout: 60_000 });
    await expect(card.getByTestId('give-touch-given').getByText('Signed')).toBeVisible();
    await shot('t6-card-given-with-touch');
    await expectStampCentredAtSizes(page, card.getByTestId('give-touch-given').locator('.av3-stamp'), 'card, given with Touch ID', shot, 't6-stamp');
    expect(page.url(), 'the give runs on the card').toBe(urlBefore);
    await card.getByTestId('give-touch-close').click();
    await until('the Records mandate is live for the AI', async () => (/records@/.test((await callTool(agent, 'list-authorizations', {})).text) ? true : undefined), 90_000);

    // S4: the AI writes a note (review mode); the person approves on the card (a click, no touch); the note exists.
    const write = await callTool(agent, 'records__create_record', { title: 'Quote follow-up', content: 'Call back on Monday.', type: 'note' });
    const writeProposal = /Proposal ID: (\S+?)\./.exec(write.text)?.[1];
    expect(writeProposal, write.text).toBeTruthy();
    const actionCard = await openCard(writeProposal!);
    await shot('t7-card-action');
    await actionCard.getByTestId('btn-approve').click();
    await until('the note is written', async () => {
      const r = await callTool(agent, 'check-pending-commitments', { proposal_id: writeProposal });
      return /pending|awaiting/i.test(r.text) ? undefined : r;
    }, 90_000);
    expect(await recordTitles(process.env.HAP_E2E_PHONE_GW_DATA_DIR!)).toContain('Quote follow-up');
    await shot('t8-after-approve');

    // S5: a second write the same day is over the limit (1): refused before anything happens, in plain words.
    const over = await callTool(agent, 'records__create_record', { title: 'Second note', content: 'x', type: 'note' });
    expect(over.isError, over.text).toBe(true);
    expect(over.text).toMatch(/limit|1 of 1|used up/i);
    expect(over.text).not.toMatch(/Proposal ID/);

    // S6: the page session ends (sign-out); Touch ID opens a new one; the AI keeps working under its mandates.
    await page.evaluate(() => fetch('/auth/logout', { method: 'POST' }));
    await page.goto(gw);
    await expect(page.getByRole('button', { name: 'Unlock with Touch ID' })).toBeVisible({ timeout: 30_000 });
    await page.getByRole('button', { name: 'Unlock with Touch ID' }).click();
    await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
    await shot('t9-new-session-with-touch');
    expect((await callTool(agent, 'list-authorizations', {})).text).toMatch(/records@/);

    // S7: "Add a phone" names where the phone app is opened: the address the gateway holds (SUVEREN_APP_ORIGIN, global-setup),
    // never one the Authority Server sends. A computer with a check key shows the code; nothing is scanned here.
    await page.getByRole('link', { name: 'Devices' }).first().click();
    await page.getByRole('button', { name: 'Add a phone' }).click();
    await page.getByRole('button', { name: 'Show the code' }).click();
    const appHost = new URL(process.env.HAP_E2E_PHONE_APP_URL!).host;
    await expect(page.getByText(`On your phone, open ${appHost}, choose Add this phone to my account, and scan this code.`, { exact: true })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId('pairing-qr')).toBeVisible();
    await shot('t10-add-phone-code');
    await page.getByRole('button', { name: 'Cancel' }).click();
  } finally {
    await agent.close().catch(() => undefined);
  }
});
