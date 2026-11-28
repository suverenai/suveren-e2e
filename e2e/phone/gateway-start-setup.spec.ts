/**
 * The computer's set-up on the gateway page in a REAL browser (DEC-91 four steps, DEC-93 start without an account key,
 * DEC-92 Touch ID where there is a helper), against the real stack: a fresh gateway of its own with the switch on (control
 * plane + MCP server built from the checkout, its own data folder), the real Authority Server of the phone suite with its
 * Connect pages, a real browser on both.
 *
 * What is real: the gateway page from /login to the dashboard; the Authority Server's /connect page, its email sign-in with
 * the 6-digit code, its "Connect this computer to your account?" and the redirect back to the gateway; the gateway's start
 * session, Connect token exchange, vault creation bound to the account, genesis with the enrolment code, page session.
 *
 * What the test does itself: reads the 6-digit code from the Authority Server's console mailer (the mail log the phone suite
 * already captures) instead of an inbox; registers the person directly (POST /api/auth/register, as the rest of the suite).
 *
 * Not covered here, and why:
 *   - Touch ID (DEC-92, DEC-94): CI runs Linux, where the gateway has no native helper (locateHelper: darwin arm64 only), so
 *     these journeys take the password-only path and assert that no Touch ID step is shown.
 *   - The give page's touch state, progress lines and "Signed" (give-feedback): they need a check key, i.e. the helper.
 *     The no-check-key give ("Give on your phone") is covered by gateway-give-on-phone.spec.ts.
 *
 * The browser does not announce automation (`--disable-blink-features=AutomationControlled`, the same as the dev helper),
 * because the gateway page refuses sign-in in a browser that says it is automated.
 */
import { test, expect, type Page, type BrowserContext, type TestInfo } from '@playwright/test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ProcessManager } from '../../src/helpers/process-manager';
import { newSecret, startControlPlane, startMcpServer, type StackOptions } from '../../src/helpers/gateway-stack';
import { http, show, stackFromEnv, type PhoneStack } from '../../src/helpers/phone-app';

/**
 * The Connect waiting text names the Authority Server in use. Gateways up to 0.47 always said
 * "suveren.ai"; later ones name the server's own host (a local test server: localhost:<port>).
 * Both are accepted until the oldest gateway this suite runs against names the host.
 */
function stillMissingText(asUrl: string): RegExp {
  const host = new URL(asUrl).host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^Still missing: press Connect on the (suveren\\.ai|${host}) page in that tab\\.$`);
}

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the gateway page is the same in every browser; one engine is enough here');
test.use({ launchOptions: { args: ['--disable-blink-features=AutomationControlled'] } });

const PASSWORD = 'correct horse battery staple 42';
// Ports of the fresh gateways this file starts (not in any lane of the machine map, nor the phone suite's 19940–19944).
const BASE_PORT = Number(process.env.HAP_E2E_SETUP_GW_BASE_PORT ?? 19950);

let stack: PhoneStack;
const pm = new ProcessManager();
const dirs: string[] = [];
let nextPort = BASE_PORT;

test.beforeAll(() => { if (!unavailable) stack = stackFromEnv(); });
test.afterAll(async () => {
  await pm.killAll();
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface FreshGateway { url: string; stack: StackOptions; name: string }

/** A gateway nobody has used: no account, no password, no data (DEC-93's "unclaimed"). */
async function freshGateway(name: string, dataDir?: string, opts?: Pick<StackOptions, 'ports' | 'secret'>): Promise<FreshGateway> {
  const dir = dataDir ?? mkdtempSync(join(tmpdir(), `hap-e2e-setup-${name}-`));
  if (!dataDir) dirs.push(dir);
  const ports = opts?.ports ?? { cp: nextPort++, mcp: nextPort++ };
  const o: StackOptions = {
    dataDir: dir, ports, secret: opts?.secret ?? newSecret(), asUrl: stack.asUrl,
    extraEnv: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
  };
  await startControlPlane(pm, o, `${name}-cp`);
  await startMcpServer(pm, o, `${name}-mcp`);
  return { url: `http://localhost:${ports.cp}`, stack: o, name };
}

async function stopGateway(g: FreshGateway): Promise<void> {
  await pm.stopProcess(`${g.name}-mcp`);
  await pm.stopProcess(`${g.name}-cp`, { confirmDownUrl: `${g.url}/health` });
}

/** A registered account the Connect email sign-in accepts. */
async function newAccount(name: string): Promise<{ name: string; email: string; userId: string }> {
  const email = `${name.toLowerCase().replace(/\W+/g, '-')}-${randomBytes(4).toString('hex')}@test.local`;
  const r = await http(stack.asUrl, 'POST', '/api/auth/register', { body: { name, email } });
  expect([200, 201], show(r)).toContain(r.status);
  return { name, email, userId: r.json.user.id as string };
}

/** The newest 6-digit Connect code mailed to `email`, from the Authority Server's console mailer. */
async function connectCode(email: string): Promise<string> {
  const log = process.env.HAP_E2E_PHONE_MAIL_LOG;
  expect(log, 'the phone suite global setup writes the mail log').toBeTruthy();
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const text = readFileSync(log!, 'utf8');
    const at = text.lastIndexOf(`To: ${email}`);
    if (at >= 0) {
      const m = /6-digit code[^:]*:\s*(\d{6})/.exec(text.slice(at));
      if (m) return m[1];
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`no Connect code mailed to ${email}`);
}

/** A screenshot of every step, kept with the run (test-results/phone/…) and in the HTML report. */
async function shot(page: Page, info: TestInfo, name: string): Promise<void> {
  const path = info.outputPath(`${String(info.attachments.length + 1).padStart(2, '0')}-${name}.png`);
  await page.screenshot({ path, fullPage: true });
  await info.attach(name, { path, contentType: 'image/png' });
}

/**
 * Records what the page ever showed, from the first byte: a flash of a screen lasts one or two frames and is gone before
 * any assertion runs, so the page itself notes it (MutationObserver), and the test reads the notes.
 */
async function watchForFlashes(context: BrowserContext): Promise<void> {
  await context.addInitScript(() => {
    const seen = { signIn: false, unlock: false, spinner: false, greyed: false };
    (window as unknown as { __seen: typeof seen }).__seen = seen;
    const look = () => {
      const t = document.body?.innerText ?? '';
      if (t.includes('Enter your API key')) seen.signIn = true;
      if (t.includes('Unlock the gateway')) seen.unlock = true;
      if (document.querySelector('.brand-spin')) seen.spinner = true;
      if (document.querySelector('.skel-area')) seen.greyed = true;
    };
    new MutationObserver(look).observe(document, { childList: true, subtree: true, characterData: true });
  });
}
const seen = (page: Page) => page.evaluate(() => (window as unknown as { __seen: { signIn: boolean; unlock: boolean; spinner: boolean; greyed: boolean } }).__seen);
const resetSeen = (page: Page) => page.evaluate(() => { const s = (window as unknown as { __seen: Record<string, boolean> }).__seen; for (const k of Object.keys(s)) s[k] = false; });

/** On the Authority Server's /connect page: the email sign-in (when asked) and "Connect this computer to your account?". */
async function confirmOnAs(popup: Page, info: TestInfo, email: string, expectEmailStep: boolean, tag: string): Promise<void> {
  await popup.waitForLoadState('domcontentloaded');
  const emailField = popup.getByLabel('Email address');
  const ask = popup.getByText('Connect this computer to your account?');
  await expect(emailField.or(ask)).toBeVisible({ timeout: 30_000 });
  await shot(popup, info, `${tag}-as-connect-page`);
  if (expectEmailStep) {
    await expect(emailField, 'a browser that never signed in is asked for its email').toBeVisible();
    await emailField.fill(email);
    await popup.getByRole('button', { name: 'Send the link' }).click();
    const codeField = popup.getByLabel('Code from the email');
    await expect(codeField).toBeVisible({ timeout: 30_000 });
    await codeField.fill(await connectCode(email));
    await shot(popup, info, `${tag}-as-code`);
    await popup.getByRole('button', { name: 'Continue' }).click();
  } else {
    // The stale-"done" fix (AS fix/connect-stale-done): a second Connect in a browser that is still signed in offers the
    // Connect button for THIS request at once, never "Done" left over from the first.
    await expect(popup.getByText('Done. You can close this tab'), 'a second Connect must not read "Done" from the first').toHaveCount(0);
  }
  await expect(ask).toBeVisible({ timeout: 30_000 });
  await shot(popup, info, `${tag}-as-ask`);
  await popup.getByRole('button', { name: 'Connect', exact: true }).click();
  // The Authority Server redirects to the gateway's own callback on 127.0.0.1, which answers "You can close this tab."
  await popup.waitForURL((u) => u.hostname === '127.0.0.1', { timeout: 30_000 });
  await expect(popup.getByText(/You can close this tab/)).toBeVisible({ timeout: 30_000 });
  await shot(popup, info, `${tag}-as-done`);
  await popup.close();
}

test('DEC-93 + DEC-91: a new gateway starts at Connect without an account key, then password, recovery code on one screen, the account, the dashboard; a restart unlocks; a second Connect in the same browser is one click', async ({ page, context }, info) => {
  test.setTimeout(300_000);
  await watchForFlashes(context);
  const account = await newAccount('Setup person');
  const gw = await freshGateway('setup-a');

  // 1. /login on a new gateway: the sign-in greyed out (DEC-100, no turning mark), then /start; the account-key sign-in never shows.
  await page.goto(`${gw.url}/login`);
  await page.waitForURL((u) => u.pathname === '/start', { timeout: 20_000 });
  await expect(page.getByRole('heading', { name: 'Connect to your Suveren account' })).toBeVisible();
  await shot(page, info, 'a-start');
  const s1 = await seen(page);
  expect(s1.signIn, 'the account-key sign-in flashed before /start').toBe(false);
  expect(s1.spinner, 'DEC-100: no turning mark while the gateway is asked').toBe(false);
  expect(s1.greyed, 'DEC-100: the page greyed out while the gateway is asked').toBe(true);

  // 2. Connect: the Authority Server's page opens in a new tab; email sign-in with the code; Connect.
  const popupP = context.waitForEvent('page');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  const popup = await popupP;
  await expect(page.getByText(stillMissingText(stack.asUrl))).toBeVisible({ timeout: 15_000 });
  await shot(page, info, 'a-waiting');
  await confirmOnAs(popup, info, account.email, true, 'a');

  // 3. The gateway page goes on by itself: the unlock password, naming the connected account.
  await expect(page.getByRole('heading', { name: 'Set an unlock password' })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(`Connected to the account of ${account.name} (${account.email}).`)).toBeVisible();
  await shot(page, info, 'a-password');
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Password again').fill(PASSWORD);
  await page.getByRole('button', { name: 'Set password' }).click();

  // 4. No helper on this computer (CI): no Touch ID step. The recovery code on ONE screen.
  await expect(page.getByRole('heading', { name: 'Your recovery code' })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText('Touch the sensor')).toHaveCount(0);
  const code = page.locator('.recovery-code');
  await expect(code).toBeVisible();
  const codeText = (await code.innerText()).trim();
  expect(codeText.length, 'a recovery code is shown').toBeGreaterThan(10);
  // DEC-88: the code wraps only between its groups (after a hyphen), never inside one: every line but the last ends in "-".
  const lines = await code.evaluate((el) => {
    const t = el.firstChild as Text; const r = document.createRange(); const out: string[] = []; let cur = ''; let top: number | null = null;
    for (let i = 0; i < t.length; i++) {
      r.setStart(t, i); r.setEnd(t, i + 1);
      const y = Math.round(r.getBoundingClientRect().top);
      if (top !== null && y !== top) { out.push(cur); cur = ''; }
      top = y; cur += t.data[i];
    }
    out.push(cur);
    return out;
  });
  for (const l of lines.slice(0, -1)) expect(l.trim(), `the code broke inside a group: ${JSON.stringify(lines)}`).toMatch(/-$/);
  const cont = page.getByRole('button', { name: 'Continue', exact: true });
  await expect(cont, 'Continue only after the tick').toBeDisabled();
  await shot(page, info, 'a-code-before-tick');
  await page.getByRole('checkbox').check();
  await expect(cont).toBeEnabled();
  await expect(code, 'the code stays visible after the tick').toHaveText(codeText);
  await expect(page.getByRole('heading', { name: 'Did you keep it?' }), 'no separate "kept" screen').toHaveCount(0);
  await shot(page, info, 'a-code-after-tick');
  await cont.click();

  // 5. Done: the connected account by name; then the dashboard with no unlock-screen flash.
  await expect(page.getByText(`Connected as ${account.name} (${account.email}). You are signed in.`)).toBeVisible({ timeout: 60_000 });
  await shot(page, info, 'a-connected');
  await resetSeen(page);
  await page.getByRole('button', { name: /^Continue|^Go on|^Open/ }).first().click();
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
  await shot(page, info, 'a-dashboard');
  expect((await seen(page)).unlock, 'the unlock screen flashed between the done screen and the dashboard').toBe(false);

  // The Authority Server holds this computer's genesis; the gateway is claimed for good.
  const st = await (await fetch(`${gw.url}/auth/start/status`)).json() as { available?: boolean };
  expect(st.available, 'a claimed gateway never offers the start access again').toBe(false);

  // 6. A second new gateway for the SAME account (which now has a device chain), same browser: Connect is one click (still
  //    signed in), and the Authority Server refuses it (plan 20.18 point 6: no enrolment code for an account with a chain).
  //    The page must say what to do instead, not "Try again".
  const gw2 = await freshGateway('setup-b');
  const page2 = await context.newPage();
  await page2.goto(`${gw2.url}/login`);
  await page2.waitForURL((u) => u.pathname === '/start', { timeout: 20_000 });
  const popup2P = context.waitForEvent('page');
  await page2.getByRole('button', { name: 'Connect', exact: true }).click();
  await confirmOnAs(await popup2P, info, account.email, false, 'b');
  await expect(page2.getByText('This account already has a device. Add this computer from a device you already have.')).toBeVisible({ timeout: 30_000 });
  await expect(page2.getByText('The connection was refused. Nothing changed. Try again.')).toHaveCount(0);
  await shot(page2, info, 'b-chain-exists');
  await page2.close();

  // 6b. The stale-"Done" fix (AS fix/connect-stale-done), the case Andreas met: in ONE browser, a Connect that was confirmed
  //     but whose gateway never finished, then a Connect from another new gateway. The second must offer Connect at once
  //     (one click, still signed in), never "Done" left over from the first, and that gateway goes on to the password.
  const other = await context.browser()!.newContext();
  await watchForFlashes(other);
  const account2 = await newAccount('Second person');
  const gwC = await freshGateway('setup-c1');
  const pageC = await other.newPage();
  await pageC.goto(`${gwC.url}/login`);
  await pageC.waitForURL((u) => u.pathname === '/start', { timeout: 20_000 });
  const popupCP = other.waitForEvent('page');
  await pageC.getByRole('button', { name: 'Connect', exact: true }).click();
  await confirmOnAs(await popupCP, info, account2.email, true, 'c1');
  await expect(pageC.getByRole('heading', { name: 'Set an unlock password' })).toBeVisible({ timeout: 30_000 });
  // This gateway stops here (no password, no genesis): the account still has no chain.
  const gwD = await freshGateway('setup-c2');
  const pageD = await other.newPage();
  await pageD.goto(`${gwD.url}/login`);
  await pageD.waitForURL((u) => u.pathname === '/start', { timeout: 20_000 });
  const popupDP = other.waitForEvent('page');
  await pageD.getByRole('button', { name: 'Connect', exact: true }).click();
  await confirmOnAs(await popupDP, info, account2.email, false, 'c2');
  await expect(pageD.getByRole('heading', { name: 'Set an unlock password' })).toBeVisible({ timeout: 30_000 });
  await expect(pageD.getByText(`Connected to the account of ${account2.name} (${account2.email}).`)).toBeVisible();
  await shot(pageD, info, 'c2-password');
  await other.close();

  // 7. A restart of the first gateway: the unlock screen, the password, the turning mark, the dashboard; the start never.
  await stopGateway(gw);
  await startControlPlane(pm, gw.stack, `${gw.name}-cp`);
  await startMcpServer(pm, gw.stack, `${gw.name}-mcp`);
  await page.goto(`${gw.url}/login`);
  await expect(page.getByRole('heading', { name: 'Unlock the gateway' })).toBeVisible({ timeout: 30_000 });
  expect(page.url()).not.toContain('/start');
  await shot(page, info, 'a-restart-unlock');
  await resetSeen(page);
  await page.locator('#unlock-password').fill(PASSWORD);
  await page.locator('#unlock-password').press('Enter');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
  await shot(page, info, 'a-restart-dashboard');
  const s7 = await seen(page);
  expect(s7.signIn, 'no account-key sign-in after the unlock').toBe(false);
});

test('the Connect waiting page says what is missing, and after 45 s offers "Start again"', async ({ page, context }, info) => {
  test.setTimeout(180_000);
  const gw = await freshGateway('setup-w');
  // Playwright's clock (not a test hook in the product): the page's 45-second timer runs on it; fastForward moves it on.
  await page.clock.install();
  await page.goto(`${gw.url}/login`);
  await page.waitForURL((u) => u.pathname === '/start', { timeout: 20_000 });
  const popupP = context.waitForEvent('page');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  const popup = await popupP;
  await popup.close(); // the person closed the tab without pressing Connect
  await expect(page.getByText(stillMissingText(stack.asUrl))).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('button', { name: 'Start again' })).toHaveCount(0);
  await shot(page, info, 'c-waiting');
  await page.clock.fastForward(46_000);
  await expect(page.getByText('Nothing has arrived yet.')).toBeVisible({ timeout: 10_000 });
  await shot(page, info, 'c-stuck');
  await page.getByRole('button', { name: 'Start again' }).click();
  await expect(page.getByRole('heading', { name: 'Connect to your Suveren account' })).toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('button', { name: 'Connect', exact: true })).toBeEnabled();
  await shot(page, info, 'c-start-again');
});
