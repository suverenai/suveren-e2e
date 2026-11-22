/**
 * DEC-98 skeleton loading on the gateway page, in a real browser against the real stack: a fresh gateway of its own with
 * the device-keys switch on (control plane + MCP server built from the checkout), the phone suite's real Authority Server.
 *
 * The network is slowed on purpose: every request of the page waits 300–1500 ms before it goes out (a different delay per
 * address), so a page's parts get their data at different moments — the case where they used to pop in one by one. For
 * each main page the browser's own layout-shift entries (PerformanceObserver 'layout-shift', without recent input) are
 * summed up while it loads: Cumulative Layout Shift must stay under 0.05. The pages are reached the way the app moves
 * between them (history + popstate), not with a click, because a click marks every shift in the next 500 ms as "after
 * input" and would hide the very pop-in this measures.
 *
 * The unlock screen: the page itself notes what was on screen the first moment the real form (the password field) is
 * there. Where the gateway has Touch ID (the macOS CI job, the helper's DEBUG build with its software backend — the file
 * name carries "touch-id" for that job's filter), the Touch ID button must be part of that first real paint. On Linux the
 * gateway has no helper: the first real paint must be the password-only form, and nothing may arrive after it.
 *
 * While a page shows its skeleton, no real card may be visible beside it (a section outside the page gate pops in).
 * Screenshots of every page: greyed out (while it loads) and loaded, kept with the run and in the HTML report.
 * Also: Tickets, Reports, Approvals, the authorise picker and the mandate wizard (the rest of DEC-98/DEC-100), and a
 * gateway in simulation mode (its banner in the greyed-out frame).
 * Not covered here: the approval card, the phone app's screens and a ticket's "what was done" panel (no ticket exists in
 * this journey); they have unit tests in the gateway.
 * The numbers are reported as annotations (cls:<page>) and on stdout, so a run against an older gateway shows the "before".
 */
import { test, expect, type Page, type TestInfo } from '@playwright/test';
import type pg from 'pg';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, } from 'node:path';
import { ProcessManager } from '../../src/helpers/process-manager';
import { newSecret, startControlPlane, startMcpServer, type StackOptions } from '../../src/helpers/gateway-stack';
import { connectDb, enrolmentCode, newPerson, stackFromEnv, type PhoneStack, type Person } from '../../src/helpers/phone-app';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE ?? process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
const helper = process.env.HAP_E2E_HELPER_APP;
test.skip(!!unavailable, `chain gateway not available: ${unavailable}`);
test.skip(({ browserName }) => browserName !== 'chromium', 'the gateway page is the same in every browser; one engine is enough here');
test.use({ launchOptions: { args: ['--disable-blink-features=AutomationControlled'] } });

const PASSWORD = 'correct horse battery staple 42';
const CLS_MAX = 0.05;
// Ports not used by any lane on the machine map nor by the rest of the phone suite (19940–19956).
const PORTS = { cp: Number(process.env.HAP_E2E_SKEL_GW_CP_PORT ?? 19960), mcp: Number(process.env.HAP_E2E_SKEL_GW_MCP_PORT ?? 19961) };

let stack: PhoneStack;
let db: pg.Client;
const pm = new ProcessManager();
let dir: string | undefined;
let gw: string;

test.beforeAll(async () => {
  if (unavailable) return;
  stack = stackFromEnv();
  db = await connectDb(stack);
  dir = mkdtempSync(join(tmpdir(), 'hap-e2e-skeleton-'));
  const o: StackOptions = {
    dataDir: dir, ports: PORTS, secret: newSecret(), asUrl: stack.asUrl,
    extraEnv: {
      SUVEREN_DEVICE_KEYS: 'on', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1',
      ...(helper ? { SUVEREN_HELPER_APP: helper, SUVEREN_HELPER_ARGS: '--backend software --allow-any-caller' } : {}),
    },
  };
  await startControlPlane(pm, o, 'skel-cp');
  await startMcpServer(pm, o, 'skel-mcp');
  gw = `http://localhost:${PORTS.cp}`;
});
test.afterAll(async () => {
  await pm.killAll();
  await db?.end().catch(() => undefined);
  if (dir) rmSync(dir, { recursive: true, force: true });
});

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

/** Slow every request of the page by 300–1500 ms, the same delay for the same address, a different one per address. */
async function slowNetwork(page: Page): Promise<void> {
  await page.route(`${gw}/**`, async (route) => {
    const req = route.request();
    if (req.resourceType() !== 'fetch' && req.resourceType() !== 'xhr') return route.continue();
    const path = new URL(req.url()).pathname;
    let h = 0;
    for (const ch of path) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    await new Promise((r) => setTimeout(r, 300 + (h % 1200)));
    await route.continue().catch(() => undefined);
  });
}

/** The page sums its own layout shifts from the first byte; it also notes the first real paint of the unlock form. */
async function watchPage(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const w = window as unknown as { __cls: number; __shifts: Array<{ v: number; at: number }>; __unlockFirst: null | { touch: boolean; skeletonSeen: boolean }; __skelSeen: boolean };
    w.__cls = 0; w.__shifts = []; w.__unlockFirst = null; w.__skelSeen = false;
    new PerformanceObserver((list) => {
      for (const e of list.getEntries() as Array<PerformanceEntry & { value: number; hadRecentInput: boolean }>) {
        if (!e.hadRecentInput) {
          // Which elements moved, from where to where: a failing number alone does not say what to fix.
          const src = ((e as unknown as { sources?: Array<{ node?: Node; previousRect: DOMRectReadOnly; currentRect: DOMRectReadOnly }> }).sources ?? []).map((x) => {
            const el = x.node instanceof Element ? x.node : x.node?.parentElement;
            const name = el ? `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${el.getAttribute('data-testid') ? '[' + el.getAttribute('data-testid') + ']' : ''}.${(el.className?.toString() ?? '').split(' ').slice(0, 3).join('.')}` : '?';
            const r = (q: DOMRectReadOnly) => `${Math.round(q.x)},${Math.round(q.y)} ${Math.round(q.width)}x${Math.round(q.height)}`;
            return `${name} ${r(x.previousRect)} -> ${r(x.currentRect)} "${(el?.textContent ?? '').trim().slice(0, 30)}"`;
          });
          w.__cls += e.value; w.__shifts.push({ v: e.value, at: Math.round(e.startTime), src } as { v: number; at: number });
        }
      }
    }).observe({ type: 'layout-shift', buffered: true });
    const look = () => {
      if (document.querySelector('.skel-area, .skeleton')) w.__skelSeen = true;
      if (!w.__unlockFirst && document.getElementById('unlock-password')) {
        w.__unlockFirst = { touch: (document.body.innerText ?? '').includes('Unlock with Touch ID'), skeletonSeen: w.__skelSeen };
      }
    };
    new MutationObserver(look).observe(document, { childList: true, subtree: true, characterData: true });

    // DEC-100: no turning mark while loading, anywhere in this journey; and the dashboard greyed out while signing in.
    const sp = window as unknown as { __spinSeen: boolean; __shellSeen: boolean };
    sp.__spinSeen = false; sp.__shellSeen = false;
    new MutationObserver(() => {
      if (document.querySelector('.brand-spin')) sp.__spinSeen = true;
      if (document.querySelector('[data-testid="shell-skeleton-dashboard"]')) sp.__shellSeen = true;
    }).observe(document, { childList: true, subtree: true });

    // DEC-98: while the page shows its skeleton, no real card may be on screen beside it (a section outside the gate
    // pops in on its own). Checked on every change of the page, so a state of one frame is caught too.
    const v = window as unknown as { __mixed: string[] };
    v.__mixed = [];
    const vis = (el: Element) => (el as HTMLElement).checkVisibility?.({ checkOpacity: true, checkVisibilityCSS: true }) ?? (el as HTMLElement).offsetParent !== null;
    const mixed = () => {
      const skel = [...document.querySelectorAll('.page-inner .skel-area, .page-inner [data-testid$="-skeleton"]')].some(vis);
      if (!skel) return;
      for (const c of document.querySelectorAll('.page-inner :is(.card, .ob-card)')) {
        if (c.classList.contains('skel-card') || c.querySelector('.skeleton') || c.closest('.skel-area, [data-testid$="-skeleton"]') || !vis(c)) continue;
        const what = `${c.className.toString().slice(0, 60)}: ${(c.textContent ?? '').trim().slice(0, 50)}`;
        if (!v.__mixed.includes(what)) v.__mixed.push(what);
      }
    };
    new MutationObserver(mixed).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'class'] });
  });
}

const mixedCards = (page: Page) => page.evaluate(() => (window as unknown as { __mixed: string[] }).__mixed);
const resetMixed = (page: Page) => page.evaluate(() => { (window as unknown as { __mixed: string[] }).__mixed = []; });

const cls = (page: Page) => page.evaluate(() => (window as unknown as { __cls: number }).__cls);
const resetCls = (page: Page) => page.evaluate(() => { const w = window as unknown as { __cls: number; __shifts: unknown[]; __skelSeen: boolean }; w.__cls = 0; w.__shifts = []; w.__skelSeen = false; });
const shifts = (page: Page) => page.evaluate(() => (window as unknown as { __shifts: Array<{ v: number; at: number }> }).__shifts);

async function goInPage(page: Page, path: string): Promise<void> {
  await page.evaluate((to) => { window.history.pushState({}, '', to); window.dispatchEvent(new PopStateEvent('popstate')); }, path);
}

async function shot(page: Page, info: TestInfo, name: string): Promise<void> {
  const path = info.outputPath(`${name}.png`);
  await page.screenshot({ path, fullPage: true });
  await info.attach(name, { path, contentType: 'image/png' });
}

/** A screenshot while the page is greyed out — if it ever is (an older gateway has no skeleton: noted, not failed). */
async function shotWhileLoading(page: Page, info: TestInfo, name: string): Promise<boolean> {
  const skel = page.locator('.skel-area, [data-testid$="-skeleton"]').first();
  const there = await skel.waitFor({ state: 'visible', timeout: 1_200 }).then(() => true, () => false);
  if (there) await shot(page, info, `${name}-skeleton`);
  return there;
}

/** Loaded: no skeleton left, the network quiet, and a moment more for anything late to land (and shift). */
async function settle(page: Page): Promise<void> {
  await page.waitForTimeout(1_600);
  await expect(page.locator('.skel-area, .skeleton')).toHaveCount(0, { timeout: 20_000 });
  await page.waitForLoadState('networkidle').catch(() => undefined);
  await page.waitForTimeout(1_500);
}

/** One page reached in the app: greyed-out and loaded screenshots, its layout shift and the "no real card beside a skeleton" check. */
async function measure(page: Page, info: TestInfo, shotName: string, name: string, path: string): Promise<void> {
  await resetCls(page);
  await resetMixed(page);
  await goInPage(page, path);
  await shotWhileLoading(page, info, shotName);
  await settle(page);
  await shot(page, info, `${shotName}-loaded`);
  const v = await cls(page);
  report(info, name, v, await shifts(page));
  expect.soft(v, `${name}: layout shift while it loads`).toBeLessThan(CLS_MAX);
  expect.soft(await mixedCards(page), `${name}: a real card was on screen beside the skeleton`).toEqual([]);
}

function report(info: TestInfo, name: string, value: number, detail: Array<{ v: number; at: number }>): void {
  const v = Math.round(value * 10_000) / 10_000;
  info.annotations.push({ type: `cls:${name}`, description: `${v} (${detail.length} shift${detail.length === 1 ? '' : 's'})` });
  console.log(`[DEC-98] CLS ${name}: ${v} — ${JSON.stringify(detail.map((d) => Math.round(d.v * 10_000) / 10_000))}`);
  for (const d of detail as Array<{ v: number; src?: string[] }>) for (const x of d.src ?? []) console.log(`[DEC-98]   ${name} ${Math.round(d.v * 10_000) / 10_000}: ${x}`);
}

test('DEC-98: every main page loads in one go under a slow network (CLS < 0.05), and the unlock form is complete at its first paint', async ({ page }, info) => {
  test.setTimeout(300_000);
  const p = await newPerson(stack, 'Skeleton person');
  const headers = await signInAndSetPassword(p);

  // This computer's set-up through the API (the set-up screens have their own journey); with the helper, Touch ID unlock on.
  if (helper) {
    const caps = await (await fetch(`${gw}/auth/platform/capabilities`, { headers })).json() as { available?: boolean };
    expect(caps.available, JSON.stringify(caps)).toBe(true);
  }
  const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office computer', checkKey: !!helper }) });
  const sb = (await start.json()) as { setupId: string };
  expect(start.status, JSON.stringify(sb)).toBe(200);
  const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
  expect(fin.status, await fin.clone().text()).toBe(200);
  if (helper) {
    const en = await fetch(`${gw}/auth/platform/enable`, { method: 'POST', headers, body: JSON.stringify({ password: PASSWORD }) });
    expect(en.status, await en.clone().text()).toBe(200);
  }

  await watchPage(page);
  await slowNetwork(page);

  // 1. Unlock: the page's first load, no input yet.
  await page.goto(`${gw}/login`);
  await shotWhileLoading(page, info, '01-unlock');
  await expect(page.locator('#unlock-password')).toBeVisible({ timeout: 30_000 });
  await page.waitForTimeout(2_000); // anything that would still arrive (the Touch ID button, the reason) lands now
  await shot(page, info, '01-unlock-loaded');
  const first = await page.evaluate(() => (window as unknown as { __unlockFirst: { touch: boolean; skeletonSeen: boolean } | null }).__unlockFirst);
  expect(first, 'the page noted the first paint of the unlock form').not.toBeNull();
  const touchNow = await page.getByRole('button', { name: 'Unlock with Touch ID' }).isVisible();
  expect.soft(touchNow, helper ? 'Touch ID is on for this gateway: the button is there' : 'no helper on this computer: no Touch ID button').toBe(!!helper);
  expect.soft(first!.touch, 'the Touch ID button is part of the first real paint of the unlock form, never later').toBe(touchNow);
  info.annotations.push({ type: 'unlock:first-paint', description: `touch=${first!.touch} skeletonBefore=${first!.skeletonSeen} touchAvailable=${!!helper}` });
  const unlockCls = await cls(page);
  report(info, 'unlock', unlockCls, await shifts(page));
  expect.soft(unlockCls, 'unlock: layout shift while it loads').toBeLessThan(CLS_MAX);

  // In: the password (the Touch ID path itself is covered by touch-id.spec.ts). DEC-100: between the password and the
  // dashboard the dashboard greyed out, in its own frame, and the real one fills in without moving. The sign-in request
  // is held a moment longer so the step between is on screen long enough to be seen.
  const holdSignIn = async (route: import('@playwright/test').Route) => { await new Promise((r) => setTimeout(r, 1_500)); await route.fallback(); };
  await page.route(`${gw}/auth/device/signin`, holdSignIn);
  await page.locator('#unlock-password').fill(PASSWORD);
  await resetCls(page);
  await page.locator('#unlock-password').press('Enter');
  await expect(page.getByTestId('shell-skeleton-dashboard'), 'DEC-100: the dashboard greyed out while signing in').toBeVisible({ timeout: 15_000 });
  await shot(page, info, '01b-signin-skeleton');
  await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
  await settle(page);
  await page.unroute(`${gw}/auth/device/signin`, holdSignIn);
  await shot(page, info, '01c-signin-dashboard');
  const signinCls = await cls(page);
  report(info, 'signin', signinCls, await shifts(page));
  expect.soft(signinCls, 'sign-in → dashboard: layout shift').toBeLessThan(CLS_MAX);

  // 2. The main pages, each reached in the app (history + popstate, no click), from a page that is already loaded.
  const pages: Array<{ name: string; path: string }> = [
    { name: 'settings', path: '/settings' },
    { name: 'mandates', path: '/mandates' },
    { name: 'connectors', path: '/integrations' },
    { name: 'devices', path: '/devices' },
    { name: 'dashboard', path: '/' },
    // The rest of DEC-98/DEC-100: these showed a plain "Loading…" line and then drew their content.
    { name: 'tickets', path: '/tickets' },
    { name: 'reports', path: '/reports' },
    { name: 'approvals', path: '/approvals' },
  ];
  for (const [i, pg] of pages.entries()) {
    await resetCls(page);
    await resetMixed(page);
    await goInPage(page, pg.path);
    await shotWhileLoading(page, info, `${String(i + 2).padStart(2, '0')}-${pg.name}`);
    await settle(page);
    await shot(page, info, `${String(i + 2).padStart(2, '0')}-${pg.name}-loaded`);
    const v = await cls(page);
    report(info, pg.name, v, await shifts(page));
    expect.soft(v, `${pg.name}: layout shift while it loads`).toBeLessThan(CLS_MAX);
    expect.soft(await mixedCards(page), `${pg.name}: a real card was on screen beside the skeleton`).toEqual([]);
  }

  // The authorise picker (New mandate): its grid of areas, greyed out until the profiles are in.
  await measure(page, info, '10-picker', 'picker', '/mandates?new=1');

  // 3. The give page: the Setup mandate's review card, handed over the way the AI's proposal does it.
  const groups = await (await fetch(`${gw}/api/groups`, { headers })).json() as { groups?: Array<{ id: string; name?: string; isPersonal?: boolean }> };
  const personal = (groups.groups ?? []).find((g) => g.isPersonal);
  expect(personal, 'the person has a personal workspace').toBeTruthy();
  const profiles = await (await fetch(`${gw}/api/profiles`, { headers })).json() as { profiles?: Array<{ id: string }> } | Array<{ id: string }>;
  const list = Array.isArray(profiles) ? profiles : (profiles.profiles ?? []);
  const delegation = list.map((x) => x.id).filter((id) => id.includes('delegation')).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).at(-1);
  expect(delegation, `a delegation profile is offered: ${JSON.stringify(list.map((x) => x.id))}`).toBeTruthy();
  await page.evaluate(({ auth, gate }) => {
    sessionStorage.setItem('agentAuth', JSON.stringify(auth));
    sessionStorage.setItem('agentGate', JSON.stringify(gate));
  }, {
    auth: { profileId: delegation!, groupId: personal!.id, groupName: personal!.name ?? null, domain: 'owner', isPersonal: true },
    gate: { bounds: { profile: delegation!, read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 30 }, context: { allowed_profiles: 'records', allowed_modes: 'review' }, gateContent: { intent: 'The AI prepares the mandates its work needs.' }, ttlConfig: { max: 86400 } },
  });
  // The mandate wizard (scope and limits step) from the same hand-over, then the give page.
  await measure(page, info, '11-wizard', 'wizard', '/mandates/new/intent');
  await measure(page, info, '12-give', 'give', '/mandates/new/sign');

  // DEC-100: no turning mark at any moment of this journey, and the sign-in showed the dashboard greyed out.
  const seen = await page.evaluate(() => { const w = window as unknown as { __spinSeen: boolean; __shellSeen: boolean }; return { spin: w.__spinSeen, shell: w.__shellSeen }; });
  expect.soft(seen.spin, 'DEC-100: the turning mark appeared while loading').toBe(false);
  expect.soft(seen.shell, 'DEC-100: the sign-in showed the dashboard greyed out').toBe(true);
});

/**
 * Simulation mode (a gateway of its own with SUVEREN_SIMULATION=1): the banner is on the unlock screen, the dashboard
 * greyed out after the sign-in carries it from its first frame, and the page does not move down when the real frame
 * replaces the grey one. Password only (no helper needed for this).
 */
test('DEC-100: in simulation mode the banner is there from the first frame after the sign-in (CLS < 0.05)', async ({ page }, info) => {
  test.setTimeout(180_000);
  const simPorts = { cp: Number(process.env.HAP_E2E_SKEL_SIM_CP_PORT ?? 19962), mcp: Number(process.env.HAP_E2E_SKEL_SIM_MCP_PORT ?? 19963) };
  const simDir = mkdtempSync(join(tmpdir(), 'hap-e2e-skeleton-sim-'));
  const simPm = new ProcessManager();
  try {
    const o: StackOptions = {
      dataDir: simDir, ports: simPorts, secret: newSecret(), asUrl: stack.asUrl,
      extraEnv: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1', SUVEREN_SIMULATION: '1' },
    };
    await startControlPlane(simPm, o, 'skel-sim-cp');
    await startMcpServer(simPm, o, 'skel-sim-mcp');
    const saved = gw;
    gw = `http://localhost:${simPorts.cp}`;
    try {
      const health = await (await fetch(`${gw}/health`)).json() as { simulation?: boolean };
      expect(health.simulation, 'the gateway runs in simulation mode').toBe(true);
      const p = await newPerson(stack, 'Simulation person');
      const headers = await signInAndSetPassword(p);
      const start = await fetch(`${gw}/auth/device/setup/start`, { method: 'POST', headers, body: JSON.stringify({ label: 'Office computer', checkKey: false }) });
      const sb = (await start.json()) as { setupId: string };
      expect(start.status, JSON.stringify(sb)).toBe(200);
      const fin = await fetch(`${gw}/auth/device/setup/finish`, { method: 'POST', headers, body: JSON.stringify({ setupId: sb.setupId, enrolmentCode: await enrolmentCode(stack, db, p) }) });
      expect(fin.status, await fin.clone().text()).toBe(200);

      await watchPage(page);
      await slowNetwork(page);
      await page.goto(`${gw}/login`);
      await expect(page.locator('#unlock-password')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('.simulation-banner'), 'the unlock screen says simulation mode').toBeVisible({ timeout: 10_000 });
      await page.waitForTimeout(2_000);
      await shot(page, info, 'sim-01-unlock');

      const holdSignIn = async (route: import('@playwright/test').Route) => { await new Promise((r) => setTimeout(r, 1_500)); await route.fallback(); };
      await page.route(`${gw}/auth/device/signin`, holdSignIn);
      await page.locator('#unlock-password').fill(PASSWORD);
      await resetCls(page);
      await page.locator('#unlock-password').press('Enter');
      const shell = page.getByTestId('shell-skeleton-dashboard');
      await expect(shell, 'the dashboard greyed out while signing in').toBeVisible({ timeout: 15_000 });
      const bannerInShell = await page.evaluate(() => !!document.querySelector('[data-testid="shell-skeleton-dashboard"] .simulation-banner'));
      await shot(page, info, 'sim-02-signin-skeleton');
      expect.soft(bannerInShell, 'the greyed-out frame carries the simulation banner from its first frame').toBe(true);
      await expect(page.locator('.page-title').first()).toBeVisible({ timeout: 30_000 });
      await settle(page);
      await page.unroute(`${gw}/auth/device/signin`, holdSignIn);
      await shot(page, info, 'sim-03-dashboard');
      await expect(page.locator('.simulation-banner')).toBeVisible();
      const v = await cls(page);
      report(info, 'sim-signin', v, await shifts(page));
      expect.soft(v, 'simulation: sign-in → dashboard layout shift').toBeLessThan(CLS_MAX);
    } finally {
      gw = saved;
    }
  } finally {
    await simPm.killAll();
    rmSync(simDir, { recursive: true, force: true });
  }
});
