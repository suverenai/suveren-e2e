/**
 * Core objects — approvals, mandates, tickets (Suveren UI spec §12). Real stack: AS +
 * gateway + the CRM connector; the agent is a real MCP client.
 *
 *   setup  an automatic customers mandate → 3 contacts created (automatic
 *          tickets); then a review mandate → 2 contacts proposed (waiting)
 *   A      dashboard: waiting for you (2), done automatically (3 × Contact
 *          created, 3 new), mandates at work today (3 of 20)
 *   B      "Automatic tickets" lands on Tickets filtered to Automatic; the
 *          three are marked new; Approved is empty
 *   C      after that visit the dashboard shows the group as seen
 *   (UI3)  each approval reads as one sentence from the manifest template
 *   D      a dashboard row opens that approval in place on the Approvals
 *          page; approving it opens the next one; its ticket is "Approved"
 */
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import type { APIRequestContext, Page } from '@playwright/test';
import {
  test, expect,
  SP_URL, GW_MCP_URL, INTERNAL_SECRET,
  registerOnSP, signInToGateway, handleOnboarding, activateIntegration,
  spApiAttest, latestProfileId,
} from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOT_DIR = join(__dirname, '..', 'test-results', 'core-objects');
mkdirSync(SCREENSHOT_DIR, { recursive: true });

// Runs only against a gateway with the core-objects UI (CI runs the journeys
// against the gateway's main branch, which may not have it yet).
const HAS_CORE = existsSync(join(__dirname, '..', '..', 'suveren-gateway', 'apps', 'ui', 'src', 'lib', 'core-objects.ts'));
// UI spec §13 (gateway 0.32.0): areas first, tools second.
// UI spec §14: automatic tickets show what was sent.
const HAS_TICKET_CONTENT = existsSync(join(__dirname, '..', '..', 'suveren-gateway', 'apps', 'mcp-server', 'src', 'lib', 'ticket-content.ts'));
const HAS_AREAS = existsSync(join(__dirname, '..', '..', 'suveren-gateway', 'apps', 'ui', 'src', 'lib', 'area.ts'));
/**
 * The area name the gateway must show: the newest customers profile's own
 * `name`, as the Authority Server lists it (what the gateway receives).
 */
async function customersAreaName(request: APIRequestContext): Promise<string> {
  const { profiles } = await (await request.get(`${SP_URL}/api/profiles`)).json() as { profiles: Array<{ id: string; name?: string }> };
  const ver = (id: string) => id.slice(id.indexOf('@') + 1).split('.').map(Number);
  const newest = profiles
    .filter(p => /\/customers@/.test(p.id))
    .sort((x, y) => ver(y.id)[0] - ver(x.id)[0] || ver(y.id)[1] - ver(x.id)[1])[0];
  expect(newest?.name, 'the AS lists the profile name (suveren-as: /api/profiles returns name)').toBeTruthy();
  return newest.name as string;
}

const CUSTOMERS_PROFILE = latestProfileId('customers');
const KEY_ORDER = ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max'];
const SCOPE = { contact_type: 'customer' };
const BOUNDS = { profile: CUSTOMERS_PROFILE, read_access: 'unlimited', export_access: 'none', write_daily_max: 20, delete_daily_max: 0, setup_daily_max: 0 };

async function mandate(request: APIRequestContext, apiKey: string, did: string, mode: 'automatic' | 'review', intent: string): Promise<void> {
  const boundsHash = computeBoundsHash(BOUNDS, KEY_ORDER);
  const scopeHash = computeScopeHash(SCOPE, Object.keys(SCOPE));
  const att = await spApiAttest(request, apiKey, {
    profile_id: CUSTOMERS_PROFILE, domain: 'owner', did,
    bounds: BOUNDS, bounds_hash: boundsHash, scope_hash: scopeHash,
    gate_content_hashes: hashGateContent({ intent }),
    execution_context_hash: 'sha256:' + 'd'.repeat(64),
    commitment_mode: mode,
    title: mode === 'automatic' ? 'Customer care' : 'Customer review',
  });
  expect(att.status).toBe('active');
  const res = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
    body: JSON.stringify({
      authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: SCOPE,
      path: CUSTOMERS_PROFILE, gateContent: { intent },
    }),
  });
  expect(res.ok, await res.text()).toBe(true);
}

async function createContacts(names: string[]): Promise<void> {
  const client = new Client({ name: 'core-objects-agent', version: '1.0.0' }, { capabilities: {} });
  await client.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  try {
    for (const name of names) {
      const res = await client.callTool({
        name: 'crm__create_contact',
        arguments: { name, email: `${name.toLowerCase().replace(/\W+/g, '.')}@core-objects.de`, type: 'customer' },
      });
      const body = ((res.content as Array<{ text?: string }>) ?? [])[0]?.text ?? '';
      expect(res.isError, body).toBeFalsy();
    }
  } finally {
    await client.close();
  }
}

async function goDashboard(page: Page): Promise<void> {
  await page.click('.sidebar-item:has-text("Dashboard")');
  await expect(page.getByTestId('core-cols')).toBeVisible({ timeout: 30_000 });
}

test.describe.serial('Core objects — dashboard, tickets, approvals (real stack)', () => {
  test.skip(!HAS_CORE, 'gateway without the core-objects UI (UI spec §12)');
  let apiKey: string;
  let page: Page;
  test.beforeAll(async ({ browser }) => { page = await browser.newPage(); });
  test.afterAll(async () => { await page?.close(); });

  test('setup: 3 automatic tickets, then 2 approvals waiting', async ({ request }) => {
    test.setTimeout(240_000);
    apiKey = await registerOnSP(page, 'Core Objects');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    const did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'CRM');

    await mandate(request, apiKey, did, 'automatic', 'Core objects e2e: keep customers up to date.');
    await createContacts(['Anna Auto', 'Bernd Auto', 'Clara Auto']);
    // Created after the seeding: when both match, the review mandate wins.
    await mandate(request, apiKey, did, 'review', 'Core objects e2e: review new customers.');
    await createContacts(['Dora Review', 'Emil Review']);
  });

  test('A: the dashboard shows what waits, what ran automatically, and the mandate at work', async () => {
    test.setTimeout(90_000);
    await goDashboard(page);
    const waiting = page.getByTestId('col-waiting');
    await expect(waiting.getByTestId('dash-approval')).toHaveCount(2, { timeout: 30_000 });
    // §18.5: the Approvals page's own row — type line with the age ("4 min"), no "waiting" word.
    await expect(waiting.getByTestId('dash-approval').first().getByTestId('approval-row')).toBeVisible();
    // UI3: the sentence comes from the manifest's summary template + the
    // sealed values ("Create contact Dora Review"), not just the action name.
    await expect(waiting.getByTestId('dash-approval').filter({ hasText: 'Create contact Dora Review' })).toHaveCount(1, { timeout: 30_000 });
    await expect(waiting.getByTestId('dash-approval').filter({ hasText: 'Create contact Emil Review' })).toHaveCount(1);

    const auto = page.getByTestId('col-automatic');
    const group = auto.getByTestId('auto-group').filter({ hasText: 'Contact created' }).first();
    await expect(group).toContainText('3 × Contact created', { timeout: 30_000 });
    await expect(group).toContainText('3 new');
    await expect(group).toContainText('Customer care');

    const atWork = page.getByTestId('col-mandates').getByTestId('mandate-at-work').filter({ hasText: 'Customer care' });
    await expect(atWork).toContainText('3 of 20 used today', { timeout: 30_000 });
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'a-dashboard.png'), fullPage: true });
  });

  test('B: "Automatic tickets" lands on Tickets filtered to Automatic, marked new', async () => {
    test.setTimeout(60_000);
    await page.getByTestId('btn-automatic-tickets').click();
    await page.waitForURL(/\/tickets\?filter=automatic/);
    await expect(page.getByTestId('tickets-filter-automatic')).toHaveAttribute('aria-selected', 'true');
    const rows = page.locator('.ticket-obj-card');
    await expect(rows).toHaveCount(3, { timeout: 30_000 });
    await expect(rows.filter({ hasText: 'automatic' })).toHaveCount(3);
    await expect(page.locator('.ticket-obj-card[data-new="true"]')).toHaveCount(3);
    await expect(page.getByTestId('tickets-new-count')).toContainText('3 new');
    await expect(page.getByTestId('tickets-filter-approved')).toContainText('0');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'b-tickets-automatic.png'), fullPage: true });
  });

  test('C: after that visit, the dashboard shows the group as seen', async () => {
    test.setTimeout(60_000);
    await goDashboard(page);
    const group = page.getByTestId('col-automatic').getByTestId('auto-group').filter({ hasText: 'Contact created' }).first();
    await expect(group).toHaveClass(/is-seen/, { timeout: 30_000 });
    await expect(group).toContainText('seen');
  });

  test('D: a dashboard row opens that approval in place; approving opens the next; its ticket is Approved', async () => {
    test.setTimeout(120_000);
    await goDashboard(page);
    await page.getByTestId('col-waiting').getByTestId('dash-approval').first().locator('.appr-item-head').click();
    await page.waitForURL(/\/approvals\?open=/);
    // Approval panel: ?open=<id> shows that approval's card in the panel, "1 of 2".
    const openId = new URL(page.url()).searchParams.get('open');
    const panel = page.getByTestId('approval-panel');
    const cards = panel.getByTestId('approval-card');
    await expect(cards).toHaveCount(1, { timeout: 30_000 });
    await expect(cards.first()).toHaveAttribute('data-proposal-id', openId!);
    await expect(cards.first().getByTestId('approval-summary')).toHaveText(/^Create contact (Dora|Emil) Review$/, { timeout: 30_000 });
    await expect(page.getByTestId('approval-position')).toContainText('of 2');
    // The Approvals page is a list only: both, one sentence each (behind the panel).
    const rows = page.getByTestId('approval-row');
    await expect(rows).toHaveCount(2, { timeout: 30_000 });
    await expect(page.getByTestId('approval-row-summary').filter({ hasText: /^Create contact (Dora|Emil) Review$/ })).toHaveCount(2, { timeout: 30_000 });
    // "Later" sends the panel to the strip; a list row brings its approval back.
    await page.getByTestId('approval-later').click();
    await expect(panel).toHaveAttribute('aria-hidden', 'true');
    await page.locator(`[data-testid="approval-row"][data-proposal-id="${openId}"] .appr-item-head`).click();
    await expect(cards.first()).toHaveAttribute('data-proposal-id', openId!, { timeout: 15_000 });

    await cards.first().locator('button:has-text("Approve")').click();
    // The ✓ stamp shows only once the gateway has answered; then the remaining card slides in by itself.
    await expect(page.getByTestId('decision-stamp')).toContainText('Approved', { timeout: 30_000 });
    await expect(cards.first()).not.toHaveAttribute('data-proposal-id', openId!, { timeout: 15_000 });
    await expect(cards).toHaveCount(1);
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'd-next-opened.png'), fullPage: true });
    // The last approval waits: send the panel away so it does not cover the pages below.
    await page.getByTestId('approval-later').click();
    await expect(panel).toHaveAttribute('aria-hidden', 'true');

    await page.click('.sidebar-item:has-text("Tickets")');
    await page.waitForURL('**/tickets');
    await page.getByTestId('tickets-filter-approved').click();
    await expect(page.locator('.ticket-obj-card')).toHaveCount(1, { timeout: 30_000 });
    await expect(page.locator('.ticket-obj-card').first()).toContainText(/approved/i);
    // The approved ticket's headline is the sentence the approver saw (from the
    // proposal's sealed values), not only the action's name.
    if (HAS_AREAS) {
      await expect(page.locator('.ticket-obj-card').first().getByTestId('ticket-headline'))
        .toHaveText(/^Create contact (Dora|Emil) Review$/, { timeout: 30_000 });
    }
  });
  test('E: areas first, tools second — area + "via CRM" on the top line, the mandate name underneath', async ({ request }) => {
    test.skip(!HAS_AREAS, 'gateway without UI spec §13 (areas)');
    test.setTimeout(90_000);
    const area = await customersAreaName(request);
    await goDashboard(page);
    const group = page.getByTestId('col-automatic').getByTestId('auto-group').filter({ hasText: 'Contact created' }).first();
    await expect(group.locator('.obj-line')).toContainText(area, { timeout: 30_000 });
    await expect(group.locator('.obj-line')).toContainText('via CRM');
    // The mandate's own name is a separate line, under the headline — never the area.
    await expect(group.getByTestId('mandate-line')).toHaveText('Mandate: Customer care');
    await expect(group.locator('.obj-line')).not.toContainText('Customer care');
    // Each mandate at work shows its own name; the area is the same for both.
    const atWork = page.getByTestId('col-mandates').getByTestId('mandate-at-work');
    await expect(atWork.filter({ hasText: 'Customer care' })).toHaveCount(1);
    await expect(atWork.filter({ hasText: 'Customer care' }).locator('.obj-line')).toContainText(area);
    // §18.5: the approval row's quiet line carries the mandate name (as on the Approvals page).
    await expect(page.getByTestId('col-waiting').getByTestId('dash-approval').first()).toContainText('Customer review');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'e-dashboard-areas.png'), fullPage: true });

    // Approvals: the one left after D carries its mandate's name underneath.
    await page.click('.sidebar-item:has-text("Approvals")');
    await page.waitForURL('**/approvals**');
    // One approval left: its card opens directly. Type line names the area; "Covered by" the mandate.
    // On the Approvals page (the list) a row brings the panel back; elsewhere it is the strip.
    await page.getByTestId('approval-row').first().locator('.appr-item-head').click();
    const card = page.getByTestId('approval-panel').getByTestId('approval-card');
    await expect(card.getByTestId('approval-type')).toContainText(area, { timeout: 30_000 });
    await expect(card.getByTestId('covered-by')).toContainText('Customer review');
    await page.getByTestId('approval-later').click();

    // Tickets: one area only → no area pills (nothing to choose between).
    await page.click('.sidebar-item:has-text("Tickets")');
    await page.waitForURL('**/tickets');
    await expect(page.locator('.ticket-obj-card').first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId('area-filter')).toHaveCount(0);
    await expect(page.locator('.ticket-obj-card').first().locator('.obj-line')).toContainText(area);
    await expect(page.locator('.ticket-obj-card').first().locator('.obj-line')).toContainText('via CRM');

    // Search: typing never blanks the page (2026-10-17: a ticket without
    // path/attestationHash threw), and it finds what the row shows.
    const errors: string[] = [];
    page.on('pageerror', e => errors.push(e.message));
    const search = page.getByTestId('tickets-search');
    await search.fill('contact');
    await expect(page.locator('.ticket-obj-card').first()).toBeVisible();
    await search.fill('zzz-nothing-matches');
    await expect(page.locator('.ticket-obj-card')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Tickets' })).toBeVisible();
    await search.fill('');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'e-tickets-search.png'), fullPage: true });
    expect(errors).toEqual([]);

    // Mandates: grouped by area, heading with the area name and the tool.
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates');
    const grp = page.locator('[data-testid="mandate-area"][data-area="customers"]');
    await expect(grp.locator('.area-group-h')).toContainText(area, { timeout: 30_000 });
    await expect(grp.locator('.area-group-h')).toContainText('via CRM');
    // Cards under their area heading do not repeat the area.
    // (§18: the area sits in the type line; the title is the mandate name alone.)
    await expect(grp.locator('.mandate-card .ob-title').first()).not.toContainText(area);
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'e-mandates-areas.png'), fullPage: true });

    // Connectors: one card for the CRM, with the area as a chip.
    await page.click('.sidebar-item:has-text("Connectors")');
    await page.waitForURL('**/integrations');
    const crmCard = page.locator('.card', { has: page.locator('.card-title', { hasText: /^CRM/ }) }).first();
    const chip = crmCard.locator('[data-testid="integration-areas"] [data-area="customers"]');
    await expect(chip).toContainText(area, { timeout: 30_000 });
    await expect(crmCard).toContainText('CRM');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'e-integrations-areas.png'), fullPage: true });
  });
  test('F: an automatic ticket shows its sentence, what was sent (sealed, checked) and what the CRM answered', async () => {
    test.skip(!HAS_TICKET_CONTENT, 'gateway without UI spec §14 (ticket content)');
    test.setTimeout(90_000);
    await page.click('.sidebar-item:has-text("Tickets")');
    await page.waitForURL('**/tickets**');
    await page.getByTestId('tickets-filter-automatic').click();
    const cards = page.locator('.ticket-obj-card');
    await expect(cards).toHaveCount(3, { timeout: 30_000 });
    // The headline is the manifest's sentence filled from what was sent.
    const anna = cards.filter({ has: page.getByTestId('ticket-headline').filter({ hasText: /^Create contact Anna Auto$/ }) });
    await expect(anna).toHaveCount(1, { timeout: 30_000 });
    await anna.locator('.ticket-obj-head').click();
    const sent = anna.getByTestId('ticket-what-was-done');
    await expect(sent).toHaveAttribute('data-bound', 'sealed', { timeout: 30_000 });
    await expect(sent).toContainText(/sealed in the ticket/i);
    await expect(sent).toContainText('Anna Auto');
    await expect(sent).toContainText('Matches the fingerprint in the signed ticket');
    await expect(anna.getByTestId('ticket-result')).toHaveAttribute('data-ok', 'true');
    await expect(anna.getByTestId('ticket-result')).toContainText('what CRM answered');
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'f-ticket-content.png'), fullPage: true });
  });

  test('G: tickets by day, new ones marked; the closed menu counts readably and pushes the page without reflowing it', async () => {
    test.setTimeout(90_000);
    // Tickets cannot be back-dated on the wire, so the display of earlier days gets older timestamps here. Display only.
    await page.route('**/api/tickets/mine*', async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      const list: Array<{ timestamp: number }> = Array.isArray(body) ? body : (Object.values(body).find(Array.isArray) as Array<{ timestamp: number }>);
      list.forEach((t, i) => { if (i >= 2) t.timestamp -= i >= 4 ? 3 * 86_400 : 86_400; });
      await route.fulfill({ response: res, json: body });
    });
    await page.setViewportSize({ width: 900, height: 800 });
    await goDashboard(page);
    await page.click('.sidebar-item[href="/tickets"]');
    await page.waitForURL('**/tickets**');

    const days = page.getByTestId('ticket-day');
    await expect(days.first()).toContainText('Today', { timeout: 30_000 });
    await expect(days.nth(1)).toContainText('Yesterday');
    await expect(days.first().locator('.ticket-obj-card.is-quiet')).toHaveCount(0);
    await expect(days.nth(1).locator('.ticket-obj-card.is-quiet').first()).toBeVisible();
    await page.mouse.move(800, 700);
    await expect.poll(async () => (await page.locator('.sidebar').boundingBox())!.width).toBeCloseTo(56, 0);
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'g-days.png'), fullPage: true });
    // A quiet line opens into the full ticket.
    const quiet = days.nth(1).locator('.ticket-obj-card').first();
    await quiet.locator('.ticket-obj-head').click();
    await expect(quiet).toHaveClass(/is-open/);
    await expect(quiet).not.toHaveClass(/is-quiet/);

    // The counter on the closed menu is big enough to read.
    await page.mouse.move(800, 700);
    await expect.poll(async () => (await page.locator('.sidebar').boundingBox())!.width).toBeCloseTo(56, 0);
    const counter = page.locator('.sidebar .nav-count:visible').first();
    await expect(counter).toBeVisible();
    expect((await counter.boundingBox())!.height).toBeGreaterThanOrEqual(20);
    expect(parseFloat(await counter.evaluate(e => getComputedStyle(e).fontSize))).toBeGreaterThanOrEqual(12);
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'g-rail-closed.png') });

    // Opening the menu moves the page right; it keeps its width; no sideways scrolling.
    const main = page.locator('.main-content');
    await page.mouse.move(800, 700);
    await expect.poll(async () => (await main.boundingBox())!.x).toBeCloseTo(56, 0); // settled: the 3.5rem rail
    const before = (await main.boundingBox())!;
    await page.hover('.sidebar');
    await expect.poll(async () => (await main.boundingBox())!.x).toBeCloseTo(240, 0); // the 15rem menu
    const after = (await main.boundingBox())!;
    expect(after.width).toBe(before.width);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: join(SCREENSHOT_DIR, 'g-rail-open.png') });

    await page.mouse.move(800, 700);
    await page.unroute('**/api/tickets/mine*');
    await page.setViewportSize({ width: 1280, height: 720 });
  });
});
