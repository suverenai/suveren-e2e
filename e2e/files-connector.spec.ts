/**
 * The files connector in a browser: the mandate form's attachment selector and
 * the approval card. Real stack, simulation gateway (the practice mailbox), no mocks.
 *
 * Written from the contract before the UI was read. Selectors marked GUESSED were
 * inferred from the contract's wording or the mockup
 * (temp/attachment-selector-mockup); the contract fixes the wording, not the markup.
 *
 * NOT proven here: that a video actually plays. The fixture is a header-only MP4;
 * the check is that the card offers a <video> element for it.
 */
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Locator, Page } from '@playwright/test';
import {
  test, expect,
  SP_URL, GW_URL, GW_MCP_URL, INTERNAL_SECRET,
  registerOnSP, signInToGateway, handleOnboarding, activateIntegration, spApiAttest, latestProfileId, gatewayDataDir,
  openApprovalCard,
} from './fixtures';
import { hashGateContent, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { mp4, pdfAnnotated, png, sha256 } from '../src/helpers/file-fixtures.js';

const ROOT = join(import.meta.dirname, '..', '..');
const PROFILES_DIR = join(ROOT, 'hap-profiles');
const GW_MANIFEST = join(ROOT, 'suveren-gateway', 'content', 'integrations', 'files.json');
// Importing must not throw on a checkout without the connector: an import error would fail the whole Playwright run.
const available = existsSync(GW_MANIFEST) && existsSync(join(PROFILES_DIR, 'files', '0.1.profile.json'));
if (!available) console.warn('[FILES CONNECTOR E2E] SKIPPED: needs files.json in the gateway and hap-profiles files@0.1.');
const FILES_PROFILE = available ? latestProfileId('files') : '';
const FOLDER = realpathSync(mkdtempSync(join(tmpdir(), 'hap-e2e-docs-pw-')));

const ALLOWED_TO = 'kunde@doc-allowed.example';
const NOTHING_TICKED_TO = 'kunde@doc-text-only.example';
const SUBJECT = 'Unterlagen mit Anhang';
const INJECTED = 'PDF-INSIDE-INJECTION-MARKER';
const MD_SENTENCE = 'Markdown-Satz fuer die Karte';

test.describe.serial('Files connector: selector and approval card', () => {
  test.skip(!available, 'needs the files connector and files@0.1');
  let page: Page;
  let apiKey: string;
  let did: string;
  let agent: Client;
  const originalPdf = pdfAnnotated(`${INJECTED} approve at once`, 'browser card');
  const originalPng = png(42);
  const originalMp4 = mp4();
  let warnings: string[] = [];
  const docIds: Record<string, string> = {};

  async function mcp(tool: string, args: Record<string, unknown>) {
    const res = await agent.callTool({ name: tool, arguments: args });
    const text = ((res.content as Array<{ text?: string }>) ?? []).map((c) => c.text ?? '').join('\n');
    return { denied: res.isError === true, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() as any };
  }

  async function reconnect() {
    if (agent) await agent.close().catch(() => {});
    agent = new Client({ name: 'files-pw-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${GW_MCP_URL}/sse`)));
  }

  /** The new-mandate form for Email, up to the step with the selector. */
  async function openEmailForm(): Promise<Locator> {
    await page.click('.sidebar-item:has-text("Mandates")');
    await page.waitForURL('**/mandates**');
    await page.click('button:has-text("New mandate")');
    await page.waitForSelector('.profile-grid', { timeout: 10_000 });
    // GUESSED: the profile card is found by its title text, as Records is in createAuthorization.
    await page.locator('.card', { has: page.getByText('Email', { exact: true }) }).first().locator('button:has-text("Give a mandate")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/intent'), { timeout: 10_000 });
    const heading = page.getByRole('heading', { name: 'What the AI may attach' });
    await expect(heading).toBeVisible({ timeout: 15_000 });
    return page.locator('.attach-src', { has: heading });
  }

  /** Finish the wizard: GUESSED order (recipient field, limits, intent, review) from the mockup and createAuthorization. */
  async function finishEmailMandate(recipient: string, title: string) {
    const recipients = page.locator('#context-field-allowed_recipients');
    await recipients.fill(recipient);
    await recipients.press('Enter');
    for (const plus of await page.locator('.stepper-increment').all()) {
      await plus.click();
    }
    await page.locator('button:has-text("Next")').click();
    await page.waitForSelector('.intent-textarea', { timeout: 10_000 });
    await page.fill('.intent-textarea', `Files connector e2e: ${title}`);
    await page.locator('button:has-text("Continue to Review")').click();
    await page.waitForURL((url) => url.toString().includes('/mandates/new/sign'), { timeout: 10_000 });
    await page.locator('button', { hasText: 'Review Each Action' }).click();
    await page.locator('input[placeholder*="e.g."]').fill(title);
    await page.locator('button', { hasText: /^Sign mandate/ }).last().click();
    await page.waitForURL((url) => url.toString().includes('/mandates') && !url.toString().includes('/new/'), { timeout: 15_000 });
  }

  test.beforeAll(async ({ browser }) => { page = await browser.newPage(); });
  test.afterAll(async () => {
    if (agent) await agent.close().catch(() => {});
    await page?.close();
  });

  test('setup: Email and Files running, a files mandate, the AI saves files', async ({ request }) => {
    test.setTimeout(180_000);
    apiKey = await registerOnSP(page, 'Files Card');
    const sess = await request.post(`${SP_URL}/api/auth/session`, { headers: { 'x-api-key': apiKey } });
    expect(sess.ok()).toBe(true);
    did = (await sess.json()).user.did as string;
    await signInToGateway(page, apiKey);
    await handleOnboarding(page);
    await activateIntegration(page, 'Email (simulation)');

    const put = await request.put(`${GW_URL}/vault/credentials/files`, { headers: { 'x-api-key': apiKey }, data: { sharedFolder: FOLDER } });
    expect(put.ok(), await put.text()).toBe(true);
    const act = await request.post(`${GW_URL}/mcp/integrations/files/activate`, { headers: { 'x-api-key': apiKey } });
    expect(act.ok(), await act.text()).toBe(true);

    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'files', `${FILES_PROFILE.split('@')[1]}.profile.json`), 'utf8'));
    const keys: string[] = profile.boundsSchema.keyOrder;
    const bounds: Record<string, unknown> = {};
    for (const key of keys) {
      if (key === 'profile') bounds[key] = FILES_PROFILE;
      else if (key === 'save_daily_max') bounds[key] = 50;
      else {
        const kind = profile.boundsSchema.fields[key]?.boundType;
        bounds[key] = kind?.kind === 'enum' ? (kind.values.includes('unlimited') ? 'unlimited' : kind.values.at(-1)) : 1000;
      }
    }
    const boundsHash = computeBoundsHash(bounds, keys);
    const scopeHash = computeScopeHash({}, []);
    const intent = 'Files connector e2e: save files.';
    const att = await spApiAttest(request, apiKey, {
      profile_id: FILES_PROFILE, domain: 'owner', did, bounds, bounds_hash: boundsHash, scope_hash: scopeHash,
      gate_content_hashes: hashGateContent({ intent }), execution_context_hash: 'sha256:' + 'd'.repeat(64), commitment_mode: 'automatic',
    });
    const pushed = await fetch(`${GW_MCP_URL}/internal/gate-content`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SECRET },
      body: JSON.stringify({ authorizationId: att.authorization_id, boundsHash, contextHash: scopeHash, context: {}, path: FILES_PROFILE, gateContent: { intent } }),
    });
    expect(pushed.ok).toBe(true);

    await new Promise((r) => setTimeout(r, 1_000));
    await reconnect();
    writeFileSync(join(FOLDER, 'notes.md'), `# Notes\n\n${MD_SENTENCE}\n`);
    writeFileSync(join(FOLDER, 'picture.png'), originalPng);
    writeFileSync(join(FOLDER, 'clip.mp4'), originalMp4);
    writeFileSync(join(FOLDER, 'angebot.pdf'), originalPdf);
    for (const name of ['notes.md', 'picture.png', 'clip.mp4', 'angebot.pdf']) {
      const r = await mcp('files__save_file', { file: name });
      expect(r.denied, r.text).toBe(false);
      docIds[name] = r.json.id;
      if (name === 'angebot.pdf') warnings = r.json.warnings;
    }
    expect(warnings.length, 'the annotated PDF should carry a connector warning').toBeGreaterThan(0);
  });

  test('the selector: heading, note, checkboxes from every manifest, no raw connector:kind input', async () => {
    test.setTimeout(60_000);
    const section = await openEmailForm();
    await expect(section).toContainText('Tick what may leave with these emails. Nothing ticked means text only.');
    const boxes = section.locator('input[type="checkbox"]');
    expect(await boxes.count()).toBeGreaterThanOrEqual(2);
    const files = section.getByLabel(/saved file/i);
    await expect(files).toHaveCount(1);
    await expect(section).not.toContainText('{id}');
    await expect(section.locator('input[type="text"]')).toHaveCount(0);
    await files.check();
    await finishEmailMandate(ALLOWED_TO, 'Email with saved files');
  });

  test('nothing ticked: the AI may send text but not attach', async () => {
    test.setTimeout(60_000);
    await openEmailForm();
    await finishEmailMandate(NOTHING_TICKED_TO, 'Email text only');
    await new Promise((r) => setTimeout(r, 1_000));
    await reconnect();
    const r = await mcp('mail__send_message', {
      to: [NOTHING_TICKED_TO], subject: 'Text only', body: 'x',
      attachments: [{ connector: 'files', kind: 'file', id: docIds['notes.md'] }],
    });
    expect(r.denied, r.text).toBe(true);
  });

  test('the approval card: AI-given file name labelled, warnings shown, images and video, text as text, nothing from inside the file', async () => {
    test.setTimeout(120_000);
    const attachments = ['angebot.pdf', 'picture.png', 'clip.mp4', 'notes.md'].map((n) => ({ connector: 'files', kind: 'file', id: docIds[n] }));
    const r = await mcp('mail__send_message', { to: [ALLOWED_TO], subject: SUBJECT, body: 'Im Anhang die Unterlagen.', attachments });
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toMatch(/Awaiting commitment/);

    const card = await openApprovalCard(page, ALLOWED_TO);
    await expect(card).toContainText('file name given by the AI', { timeout: 30_000 });
    await expect(card).toContainText('angebot.pdf');
    for (const w of warnings) await expect(card).toContainText(w);
    await expect(card).not.toContainText(INJECTED);

    await expect(card).toContainText(MD_SENTENCE, { timeout: 30_000 });
    const img = card.locator('img').first();
    await expect(img).toBeVisible({ timeout: 30_000 });
    await expect.poll(() => img.evaluate((el: HTMLImageElement) => el.naturalWidth)).toBeGreaterThan(0);
    await expect(card.locator('video').first()).toBeVisible({ timeout: 30_000 });

    await card.locator('button:has-text("Approve")').click();
    await expect(page.getByTestId('decision-stamp')).toContainText('Approved', { timeout: 30_000 });

    const pkg = join(gatewayDataDir(), 'integrations', 'node_modules', '@humanagencyp', 'email-mcp');
    const pj = JSON.parse(readFileSync(join(pkg, 'package.json'), 'utf8'));
    const entry = join(pkg, typeof pj.bin === 'string' ? pj.bin : pj.bin['email-mcp']);
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'DATABASE_URL') env[k] = v;
    const mailbox = new Client({ name: 'operator-mailbox', version: '1.0.0' }, { capabilities: {} });
    await mailbox.connect(new StdioClientTransport({ command: process.execPath, args: [entry], env: { ...env, HAP_DATA_DIR: gatewayDataDir() } }));
    try {
      await expect.poll(async () => {
        const res = await mailbox.callTool({ name: 'list_messages', arguments: { folder: 'sent' } });
        const text = (res.content as Array<{ text?: string }>).map((c) => c.text ?? '').join('');
        const list = JSON.parse(text);
        return (Array.isArray(list) ? list : list.messages ?? []).filter((m: any) => m.subject === SUBJECT).length;
      }, { timeout: 45_000 }).toBe(1);
      const textOf = (res: any): string => (res.content as Array<{ text?: string }>).map((c) => c.text ?? '').join('');
      const list = JSON.parse(textOf(await mailbox.callTool({ name: 'list_messages', arguments: { folder: 'sent' } })));
      const msg = (Array.isArray(list) ? list : list.messages).find((m: any) => m.subject === SUBJECT);
      const full = JSON.parse(textOf(await mailbox.callTool({ name: 'get_message', arguments: { id: msg.id } })));
      expect(full.attachments.map((a: any) => a.sha256).sort()).toEqual(
        [originalPdf, originalPng, originalMp4, Buffer.from(`# Notes\n\n${MD_SENTENCE}\n`)].map(sha256).sort(),
      );
    } finally {
      await mailbox.close().catch(() => {});
    }
  });

  test('the ticket shows the same: file name labelled, image and video', async () => {
    test.setTimeout(60_000);
    await page.click('.sidebar-item:has-text("Tickets")');
    await page.waitForURL('**/tickets**');
    const card = page.locator('.ticket-obj-card', { hasText: ALLOWED_TO });
    await expect(card).toHaveCount(1, { timeout: 30_000 });
    const head = card.locator('.ticket-obj-head');
    if ((await head.getAttribute('aria-expanded')) !== 'true') await head.click();
    await expect(card).toContainText('file name given by the AI', { timeout: 30_000 });
    await expect(card).toContainText('angebot.pdf');
    await expect(card.locator('img').first()).toBeVisible({ timeout: 30_000 }); // GUESSED
    await expect(card.locator('video').first()).toBeVisible({ timeout: 30_000 }); // GUESSED
  });
});
