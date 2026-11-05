/**
 * "Issue an invoice, then email it as an attachment" - on the real stack in
 * SIMULATION mode: Authority Server + the whole gateway (control plane + MCP
 * server, SUVEREN_SIMULATION=1) + the published erp-mcp at its default
 * (simulated ERP: it renders invoice PDFs on demand) + the published email-mcp
 * (simulated mailbox, with attachments). Nothing is mocked; no real email.
 *
 * Why simulation: a gateway is EITHER in simulation mode OR in production. The
 * practice mailbox only runs in simulation, and ERP live/local only in
 * production, so "ERP archive PDF -> practice email" cannot exist on one
 * gateway. Do not re-add the mix.
 *  - the production half, ERP live/local issuing an invoice with its write-once
 *    archive (preview = issued file, number consumed only on approval), is
 *    test/invoice-issue-production.test.ts, without a mailbox;
 *  - the production path "ERP archive PDF -> real email" is covered by the
 *    Rehearsal's A3 against a real Gmail test account (passed 2026-11-05).
 *
 * The journey (suveren-invoicing-plan.md section 5-7, UI spec section 15):
 *   1. a sales mandate (automatic), an invoicing mandate (review) and an email
 *      0.9 mandate (review) whose allowed_attachment_sources is
 *      "erp:invoice-pdf", for the customer's domain;
 *   2. the simulated ERP gets a quote -> order (sales), then create_invoice
 *      becomes a proposal; approval -> executed -> the invoice is issued;
 *   3. send_message with attachments [{connector:"erp", kind:"invoice-pdf",
 *      id:<invoice number>}] becomes a proposal; the card data carries the
 *      SEALED attachment (filename, sha256 = the rendered PDF's), the
 *      attachment preview route answers the same file, and the body is declared
 *      AI text (display.aiText);
 *   4. approval -> executed -> the simulated mailbox holds exactly that PDF; the
 *      ticket's content binding commits to the attachment's fingerprint;
 *   5. negatives - (a) email 0.8 / 0.9 without allowed sources: refused, nothing
 *      proposed or sent; (b) an undeclared document kind: refused; (c) AI-supplied
 *      bytes / `raw`: refused.
 *
 * NOT covered here: the archived PDF altered on disk after approval (execution
 * refused, outcome "changed") - the simulated ERP keeps no archive, it renders
 * on demand; and a quote PDF as attachment (the simulator has no quote-pdf).
 * Both need ERP live/local, i.e. production, i.e. no practice mailbox. The
 * archive-tamper check is therefore not covered in the suite any more (it needs
 * a real mailbox in production: Rehearsal A3 covers the happy path only).
 * Also NOT covered: inserting a Mollie payment link into the body (`insert`) -
 * needs a real Mollie account (house rule: no mocked Mollie).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { computeContentHash, selectBoundFields } from '@humanagencyp/hap-core';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient, GW_DIR, PROFILES_DIR } from '../src/helpers/gateway-stack.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles.js';

const AS_PORT = 19910;
const MCP_PORT = 19911;
const CP_PORT = 19912;
const AS_URL = `http://localhost:${AS_PORT}`;
const MCP_URL = `http://localhost:${MCP_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;

const ATTACHMENT_SRC = join(GW_DIR, 'apps', 'mcp-server', 'src', 'lib', 'attachment-resolution.ts');
const ERP_MANIFEST = join(GW_DIR, 'content', 'integrations', 'erp.json');
const MAIL_MANIFEST = join(GW_DIR, 'content', 'integrations', 'mail.json');

function readJson(path: string): any {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}
const erpManifest = readJson(ERP_MANIFEST);
const mailManifest = readJson(MAIL_MANIFEST);
const gaps: string[] = [];
if (!existsSync(ATTACHMENT_SRC)) gaps.push('a gateway with attachments by reference (apps/mcp-server/src/lib/attachment-resolution.ts)');
if (!existsSync(join(PROFILES_DIR, 'email', '0.9.profile.json'))) gaps.push('hap-profiles email@0.9');
if (!existsSync(join(PROFILES_DIR, 'invoicing', '0.1.profile.json'))) gaps.push('hap-profiles invoicing@0.1');
if (String(erpManifest?.npmVersion ?? '').localeCompare('0.10.0', undefined, { numeric: true }) < 0) gaps.push('erp.json pinning erp-mcp >= 0.10.0 (the simulator renders invoice PDFs: get_document)');
if (!erpManifest?.documents?.['invoice-pdf']) gaps.push('erp.json declaring documents.invoice-pdf');
if (mailManifest?.attachments?.transport !== 'field') gaps.push('mail.json declaring an attachments transport (email-mcp >= 0.4.0)');
const available = gaps.length === 0;
if (!available) console.warn(`[INVOICE EMAIL E2E] SKIPPED — needs ${gaps.join('; ')}.`);

const SALES = PROFILE_V07.sales;
const SALES_KEYS = ['profile', 'read_access', 'value_max', 'discount_max', 'order_value_daily_max', 'quote_daily_max', 'send_daily_max', 'order_daily_max', 'setup_daily_max'];
const P = 'github.com/humanagencyprotocol/hap-profiles';
const INVOICING = `${P}/invoicing@0.1`;
const EMAIL_09 = `${P}/email@0.9`;
const EMAIL_08 = `${P}/email@0.8`;
const INVOICING_KEYS = ['profile', 'read_access', 'invoice_net_max', 'credit_net_max',
  'invoice_net_monthly_max', 'credit_net_monthly_max', 'invoice_daily_max', 'credit_daily_max'];
const EMAIL_KEYS = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'read_max_age_days', 'setup_daily_max'];
const EMAIL_SCOPE_KEYS_09 = ['allowed_recipients', 'allowed_domains', 'allowed_attachment_sources'];
const EMAIL_SCOPE_KEYS_08 = ['allowed_recipients', 'allowed_domains'];

// Seed for the simulated ERP (loaded by the person through the connector's own
// operator command, never by the AI): one customer, one item.
const COMPANY_DATA = {
  name: 'Muster Beratung e.U.', currency: 'EUR',
  items: [{ id: 'item-1', sku: 'BERATUNG-1', name: 'Beratung', unit: 'Std.', list_price: 120, stock: 1000 }],
  customers: [{ id: 'cust-kunde', name: 'Kunde GmbH', email: 'buchhaltung@kunde-gmbh.example', country: 'AT', credit_limit: 100000, open_balance: 0, payment_terms: 'NET14', currency: 'EUR' }],
};
const CUSTOMER_DOMAIN = 'kunde-gmbh.example';
const CUSTOMER_EMAIL = `buchhaltung@${CUSTOMER_DOMAIN}`;
const CUSTOMER_ID = 'cust-kunde';
const ORDER_NET = 1200;
/** The simulated ERP numbers its invoices itself; set once the invoice is issued. */
let NUMBER = '';
const ATTACHMENT_REF = { connector: 'erp', kind: 'invoice-pdf', id: '' };
const MAIL_BODY = 'Sehr geehrte Damen und Herren,\n\nanbei erhalten Sie unsere Rechnung fuer September.\n\nMit freundlichen Gruessen\nMaria Muster';

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const gw = new GatewayClient(MCP_URL);
const cp = new ControlPlaneClient(CP_URL);
const work = mkdtempSync(join(tmpdir(), 'hap-e2e-inv-mail-'));
const COMPANY_FILE = join(work, 'company.json');
const YEAR = new Date().getFullYear();

let apiKey: string;
let did: string;
let groupId: string;
let agent: Client;
let mailbox: Client;
let previousDisableAuto: string | undefined;

// ── helpers ──────────────────────────────────────────────────────────────

const sha256 = (buf: Buffer) => createHash('sha256').update(buf).digest('hex');

async function call(tool: string, args: Record<string, unknown>) {
  const r = await agent.callTool({ name: tool, arguments: args });
  const text = (r.content as Array<{ text?: string }>)?.map((c) => c.text ?? '').join('\n') ?? '';
  return { denied: r.isError === true, text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
}

function proposalIdOf(text: string): string {
  const m = text.match(/Proposal ID:\s*([^\s.]+)/);
  expect(m, `a "Proposal ID: ..." line in: ${text}`).toBeTruthy();
  return m![1];
}

async function asApi(method: string, path: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}

async function cpGet(path: string) {
  const res = await cp.authed(apiKey, 'GET', path);
  return { status: res.status, body: await res.json().catch(() => null) as any };
}

async function pendingProposals(): Promise<Array<{ id: string; tool: string }>> {
  return ((await asApi('GET', '/api/proposals?domain=owner')).body.proposals ?? [])
    .filter((p: { status: string }) => p.status === 'pending');
}

async function commit(proposalId: string) {
  const r = await asApi('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner' });
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
}

async function reject(proposalId: string) {
  await asApi('POST', `/api/proposals/${proposalId}/resolve`, { action: 'reject', domain: 'owner' });
}

/** After approval: the gateway's executor (poll or this call) runs it once. */
async function awaitExecution(proposalId: string): Promise<{ denied: boolean; text: string }> {
  const until = Date.now() + 40_000;
  let last = { denied: false, text: '' };
  while (Date.now() < until) {
    last = await call('check-pending-commitments', { proposal_id: proposalId });
    if (/executed|refused|failed|nothing was done|Refused/i.test(last.text) && !/Awaiting|pending/i.test(last.text.split('\n')[0])) return last;
    await new Promise((r) => setTimeout(r, 1_000));
  }
  return last;
}

function resultJson(text: string): any {
  const i = text.indexOf('Result:');
  expect(i, `a "Result:" in: ${text}`).toBeGreaterThanOrEqual(0);
  return JSON.parse(text.slice(i + 'Result:'.length).trim());
}

/** The proposal's own args as the approval card reads them (PE1: decrypted on this gateway). */
async function cardArgs(proposalId: string): Promise<Record<string, any>> {
  const { body } = await asApi('GET', `/api/proposals/${proposalId}`);
  const p = body.proposal;
  if (p.toolArgs) return p.toolArgs;
  const res = await cp.authed(apiKey, 'POST', '/api/decrypt-proposal-content', p.content);
  const dec = await res.json() as { plaintext?: string; error?: string };
  expect(res.status, JSON.stringify(dec)).toBe(200);
  return JSON.parse(dec.plaintext!);
}

async function grant(profileId: string, keys: string[], bounds: Record<string, unknown>,
  scope: Record<string, string>, scopeKeys: string[], intent: string, mode: 'review' | 'automatic' = 'review'): Promise<string> {
  const boundsHash = computeBoundsHash(bounds, keys);
  const contextHash = computeScopeHash(scope, scopeKeys);
  const gate = { intent };
  const att = await sp.submitMandate(apiKey, {
    profile_id: profileId, profile_hash: profileHashFor(profileId, PROFILES_DIR), group_id: groupId,
    bounds, bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did,
    commitment_mode: mode, gate_content_hashes: hashGateContent(gate),
    execution_context_hash: hashExecutionContext({ intent }),
  });
  await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, profileId, gate);
  return att.authorization_id;
}

function emailBounds(profileId: string) {
  return { profile: profileId, read_access: 'unlimited', recipient_max: 1, send_daily_max: 20, read_max_age_days: 30, setup_daily_max: 0 };
}

function erpCli(...args: string[]): string {
  const dataDir = pm.getDataDir();
  const bin = join(dataDir, 'integrations', 'node_modules', '@humanagencyp', 'erp-mcp', 'dist', 'index.js');
  const env: NodeJS.ProcessEnv = { ...process.env, HAP_DATA_DIR: dataDir, ERP_COMPANY_FILE: COMPANY_FILE };
  delete env.DATABASE_URL;
  return execFileSync('node', [bin, ...args], { env, encoding: 'utf8' });
}

/** The operator's own view of the simulated mailbox: the installed email-mcp, over stdio, on the gateway's data dir. */
async function mailboxCall(tool: string, args: Record<string, unknown>): Promise<any> {
  const r = await mailbox.callTool({ name: tool, arguments: args });
  const text = (r.content as Array<{ text?: string }>)?.map((c) => c.text ?? '').join('\n') ?? '';
  expect(r.isError, text).not.toBe(true);
  return JSON.parse(text);
}

async function sentCount(): Promise<number> {
  const list = await mailboxCall('list_messages', { folder: 'sent' });
  return (Array.isArray(list) ? list : list.messages ?? []).length;
}

// ── suite ────────────────────────────────────────────────────────────────

describe.skipIf(!available)('Issue an invoice, then email it as an attachment (simulation gateway: real AS + gateway + simulated erp-mcp + email-mcp)', () => {
  beforeAll(async () => {
    previousDisableAuto = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';

    pm.buildGateway();
    await pm.startSP(AS_PORT);
    const reg = await sp.register('Invoice Email E2E', `inv-mail-${Date.now()}@test.local`);
    apiKey = reg.apiKey;
    did = reg.user.did;
    groupId = await sp.getPersonalGroupId(apiKey);

    // SIMULATION gateway: the simulated ERP and the practice mailbox start at their defaults.
    await pm.startGateway({ simulation: true, port: MCP_PORT, cpPort: CP_PORT, spUrl: AS_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
    await gw.configure({ sessionCookie: 'inv-mail-e2e', apiKey });
    // Auto-provisioning is off in this suite; activate the two connectors from their manifests, at their defaults.
    for (const id of ['erp', 'mail']) {
      const res = await cp.authed(apiKey, 'POST', `/mcp/integrations/${id}/activate`);
      expect(res.status, await res.text()).toBe(200);
    }
    await gw.waitForIntegration('erp');
    await gw.waitForIntegration('mail');
    for (const id of ['erp', 'mail']) {
      const s = (await gw.integrations()).find((x) => x.id === id);
      expect(s?.running, `${id} should run on a simulation gateway`).toBe(true);
    }

    // The customer and the item are master data: only the person loads them (CLI), never the AI.
    writeFileSync(COMPANY_FILE, JSON.stringify(COMPANY_DATA, null, 2));
    erpCli('export');

    const mailBin = join(pm.getDataDir(), 'integrations', 'node_modules', '@humanagencyp', 'email-mcp', 'dist', 'index.js');
    const mailEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'DATABASE_URL') mailEnv[k] = v;
    mailbox = new Client({ name: 'operator-mailbox', version: '1.0.0' }, { capabilities: {} });
    await mailbox.connect(new StdioClientTransport({ command: process.execPath, args: [mailBin], env: { ...mailEnv, HAP_DATA_DIR: pm.getDataDir() } }));

    await new Promise((r) => setTimeout(r, 1_000));
    agent = new Client({ name: 'invoice-email-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  }, 300_000);

  afterAll(async () => {
    for (const c of [agent, mailbox]) if (c) await c.close().catch(() => {});
    await pm.killAll();
    rmSync(work, { recursive: true, force: true });
    if (previousDisableAuto === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = previousDisableAuto;
  }, 30_000);

  let invoiceProposal = '';
  let issuedSha = '';
  let pdfBytes: Buffer = Buffer.alloc(0);
  let mailProposal = '';
  let ticketId = '';
  let emailAuthId = '';
  let orderId = '';

  it('1. a sales mandate (automatic), an invoicing mandate (review) and an email 0.9 mandate (review) allowing erp:invoice-pdf', async () => {
    await grant(SALES, SALES_KEYS, {
      profile: SALES, read_access: 'unlimited', value_max: 5000, discount_max: 0, order_value_daily_max: 20000,
      quote_daily_max: 10, send_daily_max: 10, order_daily_max: 10, setup_daily_max: 0,
    }, { currency: 'EUR' }, ['currency'], 'E2E: quote, send and convert to an order automatically.', 'automatic');
    await grant(INVOICING, INVOICING_KEYS, {
      profile: INVOICING, read_access: 'unlimited', invoice_net_max: 5000, credit_net_max: 5000,
      invoice_net_monthly_max: 20000, credit_net_monthly_max: 20000, invoice_daily_max: 10, credit_daily_max: 10,
    }, { currency: 'EUR' }, ['currency'], 'E2E: issue our invoices, each approved before it is issued.');
    emailAuthId = await grant(EMAIL_09, EMAIL_KEYS, emailBounds(EMAIL_09), {
      allowed_recipients: CUSTOMER_EMAIL, allowed_domains: CUSTOMER_DOMAIN, allowed_attachment_sources: 'erp:invoice-pdf',
    }, EMAIL_SCOPE_KEYS_09, 'E2E: send issued invoices to the customer, each email approved.');
    await new Promise((r) => setTimeout(r, 1_000));

    // A fresh session sees every tool the mandates cover.
    await agent.close().catch(() => {});
    agent = new Client({ name: 'invoice-email-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
    const names = (await agent.listTools()).tools.map((t) => t.name);
    expect(names).toContain('erp__create_invoice');
    expect(names).toContain('mail__send_message');
    // The connector's document tools are internal: the gateway's, never the AI's.
    expect(names).not.toContain('erp__preview_invoice');
    expect(names).not.toContain('erp__get_document');
  });

  it('2. the simulated ERP gets a quote and an order; create_invoice becomes a proposal', async () => {
    const q = await call('erp__create_quote', { customer_id: CUSTOMER_ID, lines: [{ item_id: 'item-1', qty: 10 }], discount_pct: 0, value: ORDER_NET, currency: 'EUR' });
    expect(q.denied, q.text).toBe(false);
    const s = await call('erp__send_quote', { id: q.json.id, value: ORDER_NET, discount_pct: 0, currency: 'EUR', revision: 1 });
    expect(s.denied, s.text).toBe(false);
    const o = await call('erp__convert_quote_to_order', { id: q.json.id, value: ORDER_NET, discount_pct: 0, currency: 'EUR', revision: 1 });
    expect(o.denied, o.text).toBe(false);
    orderId = o.json.id;

    const r = await call('erp__create_invoice', { customer_id: CUSTOMER_ID, order_id: orderId, net_total: ORDER_NET, currency: 'EUR' });
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toMatch(/Awaiting commitment/);
    invoiceProposal = proposalIdOf(r.text);
    const list = await call('erp__list_invoices', {});
    expect(list.denied, list.text).toBe(false);
    expect(Array.isArray(list.json) ? list.json : list.json?.invoices).toHaveLength(0);
  }, 60_000);

  it('3. approved -> executed: the invoice is issued under the simulator\'s own number', async () => {
    await commit(invoiceProposal);
    const done = await awaitExecution(invoiceProposal);
    expect(done.denied, done.text).toBe(false);
    const inv = resultJson(done.text);
    expect(inv.number).toBe(`INV-${YEAR}-0001`);
    expect(inv.status).toBe('issued');
    expect(inv.net_total).toBe(ORDER_NET);
    expect(inv.ticket_id ?? inv.receipt_id).toEqual(expect.any(String));
    NUMBER = inv.number;
    ATTACHMENT_REF.id = NUMBER;
  }, 60_000);

  it('4. send_message with the invoice by reference becomes a proposal; the card shows it sealed, same file as issued, body as AI text', async () => {
    expect(NUMBER, 'step 3 must have issued the invoice').toMatch(/^INV-/);
    const before = await sentCount();
    const r = await call('mail__send_message', {
      to: [CUSTOMER_EMAIL], subject: `Rechnung ${NUMBER}`, body: MAIL_BODY, attachments: [ATTACHMENT_REF],
    });
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toMatch(/Awaiting commitment/);
    mailProposal = proposalIdOf(r.text);
    expect(await sentCount()).toBe(before);

    const args = await cardArgs(mailProposal);
    // The proposal carries the reference's fingerprint, never bytes, and no reference arg.
    expect(args.attachments).toBeUndefined();
    expect(JSON.stringify(args)).not.toContain('contentBase64');
    const sealed = args._attachmentsSealed?.attachments;
    expect(sealed, JSON.stringify(args).slice(0, 500)).toHaveLength(1);
    expect(sealed[0]).toMatchObject({ connector: 'erp', kind: 'invoice-pdf', id: NUMBER, contentType: 'application/pdf' });
    expect(sealed[0].sha256).toMatch(/^[0-9a-f]{64}$/);
    issuedSha = sealed[0].sha256;
    expect(sealed[0].filename).toMatch(/\.pdf$/);

    // "Same file as sealed": the live attachment preview renders the document again and matches the seal.
    const prev = await cpGet(`/proposal-status/${mailProposal}/attachment-preview/${issuedSha}`);
    expect(prev.status, JSON.stringify(prev.body).slice(0, 300)).toBe(200);
    expect(prev.body.status, JSON.stringify(prev.body).slice(0, 300)).toBe('ok');
    expect(prev.body.sha256).toBe(issuedSha);
    pdfBytes = Buffer.from(prev.body.contentBase64, 'base64');
    expect(pdfBytes.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(sha256(pdfBytes)).toBe(issuedSha);
    expect(sealed[0].bytes).toBe(pdfBytes.length);
    // A fingerprint that is not sealed on this proposal is never served.
    const other = await cpGet(`/proposal-status/${mailProposal}/attachment-preview/${'0'.repeat(64)}`);
    expect(other.status).toBe(404);

    // The body is the AI's own text — declared by the manifest, shown in its own box.
    const display = await cpGet('/tool-display');
    expect(display.status).toBe(200);
    expect(display.body.tools['mail__send_message'].aiTextArg).toBe('body');
    expect(args.body).toBe(MAIL_BODY);
  }, 60_000);

  it('5. approved → executed: the mailbox holds exactly the issued PDF; the ticket binds its fingerprint', async () => {
    expect(mailProposal, 'step 4 made no proposal').not.toBe('');
    const before = await sentCount();
    await commit(mailProposal);
    const done = await awaitExecution(mailProposal);
    expect(done.denied, done.text).toBe(false);
    const sent = resultJson(done.text);
    expect(await sentCount()).toBe(before + 1);

    const msg = await mailboxCall('get_message', { id: sent.id });
    expect(msg.to).toEqual([CUSTOMER_EMAIL]);
    expect(msg.attachments).toHaveLength(1);
    expect(msg.attachments[0]).toMatchObject({ contentType: 'application/pdf', sha256: issuedSha });
    const file = await mailboxCall('get_attachment', { message_id: sent.id, sha256: issuedSha });
    const fileBytes = Buffer.from(file.contentBase64, 'base64');
    expect(sha256(fileBytes)).toBe(issuedSha);
    expect(fileBytes.equals(pdfBytes)).toBe(true);

    // The ticket (issued and signed by the AS) commits to the attachment's fingerprint.
    // The verification footer the gateway appended names the ticket; the AS lists it too.
    const { tickets } = await sp.getMyTicketsPage(apiKey, { limit: 100 });
    const mine = tickets.filter((t) => String(t.action).includes('send_message') && t.authorizationId === emailAuthId);
    expect(mine, JSON.stringify(tickets.map((t) => [t.action, t.authorizationId]))).toHaveLength(1);
    ticketId = String(mine[0].id);
    expect(msg.body).toContain(ticketId);
    const pub = await fetch(`${AS_URL}/api/as/public-receipt/${ticketId}`);
    const receipt = await pub.json() as any;
    expect(pub.status, JSON.stringify(receipt)).toBe(200);
    expect(receipt.signatureValid).toBe(true);
    expect(receipt.contentBinding?.fields).toContain('attachments');

    const binding = { version: '2', kind: 'jcs', fields: ['to', 'cc', 'subject', 'body', 'attachments'], required_fields: ['to', 'body'] } as const;
    const expected = selectBoundFields(binding as any, {
      to: [CUSTOMER_EMAIL], subject: `Rechnung ${NUMBER}`, body: MAIL_BODY,
      attachments: [{ filename: msg.attachments[0].filename, sha256: issuedSha }],
    });
    expect(receipt.contentHash).toBe(computeContentHash(binding as any, expected));
    // Any other file would not match what was signed.
    const forged = selectBoundFields(binding as any, {
      to: [CUSTOMER_EMAIL], subject: `Rechnung ${NUMBER}`, body: MAIL_BODY,
      attachments: [{ filename: msg.attachments[0].filename, sha256: 'f'.repeat(64) }],
    });
    expect(receipt.contentHash).not.toBe(computeContentHash(binding as any, forged));

    // The gateway's local ticket archive holds the bound content: fingerprints, never bytes.
    const ev = await cpGet(`/api/evidence/receipt/${ticketId}`);
    expect(ev.status, JSON.stringify(ev.body).slice(0, 300)).toBe(200);
    expect(ev.body.entry.boundContent.attachments).toEqual([{ filename: msg.attachments[0].filename, sha256: issuedSha }]);
    expect(JSON.stringify(ev.body.entry.boundContent)).not.toContain('contentBase64');
    // The ticket view's own attachment preview answers the same file.
    const tv = await cpGet(`/api/evidence/receipt/${ticketId}/attachment-preview/${issuedSha}`);
    expect(tv.body.status, JSON.stringify(tv.body).slice(0, 300)).toBe('ok');
  }, 90_000);

  describe('6. negatives', () => {
    const NEG = {
      a08: { domain: 'neg-a.example', to: 'ap@neg-a.example' },
      a09: { domain: 'neg-b.example', to: 'ap@neg-b.example' },
      b: { domain: 'neg-c.example', to: 'ap@neg-c.example' },
    };

    async function expectRefusedNothingProposedOrSent(args: Record<string, unknown>, pattern: RegExp) {
      const pendingBefore = (await pendingProposals()).length;
      const sentBefore = await sentCount();
      const r = await call('mail__send_message', args);
      expect(r.denied, r.text).toBe(true);
      expect(r.text).toMatch(pattern);
      expect((await pendingProposals()).length).toBe(pendingBefore);
      expect(await sentCount()).toBe(sentBefore);
      return r;
    }

    beforeAll(async () => {
      // Each mandate covers its own recipient domain only, so exactly one of
      // them passes the Gatekeeper for each call — no ordering, no revocation.
      await grant(EMAIL_08, EMAIL_KEYS, emailBounds(EMAIL_08),
        { allowed_recipients: NEG.a08.to, allowed_domains: NEG.a08.domain }, EMAIL_SCOPE_KEYS_08,
        'E2E: an email 0.8 mandate — it knows nothing of attachments.');
      await grant(EMAIL_09, EMAIL_KEYS, emailBounds(EMAIL_09),
        { allowed_recipients: NEG.a09.to, allowed_domains: NEG.a09.domain }, EMAIL_SCOPE_KEYS_09,
        'E2E: an email 0.9 mandate without allowed attachment sources.');
      await grant(EMAIL_09, EMAIL_KEYS, emailBounds(EMAIL_09),
        { allowed_recipients: NEG.b.to, allowed_domains: NEG.b.domain, allowed_attachment_sources: 'erp:delivery-note-pdf' }, EMAIL_SCOPE_KEYS_09,
        'E2E: an email 0.9 mandate allowing a document kind the erp connector does not declare.');
      await new Promise((r) => setTimeout(r, 1_000));
    }, 60_000);

    it('(a) an email 0.8 mandate: the attachment is refused — nothing proposed, nothing sent', async () => {
      await expectRefusedNothingProposedOrSent(
        { to: [NEG.a08.to], subject: 'Rechnung', body: 'Anbei die Rechnung.', attachments: [ATTACHMENT_REF] },
        /not allowed[\s\S]*does not yet declare "allowed_attachment_sources"/,
      );
    });

    it('(a) an email 0.9 mandate without allowed sources: the attachment is refused — nothing proposed, nothing sent', async () => {
      await expectRefusedNothingProposedOrSent(
        { to: [NEG.a09.to], subject: 'Rechnung', body: 'Anbei die Rechnung.', attachments: [ATTACHMENT_REF] },
        /"erp:invoice-pdf" is not in this mandate's "allowed_attachment_sources" \(\(none\)\)/,
      );
    });

    it('(b) a kind the connector does not declare: refused even where the mandate lists it', async () => {
      await expectRefusedNothingProposedOrSent(
        { to: [NEG.b.to], subject: 'Lieferschein', body: 'Anbei der Lieferschein.', attachments: [{ connector: 'erp', kind: 'delivery-note-pdf', id: NUMBER }] },
        /declares no document kind "delivery-note-pdf"/,
      );
      // And under the main mandate, a kind outside its allowed sources is refused by policy.
      await expectRefusedNothingProposedOrSent(
        { to: [CUSTOMER_EMAIL], subject: 'Gutschrift', body: 'Anbei.', attachments: [{ connector: 'erp', kind: 'credit-note-pdf', id: NUMBER }] },
        /allowed_attachment_sources: Values \[erp:credit-note-pdf\] not in authorized set \[erp:invoice-pdf\]|"erp:credit-note-pdf" is not in this mandate's "allowed_attachment_sources"/,
      );
    });

    it('(d) AI-supplied bytes are refused — on the reference, or as a file object', async () => {
      const pdf = pdfBytes.toString('base64');
      await expectRefusedNothingProposedOrSent(
        { to: [CUSTOMER_EMAIL], subject: 'Rechnung', body: 'Anbei.', attachments: [{ ...ATTACHMENT_REF, contentBase64: pdf }] },
        /contentBase64/,
      );
      await expectRefusedNothingProposedOrSent(
        { to: [CUSTOMER_EMAIL], subject: 'Rechnung', body: 'Anbei.', attachments: [{ filename: 'rechnung.pdf', contentType: 'application/pdf', contentBase64: pdf }] },
        /attachments|connector/i,
      );
    });

    it('(d) a `raw` MIME message from the AI never reaches the mailbox', async () => {
      const raw = Buffer.from(`To: ${CUSTOMER_EMAIL}\r\nSubject: x\r\n\r\nforged`).toString('base64url');
      const pendingBefore = (await pendingProposals()).length;
      const sentBefore = await sentCount();
      const r = await call('mail__send_message', { to: [CUSTOMER_EMAIL], subject: 'Rechnung', body: 'Anbei.', raw });
      if (r.denied) {
        expect((await pendingProposals()).length).toBe(pendingBefore);
      } else {
        // Not refused: then it must be dropped — the proposal carries no `raw`.
        const id = proposalIdOf(r.text);
        const args = await cardArgs(id);
        console.error(`[INVOICE EMAIL E2E] (d) raw was not refused on mail__send_message; proposal args keys: ${Object.keys(args).join(', ')}`);
        expect(args.raw).toBeUndefined();
        await reject(id);
      }
      expect(await sentCount()).toBe(sentBefore);
    });

    it.skip('payment link inserted into the body (Mollie) — needs a real Mollie account; no mocked Mollie (house rule)', () => {});
  });
});
