/**
 * "Issue an invoice" in production — on the real stack: Authority Server + the
 * whole gateway (control plane + MCP server, NOT simulation mode) + the
 * published erp-mcp in live mode "local" (Suveren's own invoicing: a real
 * company file, real PDFs, a write-once archive). Nothing is mocked.
 *
 * NO MAILBOX HERE, by design: a gateway is EITHER in simulation mode OR in
 * production. The practice mailbox (email-mcp at its default, simulated) does
 * not start in production, so "ERP archive PDF -> email" cannot be tested on one
 * gateway with ERP live. Do not re-add the mix.
 *  - the email-with-attachment-by-reference journey (sealed fingerprint, card,
 *    ticket binding, negatives) lives in invoice-email-attachment.test.ts, on a
 *    SIMULATION gateway with the simulated ERP;
 *  - the production path "ERP archive PDF -> real email" is covered by the
 *    Rehearsal's A3 against a real Gmail test account (passed 2026-11-05).
 *
 * The journey (suveren-invoicing-plan.md section 5-7, UI spec section 15):
 *   1. an invoicing mandate (review);
 *   2. create_invoice (number "2026-0001", service period, one line, declared
 *      net_total) becomes a proposal; the control-plane preview route the UI
 *      uses returns the PDF as it will be issued (sha256, pages >= 1) - twice,
 *      and the number is still free afterwards (a preview consumes nothing);
 *   3. approval -> executed -> the invoice is issued with its archived PDF's
 *      fingerprint, equal to the previewed one.
 *
 * erp-mcp >= 0.9.0: the document date comes with the request and the PDF is
 * deterministic, so the approved preview IS the issued file.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { ControlPlaneClient, GW_DIR, PROFILES_DIR } from '../src/helpers/gateway-stack.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { profileHashFor } from '../src/helpers/profiles.js';

const AS_PORT = 19910;
const MCP_PORT = 19911;
const CP_PORT = 19912;
const AS_URL = `http://localhost:${AS_PORT}`;
const MCP_URL = `http://localhost:${MCP_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;

const ERP_MANIFEST = join(GW_DIR, 'content', 'integrations', 'erp.json');

function readJson(path: string): any {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
}
const erpManifest = readJson(ERP_MANIFEST);
const gaps: string[] = [];
if (!existsSync(join(PROFILES_DIR, 'invoicing', '0.1.profile.json'))) gaps.push('hap-profiles invoicing@0.1');
if (String(erpManifest?.npmVersion ?? '').localeCompare('0.9.0', undefined, { numeric: true }) < 0) gaps.push('erp.json pinning erp-mcp >= 0.9.0 (live mode "local" with document_date)');
if (!erpManifest?.documents?.['invoice-pdf']) gaps.push('erp.json declaring documents.invoice-pdf');
const available = gaps.length === 0;
if (!available) console.warn(`[INVOICE PRODUCTION E2E] SKIPPED — needs ${gaps.join('; ')}.`);

const P = 'github.com/humanagencyprotocol/hap-profiles';
const INVOICING = `${P}/invoicing@0.1`;
const INVOICING_KEYS = ['profile', 'read_access', 'invoice_net_max', 'credit_net_max',
  'invoice_net_monthly_max', 'credit_net_monthly_max', 'invoice_daily_max', 'credit_daily_max'];

// Placeholder company data — an Austrian sole trader, invented throughout.
const COMPANY = {
  name: 'Muster Beratung e.U.', owner: 'Maria Muster',
  address: { street: 'Musterstraße 1', zip: '1010', city: 'Wien', country: 'Österreich', country_code: 'AT' },
  uid: 'ATU12345678', email: 'office@muster-beratung.example', web: 'https://muster-beratung.example',
  register: null, bank: { name: 'Musterbank AG', iban: 'AT611904300234573201', bic: 'MUSTATWWXXX' },
  default_payment_term_days: 14, vat_mode: 'normal',
};
const CUSTOMER = {
  id: 'cust-kunde', name: 'Kunde GmbH', address_lines: ['Kundenweg 2', '4020 Linz'],
  country: 'AT', uid: 'ATU87654321', email: 'buchhaltung@kunde-gmbh.example',
};
const NUMBER = '2026-0001';
/** The invoice is dated today (the connector refuses any other day), in the
 *  connector's default timezone. */
const TODAY_VIENNA = new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Vienna', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
const INVOICE_ARGS = {
  customer_id: CUSTOMER.id, number: NUMBER, document_date: TODAY_VIENNA,
  service_period: { from: '2026-09-01', to: '2026-09-30' },
  lines: [{ description: 'Beratung September 2026', qty: 10, unit: 'Std.', unit_price: 120, vat_rate: 20 }],
  net_total: 1200, currency: 'EUR',
};

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);
const gw = new GatewayClient(MCP_URL);
const cp = new ControlPlaneClient(CP_URL);
const work = mkdtempSync(join(tmpdir(), 'hap-e2e-inv-prod-'));
const COMPANY_FILE = join(work, 'company.json');

let apiKey: string;
let did: string;
let groupId: string;
let agent: Client;
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

async function commit(proposalId: string) {
  const r = await asApi('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner' });
  expect(r.status, JSON.stringify(r.body)).toBeLessThan(300);
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

async function grant(profileId: string, keys: string[], bounds: Record<string, unknown>,
  scope: Record<string, string>, scopeKeys: string[], intent: string): Promise<string> {
  const boundsHash = computeBoundsHash(bounds, keys);
  const contextHash = computeScopeHash(scope, scopeKeys);
  const gate = { intent };
  const att = await sp.submitMandate(apiKey, {
    profile_id: profileId, profile_hash: profileHashFor(profileId, PROFILES_DIR), group_id: groupId,
    bounds, bounds_hash: boundsHash, scope_hash: contextHash, domain: 'owner', did,
    commitment_mode: 'review', gate_content_hashes: hashGateContent(gate),
    execution_context_hash: hashExecutionContext({ intent }),
  });
  await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: scope }, profileId, gate);
  return att.authorization_id;
}

function erpCli(...args: string[]): string {
  const dataDir = pm.getDataDir();
  const bin = join(dataDir, 'integrations', 'node_modules', '@humanagencyp', 'erp-mcp', 'dist', 'index.js');
  const env: NodeJS.ProcessEnv = { ...process.env, HAP_DATA_DIR: dataDir, ERP_MODE: 'live', ERP_LIVE_ADAPTER: 'local', ERP_LIVE_COMPANY_FILE: COMPANY_FILE };
  delete env.DATABASE_URL;
  return execFileSync('node', [bin, ...args], { env, encoding: 'utf8' });
}

// ── suite ────────────────────────────────────────────────────────────────

describe.skipIf(!available)('Issue an invoice in production (real AS + gateway + erp-mcp live/local)', () => {
  beforeAll(async () => {
    previousDisableAuto = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';

    pm.buildGateway();
    await pm.startSP(AS_PORT);
    const reg = await sp.register('Invoice Production E2E', `inv-prod-${Date.now()}@test.local`);
    apiKey = reg.apiKey;
    did = reg.user.did;
    groupId = await sp.getPersonalGroupId(apiKey);

    await pm.startGateway({ port: MCP_PORT, cpPort: CP_PORT, spUrl: AS_URL, spApiKey: apiKey, profilesDir: PROFILES_DIR });
    await gw.configure({ sessionCookie: 'inv-prod-e2e', apiKey });

    // The person's own connector settings, the way the gateway UI saves them:
    // vault credentials for "erp" (mapped to env by erp.json's envMapping),
    // then the connector is activated from its manifest.
    writeFileSync(COMPANY_FILE, JSON.stringify(COMPANY, null, 2));
    const put = await cp.authed(apiKey, 'PUT', '/vault/credentials/erp', { mode: 'live', liveAdapter: 'local', companyFile: COMPANY_FILE });
    expect(put.status, await put.text()).toBe(200);
    const act = await cp.authed(apiKey, 'POST', '/mcp/integrations/erp/activate');
    expect(act.status, await act.text()).toBe(200);
    await gw.waitForIntegration('erp');

    // The customer is master data: only the person adds it (CLI), never the AI.
    erpCli('customers', 'add', JSON.stringify(CUSTOMER));

    await new Promise((r) => setTimeout(r, 1_000));
    agent = new Client({ name: 'invoice-production-agent', version: '1.0.0' }, { capabilities: {} });
    await agent.connect(new SSEClientTransport(new URL(`${MCP_URL}/sse`)));
  }, 300_000);

  afterAll(async () => {
    for (const c of [agent]) if (c) await c.close().catch(() => {});
    await pm.killAll();
    rmSync(work, { recursive: true, force: true });
    if (previousDisableAuto === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = previousDisableAuto;
  }, 30_000);

  let invoiceProposal = '';
  let previewShas: string[] = [];
  let previewSha = '';
  let issuedSha = '';
  let archivePath = '';

  it('1. an invoicing mandate (review)', async () => {
    await grant(INVOICING, INVOICING_KEYS, {
      profile: INVOICING, read_access: 'unlimited', invoice_net_max: 5000, credit_net_max: 5000,
      invoice_net_monthly_max: 20000, credit_net_monthly_max: 20000, invoice_daily_max: 10, credit_daily_max: 10,
    }, { currency: 'EUR' }, ['currency'], 'E2E: issue our invoices, each approved before it is issued.');
    await new Promise((r) => setTimeout(r, 1_000));

    const names = (await agent.listTools()).tools.map((t) => t.name);
    expect(names).toContain('erp__create_invoice');
    // The connector's document tools are internal: the gateway's, never the AI's.
    expect(names).not.toContain('erp__preview_invoice');
    expect(names).not.toContain('erp__get_document');
  });

  it('2. create_invoice becomes a proposal; the preview is the PDF as it will be issued, and consumes no number', async () => {
    const r = await call('erp__create_invoice', INVOICE_ARGS);
    expect(r.denied, r.text).toBe(false);
    expect(r.text).toMatch(/Awaiting commitment/);
    invoiceProposal = proposalIdOf(r.text);

    async function documentPreview() {
      const { status, body } = await cpGet(`/proposal-status/${invoiceProposal}/preview`);
      expect(status, JSON.stringify(body)).toBe(200);
      expect(body.status, JSON.stringify(body).slice(0, 600)).toBe('ok');
      const reads: any[] = body.reads ?? body.sections ?? [];
      const doc = reads.find((s) => s.kind === 'document');
      expect(doc, JSON.stringify(Object.keys(body))).toBeTruthy();
      expect(doc.tool).toBe('preview_invoice');
      expect(doc.result?.status, JSON.stringify(doc.result).slice(0, 400)).toBe('ok');
      const b = doc.result.body;
      return (b.structured ?? JSON.parse(b.text)) as { filename: string; contentType: string; contentBase64: string; sha256: string; pages: number };
    }

    const first = await documentPreview();
    expect(first.contentType).toBe('application/pdf');
    expect(first.filename).toContain(NUMBER);
    expect(first.pages).toBeGreaterThanOrEqual(1);
    const bytes = Buffer.from(first.contentBase64, 'base64');
    expect(bytes.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(first.sha256).toBe(sha256(bytes));
    previewSha = first.sha256;

    const second = await documentPreview();
    expect(second.pages).toBeGreaterThanOrEqual(1);
    previewShas = [first.sha256, second.sha256];

    // Two previews and still nothing issued, nothing archived: the number is free.
    const list = await call('erp__list_invoices', {});
    expect(list.denied, list.text).toBe(false);
    expect(Array.isArray(list.json) ? list.json : list.json?.invoices).toHaveLength(0);
    expect(existsSync(join(pm.getDataDir(), 'erp-local-archive'))).toBe(false);
  }, 60_000);

  it('3. approved → executed: the invoice is issued, with its archived PDF\'s fingerprint', async () => {
    await commit(invoiceProposal);
    const done = await awaitExecution(invoiceProposal);
    if (done.denied) console.error(`[INVOICE PRODUCTION E2E] step 3 refused at execution: ${done.text}\n  the two previews' sha256: ${previewShas.join(' / ')}`);
    expect(done.denied, done.text).toBe(false);
    const inv = resultJson(done.text);
    expect(inv.number).toBe(NUMBER);
    expect(inv.status).toBe('issued');
    expect(inv.net_total).toBe(1200);
    expect(inv.archive_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(inv.ticket_id).toEqual(expect.any(String));
    issuedSha = inv.archive_sha256;
    archivePath = inv.archive_path;
    expect(sha256(readFileSync(archivePath))).toBe(issuedSha);
    // The approved preview IS the issued document: same date, same bytes.
    expect(previewShas[0]).toBe(previewShas[1]);
    expect(issuedSha).toBe(previewSha);
  }, 60_000);
});
