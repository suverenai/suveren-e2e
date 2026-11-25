/**
 * Live events (0.46.1, DEC-107) — real AS + real gateway, no mocks.
 *
 * The gateway holds one outbound stream to the Authority Server (GET /api/events). A counting proxy sits between the
 * gateway and the AS, so the test counts every request the gateway really makes. It asserts:
 *   1. a decision made elsewhere (here: another client of the AS, as a phone or another approver would) reaches the
 *      gateway within 2 s — the page's `as-changed` event and the MCP server's auto-execution;
 *   2. an idle gateway with the stream up makes no other AS request (only the planned stream reconnects);
 *   3. without the stream (the proxy answers 404 for /api/events, as an AS with the switch off does) the gateway
 *      polls exactly as before.
 * It also reports the AS database's transactions per minute in both phases (pg_stat_database).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { Client as PgClient } from 'pg';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { ProcessManager } from '../src/helpers/process-manager';
import { SPClient } from '../src/helpers/sp-client';
import { GatewayClient } from '../src/helpers/gateway-client';
import { computeBoundsHash, hashGateContent, hashExecutionContext } from '../src/helpers/crypto';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles';

const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;
const SP_PORT = 19700;   // unused elsewhere in the suite as of 2026-11-25
const PROXY_PORT = 19701;
const GW_PORT = 19730;
const CP_PORT = 19702;
const MAX_STREAM_S = 60;

const pm = new ProcessManager();
let sp: SPClient;
let gw: GatewayClient;
let apiKey: string;
let mcpClient: Client;
let proxy: http.Server;
let blockEvents = false;
const counts = new Map<string, number>();

function countKey(method: string, url: string): string {
  const path = url.split('?')[0].replace(/\/[0-9a-f]{12,}(?=\/|$)/g, '/:id').replace(/authz_[0-9a-f-]+/g, ':authz');
  return `${method} ${path}`;
}
function snapshot(): Map<string, number> { return new Map(counts); }
function diff(before: Map<string, number>): Map<string, number> {
  const out = new Map<string, number>();
  for (const [k, v] of counts) { const d = v - (before.get(k) ?? 0); if (d > 0) out.set(k, d); }
  return out;
}
const sum = (m: Map<string, number>, pred: (k: string) => boolean = () => true) => [...m].filter(([k]) => pred(k)).reduce((a, [, v]) => a + v, 0);

function startProxy(): Promise<http.Server> {
  const server = http.createServer((req, res) => {
    const key = countKey(req.method ?? 'GET', req.url ?? '/');
    counts.set(key, (counts.get(key) ?? 0) + 1);
    if (blockEvents && (req.url ?? '').startsWith('/api/events')) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":"Not found"}');
      return;
    }
    const up = http.request({ host: '127.0.0.1', port: SP_PORT, method: req.method, path: req.url, headers: { ...req.headers, host: `localhost:${SP_PORT}` } }, (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers);
      res.flushHeaders();
      r.pipe(res);
    });
    up.on('error', () => { try { res.writeHead(502); res.end(); } catch { /* */ } });
    req.pipe(up);
    res.on('close', () => up.destroy());
  });
  return new Promise((resolve) => server.listen(PROXY_PORT, '127.0.0.1', () => resolve(server)));
}

async function dbXacts(): Promise<number | null> {
  const url = pm.asDatabaseUrl();
  if (!url) return null;
  const c = new PgClient({ connectionString: url });
  await c.connect();
  try {
    const { rows } = await c.query<{ n: string }>('select xact_commit + xact_rollback as n from pg_stat_database where datname = current_database()');
    return Number(rows[0].n);
  } finally { await c.end(); }
}

/** Read the control plane's own SSE stream; resolves with the ms until the first `as-changed` after `since`. */
function firstAsChanged(since: number, timeoutMs: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const ac = new AbortController();
    const timer = setTimeout(() => { ac.abort(); reject(new Error(`no as-changed within ${timeoutMs} ms`)); }, timeoutMs);
    void fetch(`http://localhost:${CP_PORT}/events`, { headers: { 'X-API-Key': apiKey }, signal: ac.signal }).then(async (res) => {
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value);
        if (buf.includes('event: as-changed') && Date.now() >= since) {
          clearTimeout(timer); ac.abort(); resolve(Date.now() - since); return;
        }
        if (Date.now() < since) buf = '';
      }
    }).catch(() => { /* aborted */ });
  });
}

async function callText(name: string, args: Record<string, unknown>): Promise<string> {
  const r = await mcpClient.callTool({ name, arguments: args });
  return (r.content as Array<{ text: string }>).map((c) => c.text).join('\n');
}

async function liveUp(): Promise<boolean> {
  const r = await fetch(`http://localhost:${CP_PORT}/api/live-status`, { headers: { 'X-API-Key': apiKey } });
  return r.ok && (await r.json()).up === true;
}
async function waitFor(fn: () => Promise<boolean>, ms: number): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await fn()) return; await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`condition not met within ${ms} ms`);
}

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT, { env: { SUVEREN_LIVE_EVENTS: 'on', SUVEREN_DEPLOYMENT: 'test', SUVEREN_EVENTS_MAX_STREAM_S: String(MAX_STREAM_S) } });
  sp = new SPClient(`http://localhost:${SP_PORT}`);
  proxy = await startProxy();

  const user = await sp.register('LiveUser', `liveuser-${Date.now()}@test.com`);
  apiKey = user.apiKey;
  const groupId = await sp.getPersonalGroupId(apiKey);

  await pm.startGateway({
    simulation: true,
    port: GW_PORT,
    cpPort: CP_PORT,
    spUrl: `http://localhost:${PROXY_PORT}`,
    spApiKey: apiKey,
    profilesDir: PROFILES_DIR,
  });
  gw = new GatewayClient(`http://localhost:${GW_PORT}`);
  await gw.configure({ sessionCookie: `api-key=${apiKey}`, apiKey });

  const profile = PROFILE_V07.customers;
  const bounds = { profile, read_access: 'unlimited', export_access: 'none', write_daily_max: 10, delete_daily_max: 5, setup_daily_max: 0 };
  const boundsHash = computeBoundsHash(bounds, ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max']);
  const contextHash = computeBoundsHash({}, []);
  const att = await sp.submitMandate(apiKey, {
    profile_id: profile, profile_hash: profileHashFor(profile, PROFILES_DIR), group_id: groupId, domain: 'owner', did: user.user.did,
    bounds, bounds_hash: boundsHash, scope_hash: contextHash, gate_content_hashes: hashGateContent({ intent: 'test' }),
    execution_context_hash: hashExecutionContext({ profile, domain: 'owner' }), commitment_mode: 'review',
  });
  await gw.pushGateContent({ authorizationId: att.authorization_id, boundsHash, contextHash, context: {} }, profile, { intent: 'test' });
  await gw.waitForIntegration('crm');
  await new Promise((r) => setTimeout(r, 2_000));
  mcpClient = new Client({ name: 'live-agent', version: '1.0.0' }, { capabilities: {} });
  await mcpClient.connect(new SSEClientTransport(new URL(`http://localhost:${GW_PORT}/sse`)));
}, 180_000);

afterAll(async () => {
  if (mcpClient) { try { await mcpClient.close(); } catch { /* */ } }
  await new Promise<void>((r) => proxy ? proxy.close(() => r()) : r());
  await pm.killAll();
});

describe('live events: the gateway holds one stream to the AS', () => {
  it('the stream comes up', async () => {
    await waitFor(liveUp, 30_000);
    expect(sum(counts, (k) => k === 'GET /api/events')).toBeGreaterThanOrEqual(1);
  }, 40_000);

  it('a decision made elsewhere reaches the gateway within 2 s (page event and MCP execution)', async () => {
    const text = await callText('crm__create_contact', { name: 'Live Contact', type: 'customer' });
    const id = text.match(/Proposal ID: ([a-f0-9]+)/)![1];
    await new Promise((r) => setTimeout(r, 1_000)); // let the "proposal created" announcement pass

    const t0 = Date.now();
    const pageEvent = firstAsChanged(t0, 5_000);
    const res = await fetch(`http://localhost:${SP_PORT}/api/proposals/${id}/resolve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey }, body: JSON.stringify({ action: 'commit', domain: 'owner' }),
    });
    expect(res.ok).toBe(true);
    const pageMs = await pageEvent;
    let execMs = -1;
    for (let i = 0; i < 40; i++) {
      if (/executed|not found/i.test(await callText('check-pending-commitments', { proposal_id: id }))) { execMs = Date.now() - t0; break; }
      await new Promise((r) => setTimeout(r, 100));
    }
    console.error(`[live-events] decision → page event ${pageMs} ms, → executed ${execMs} ms`);
    expect(pageMs).toBeLessThan(2_000);
    expect(execMs).toBeGreaterThan(0);
    expect(execMs).toBeLessThan(2_000);
  }, 30_000);

  it('idle with the stream up: no AS request except the planned stream reconnects', async () => {
    await waitFor(liveUp, 10_000);
    const WINDOW_MS = 150_000;
    const before = snapshot();
    const x0 = await dbXacts();
    await new Promise((r) => setTimeout(r, WINDOW_MS));
    const d = diff(before);
    const x1 = await dbXacts();
    const other = sum(d, (k) => k !== 'GET /api/events');
    const streams = sum(d, (k) => k === 'GET /api/events');
    console.error(`[live-events] idle ${WINDOW_MS / 1000} s, stream up: ${streams} stream connects, ${other} other AS requests ${JSON.stringify([...d])}; AS db transactions ${x0 !== null && x1 !== null ? ((x1 - x0) / (WINDOW_MS / 60_000)).toFixed(1) : 'n/a'}/min`);
    // maxStreamS 60 → about one reconnect a minute; anything else would be polling. One 5-minute backup tick may fall in.
    expect(streams).toBeLessThanOrEqual(Math.ceil(WINDOW_MS / 1000 / MAX_STREAM_S) + 1);
    expect(other).toBeLessThanOrEqual(2);
  }, 200_000);

  it('without the stream (404, as an AS with the switch off) the gateway polls as before', async () => {
    blockEvents = true;
    // The open stream ends at its planned time (≤ maxStreamS); the reconnect then gets 404 and the gateway drops to polling.
    await waitFor(async () => !(await liveUp()), (MAX_STREAM_S + 15) * 1000);
    await new Promise((r) => setTimeout(r, 6_000));
    const WINDOW_MS = 30_000;
    const before = snapshot();
    const x0 = await dbXacts();
    await new Promise((r) => setTimeout(r, WINDOW_MS));
    const d = diff(before);
    const x1 = await dbXacts();
    const polls = sum(d, (k) => k.startsWith('GET /api/proposals'));
    console.error(`[live-events] idle ${WINDOW_MS / 1000} s, no stream: ${sum(d)} AS requests ${JSON.stringify([...d])}; AS db transactions ${x0 !== null && x1 !== null ? ((x1 - x0) / (WINDOW_MS / 60_000)).toFixed(1) : 'n/a'}/min`);
    // Today's behaviour: the MCP server asks for committed and decided proposals every 5 s.
    expect(polls).toBeGreaterThanOrEqual(8);
    blockEvents = false;
  }, 150_000);
});
