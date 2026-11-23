/**
 * Weekly limits (Andreas, 2026-11-23): publish@0.9 `post_weekly_max` and email@0.11
 * `send_weekly_max`, both `cumulative_count` with `window: "weekly"` — the last 7 days,
 * rolling (protocol 0.7/0.8, Cumulative Bounds).
 *
 * Real stack, nothing mocked:
 *  - Publishing, on the Authority Server directly (no LinkedIn account in CI): a mandate
 *    with a weekly limit of 3 (daily 10) — three tickets are issued, the fourth is
 *    refused with the weekly bound named, and the ticket's signed cumulativeState carries
 *    `weekly` (protocol: present when a bound of the profile declares the weekly window).
 *    A publish@0.8 ticket (no weekly bound) carries no `weekly`.
 *  - Email, through the whole gateway in simulation (practice mailbox): an AI-proposed
 *    mandate under email@0.11 (the newest version is the default) with send_weekly_max 3;
 *    three sends go out, the fourth is refused and nothing is sent.
 *
 * Needs the profile versions from hap-profiles (CI input `profiles_ref`); skipped
 * when the checkout does not have them.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

import { ProcessManager } from '../src/helpers/process-manager.js';
import { SPClient } from '../src/helpers/sp-client.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { hashGateContent, hashExecutionContext, computeBoundsHash, computeScopeHash } from '../src/helpers/crypto.js';
import { ControlPlaneClient, newSecret, startControlPlane, startMcpServer, textOf, PROFILES_DIR, type StackOptions } from '../src/helpers/gateway-stack.js';
import { profileHashFor } from '../src/helpers/profiles.js';

// 19950–19954 belong to this file.
const AS_PORT = 19950;
const PORTS = { cp: 19951, mcp: 19952 };
const AS_URL = `http://localhost:${AS_PORT}`;
const P = 'github.com/humanagencyprotocol/hap-profiles';
const PUBLISH_09 = `${P}/publish@0.9`;
const PUBLISH_08 = `${P}/publish@0.8`;
const EMAIL_11 = `${P}/email@0.11`;
const DELEGATION = `${P}/delegation@0.6`;
const available = ['publish/0.9', 'email/0.11', 'delegation/0.6'].every((f) => existsSync(join(PROFILES_DIR, `${f}.profile.json`)));
if (!available) console.warn('[WEEKLY LIMITS E2E] SKIPPED — needs hap-profiles publish@0.9, email@0.11 and delegation@0.6 (CI input profiles_ref).');

const PUBLISH_09_KEYS = ['profile', 'post_daily_max', 'post_weekly_max', 'post_monthly_max'];
const PUBLISH_08_KEYS = ['profile', 'post_daily_max', 'post_monthly_max'];
const PUBLISH_SCOPE = { allowed_platforms: 'linkedin', content_type: 'text', audience: 'public' };
const PUBLISH_SCOPE_KEYS = ['allowed_platforms', 'content_type', 'audience'];
const DELEGATION_KEYS = ['profile', 'read_access', 'brief_daily_max', 'mandate_daily_max'];
const DOMAIN = 'kunde-gmbh.example';

const pm = new ProcessManager();
const sp = new SPClient(AS_URL);

type Account = { apiKey: string; user: { id: string; did: string } };
let owner: Account;
let groupId: string;
let stack: StackOptions;
let cp: ControlPlaneClient;
let mcp: GatewayClient;
let agent: Client;
let mailbox: Client;

async function as(method: string, path: string, body?: unknown) {
  const res = await fetch(`${AS_URL}${path}`, {
    method, headers: { 'X-API-Key': owner.apiKey, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: await res.json().catch(() => ({})) as any };
}

async function grantPublish(profile: string, keys: string[], bounds: Record<string, number>): Promise<{ id: string; boundsHash: string }> {
  const b = { profile, ...bounds };
  const boundsHash = computeBoundsHash(b, keys);
  const att = await sp.submitMandate(owner.apiKey, {
    profile_id: profile, profile_hash: profileHashFor(profile, PROFILES_DIR), group_id: groupId, bounds: b, bounds_hash: boundsHash,
    scope_hash: computeScopeHash(PUBLISH_SCOPE, PUBLISH_SCOPE_KEYS),
    domain: 'owner', did: owner.user.did, commitment_mode: 'automatic',
    gate_content_hashes: hashGateContent({ intent: 'E2E: a few LinkedIn posts a week.' }), execution_context_hash: hashExecutionContext({ m: profile }),
  });
  return { id: att.authorization_id, boundsHash };
}

const post = (profileId: string, g: { id: string; boundsHash: string }) => sp.postTicket(owner.apiKey, {
  authorizationId: g.id, boundsHash: g.boundsHash, profileId, action: 'linkedin__create_post', actionType: 'post',
  executionContext: { action_type: 'post', ...PUBLISH_SCOPE },
});

async function tool(name: string, args: Record<string, unknown>) {
  const r = await agent.callTool({ name, arguments: args });
  return { denied: r.isError === true, text: textOf(r) };
}

async function activeEmail(): Promise<Array<{ authorization_id: string; profileId?: string; profile_id?: string; bounds?: Record<string, unknown> }>> {
  const rows = (await as('GET', '/api/mandates/mine?status=active')).body.mandates ?? [];
  return rows.filter((m: { profileId?: string; profile_id?: string }) => (m.profileId ?? m.profile_id ?? '').includes('/email@'));
}

async function sentCount(): Promise<number> {
  const r = await mailbox.callTool({ name: 'list_messages', arguments: { folder: 'sent' } });
  const list = JSON.parse(((r.content as Array<{ text?: string }>)?.[0]?.text ?? '[]'));
  return (Array.isArray(list) ? list : list.messages ?? []).length;
}

const send = (n: number) => tool('mail__send_message', { to: [`buchhaltung@${DOMAIN}`], subject: `Woche ${n}`, body: 'Guten Tag, ein Test der Suveren-E2E-Suite.' });

describe.skipIf(!available)('weekly limits: publish@0.9 and email@0.11 (real stack)', () => {
  beforeAll(async () => {
    pm.buildGateway();
    await pm.startSP(AS_PORT);
    owner = await sp.register('Wanda Weekly', `wanda-weekly-${Date.now()}@test.local`) as unknown as Account;
    groupId = await sp.getPersonalGroupId(owner.apiKey);
  }, 300_000);

  afterAll(async () => {
    for (const c of [agent, mailbox]) if (c) await c.close().catch(() => {});
    await pm.stopProcess('mcp-weekly').catch(() => {});
    await pm.stopProcess('cp-weekly').catch(() => {});
    await pm.killAll();
    if (stack) rmSync(stack.dataDir, { recursive: true, force: true });
  }, 30_000);

  describe('Publishing on the Authority Server: post_weekly_max 3', () => {
    let g: { id: string; boundsHash: string };

    it('three posts get a ticket; the third ticket signs weekly.count 3 next to daily and monthly', async () => {
      g = await grantPublish(PUBLISH_09, PUBLISH_09_KEYS, { post_daily_max: 10, post_weekly_max: 3, post_monthly_max: 30 });
      let last: Record<string, any> = {};
      for (let i = 1; i <= 3; i++) {
        const r = await post(PUBLISH_09, g);
        expect(r.status, JSON.stringify(r.body)).toBe(201);
        last = r.body.ticket as Record<string, any>;
      }
      expect(last.cumulativeState.weekly).toEqual({ amount: 0, count: 3 });
      expect(last.cumulativeState.daily.count).toBe(3);
      expect(last.cumulativeState.monthly.count).toBe(3);
      expect(last.limits.post_weekly_max).toBe(3);
    });

    it('the fourth post is refused, naming the weekly bound', async () => {
      const r = await post(PUBLISH_09, g);
      expect(r.status, JSON.stringify(r.body)).toBe(403);
      const err = (r.body.errors as Array<Record<string, unknown>>)[0];
      expect(err.code).toBe('CUMULATIVE_LIMIT_EXCEEDED');
      expect(err.field).toBe('post_weekly_max');
      expect(String(err.message)).toBe('Cumulative weekly count (4) exceeds post_weekly_max=3');
    });

    it('the mandate summary the gateway reads reports the weekly usage: 3 of 3', async () => {
      const r = await as('GET', `/api/authorizations/${g.id}`);
      expect(r.status).toBe(200);
      const weekly = (r.body.cumulative_usage as Array<Record<string, unknown>>).find((u) => u.field === 'post_weekly_max');
      expect(weekly).toMatchObject({ window: 'weekly', kind: 'cumulative_count', used: 3, limit: 3, action_type: 'post' });
    });

    it('a profile without a weekly bound (publish@0.8) signs no weekly state, as before', async () => {
      await as('POST', `/api/authorizations/${g.id}/revoke`, { reason: 'test' });
      const old = await grantPublish(PUBLISH_08, PUBLISH_08_KEYS, { post_daily_max: 10, post_monthly_max: 30 });
      const r = await post(PUBLISH_08, old);
      expect(r.status, JSON.stringify(r.body)).toBe(201);
      const state = (r.body.ticket as Record<string, any>).cumulativeState;
      expect(Object.keys(state).sort()).toEqual(['daily', 'monthly']);
      await as('POST', `/api/authorizations/${old.id}/revoke`, { reason: 'test' });
    });
  });

  describe('a team configured for email@0.10: email@0.11 is not enabled until an admin saves it (today\'s carry-over rule)', () => {
    it('a mandate under 0.11 is refused, naming the new field send_weekly_max and the version it would carry over from', async () => {
      const EMAIL_10 = `${P}/email@0.10`;
      // Its own account: joining a team pauses the Personal workspace the other cases use.
      const admin = await sp.register('Tess Team', `tess-weekly-${Date.now()}@test.local`) as unknown as Account;
      const team = await sp.createGroup(admin.apiKey, `Weekly Team ${Date.now()}`);
      const teamId = team.group.id;
      await sp.setProfileConfig(admin.apiKey, teamId, EMAIL_10, { approvers: [admin.user.id] });
      const keys = ['profile', 'read_access', 'recipient_max', 'send_daily_max', 'send_weekly_max', 'read_max_age_days', 'setup_daily_max'];
      const b = { profile: EMAIL_11, read_access: 'unlimited', recipient_max: 1, send_daily_max: 5, send_weekly_max: 3, setup_daily_max: 0 };
      const r = await sp.submitMandateRaw(admin.apiKey, {
        authorization_id: `authz_${crypto.randomUUID()}`,
        profile_id: EMAIL_11, profile_hash: profileHashFor(EMAIL_11, PROFILES_DIR), group_id: teamId, bounds: b,
        bounds_hash: computeBoundsHash(b, keys), scope_hash: computeScopeHash({ allowed_domains: DOMAIN }, ['allowed_recipients', 'allowed_domains', 'allowed_attachment_sources']),
        domain: admin.user.id, did: admin.user.did, commitment_mode: 'automatic',
        gate_content_hashes: hashGateContent({ intent: 'E2E: team weekly.' }), execution_context_hash: hashExecutionContext({ m: EMAIL_11 }),
      });
      expect(r.status, JSON.stringify(r.body)).toBeGreaterThanOrEqual(400);
      const err = ((r.body.errors as Array<Record<string, unknown>> | undefined)?.[0] ?? r.body) as Record<string, unknown>;
      expect(err.code, JSON.stringify(r.body)).toBe('PROFILE_NOT_ENABLED_FOR_GROUP');
      expect(err.newFields).toEqual(['send_weekly_max']);
      expect(err.carriedOverFrom).toBe(EMAIL_10);
    });
  });

  describe('Email through the gateway (simulation): send_weekly_max 3', () => {
    beforeAll(async () => {
      stack = {
        dataDir: mkdtempSync(join(tmpdir(), 'hap-e2e-weekly-')), ports: PORTS, secret: newSecret(), asUrl: AS_URL,
        extraEnv: { SUVEREN_SIMULATION: '1', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
      };
      await startControlPlane(pm, stack, 'cp-weekly');
      await startMcpServer(pm, stack, 'mcp-weekly');
      cp = new ControlPlaneClient(`http://localhost:${PORTS.cp}`);
      expect((await cp.login(owner.apiKey)).status).toBe(200);
      mcp = new GatewayClient(`http://localhost:${PORTS.mcp}`, stack.secret);
      const act = await cp.authed(owner.apiKey, 'POST', '/mcp/integrations/mail/activate');
      expect(act.status, await act.text()).toBe(200);
      await mcp.waitForIntegration('mail');

      // The AI may propose Email mandates (the setup mandate, review mode).
      const dBounds = { profile: DELEGATION, read_access: 'unlimited', brief_daily_max: 0, mandate_daily_max: 50 };
      const dScope = { allowed_profiles: 'email', allowed_modes: 'review,automatic' };
      const dBoundsHash = computeBoundsHash(dBounds, DELEGATION_KEYS);
      const dContextHash = computeScopeHash(dScope, ['allowed_profiles', 'allowed_modes']);
      const dGate = { intent: 'E2E: let the AI propose Email mandates.' };
      const d = await sp.submitMandate(owner.apiKey, {
        profile_id: DELEGATION, profile_hash: profileHashFor(DELEGATION, PROFILES_DIR), group_id: groupId, bounds: dBounds, bounds_hash: dBoundsHash,
        scope_hash: dContextHash, domain: 'owner', did: owner.user.did, commitment_mode: 'review',
        gate_content_hashes: hashGateContent(dGate), execution_context_hash: hashExecutionContext({ m: DELEGATION }),
      });
      await mcp.pushGateContent({ authorizationId: d.authorization_id, boundsHash: dBoundsHash, contextHash: dContextHash, context: dScope }, DELEGATION, dGate);

      const mailBin = join(stack.dataDir, 'integrations', 'node_modules', '@humanagencyp', 'email-mcp', 'dist', 'index.js');
      const env: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== 'DATABASE_URL') env[k] = v;
      mailbox = new Client({ name: 'operator-mailbox', version: '1.0.0' }, { capabilities: {} });
      await mailbox.connect(new StdioClientTransport({ command: process.execPath, args: [mailBin], env: { ...env, HAP_DATA_DIR: stack.dataDir } }));
      await new Promise((r) => setTimeout(r, 1_500));
      agent = new Client({ name: 'weekly-agent', version: '1.0.0' }, { capabilities: {} });
      await agent.connect(new SSEClientTransport(new URL(`http://localhost:${PORTS.mcp}/sse`)));
    }, 300_000);

    it('the AI is told the field: "per week"', async () => {
      const r = await tool('list-authorizations', { domain: 'email' });
      expect(r.text).toContain('send_weekly_max');
    });

    it('an AI-proposed Email mandate with a weekly limit is created under email@0.11 (the default)', async () => {
      const r = await tool('setup__create_mandate', {
        profile: 'email', limits: { read_access: 'unlimited', recipient_max: 1, send_daily_max: 10, send_weekly_max: 3, setup_daily_max: 0 },
        scope: { allowed_domains: DOMAIN }, intent: 'Why — a few replies a week.', mode: 'automatic', duration_hours: 2, title: 'Weekly replies',
      });
      expect(r.denied, r.text).toBe(false);
      const proposalId = r.text.match(/Proposal ID: ([a-f0-9-]+)/)![1];
      const c = await as('POST', `/api/proposals/${proposalId}/resolve`, { action: 'commit', domain: 'owner' });
      expect(c.status, JSON.stringify(c.body)).toBeLessThan(300);
      const until = Date.now() + 25_000;
      let m: Awaited<ReturnType<typeof activeEmail>>[number] | undefined;
      while (Date.now() < until && !m) {
        m = (await activeEmail())[0];
        if (!m) await new Promise((res) => setTimeout(res, 500));
      }
      expect(m, 'no Email mandate appeared after approval').toBeTruthy();
      expect(m!.profileId ?? m!.profile_id).toBe(EMAIL_11);
      await new Promise((res) => setTimeout(res, 1_000));
    }, 60_000);

    it('three sends go out; the fourth is refused with the weekly limit named, and nothing is sent', async () => {
      const before = await sentCount();
      for (let i = 1; i <= 3; i++) {
        const s = await send(i);
        expect(s.denied, s.text).toBe(false);
      }
      expect(await sentCount()).toBe(before + 3);
      const s = await send(4);
      expect(s.denied, s.text).toBe(true);
      expect(s.text).toMatch(/send_weekly_max|weekly/i);
      expect(await sentCount()).toBe(before + 3);
    }, 120_000);
  });
});
