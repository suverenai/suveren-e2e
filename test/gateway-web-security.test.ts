/**
 * The gateway's UI + API port against hostile requests (security review
 * 2026-11, findings A1, A2, A4, A5, B).
 *
 * Real Authority Server, real gateway (control plane + MCP server) built from
 * source, signed in the way a person signs in. Every request below is the
 * exact one an attacker would send: raw HTTP, so neither fetch nor a URL
 * parser in this test can clean the path or the Host header first.
 *
 *  - A1: the OAuth callback page shows `?error=<script>…` as text, not script.
 *  - A2: a foreign Host header (DNS rebinding) is refused on /auth, /api and
 *        /internal — and the same requests with Host localhost still work.
 *  - A4: POST /mcp/integrations cannot start an arbitrary program.
 *  - A5: an OAuth callback without the state its start issued is refused.
 *  - B:  `/api\groups` and friends never reach the Authority Server without
 *        the API key (the proxy used to forward them WITH the person's
 *        session cookie).
 *
 * Runs in production mode (no simulation): simulation refuses an integration
 * without a manifest on its own, which would hide A4.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { request as httpRequest } from 'node:http';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProcessManager } from '../src/helpers/process-manager';
import { SPClient } from '../src/helpers/sp-client';

const SP_PORT = 19400;
const CP_PORT = 19401;
const MCP_PORT = 19430;
const SP_URL = `http://localhost:${SP_PORT}`;
const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;

const pm = new ProcessManager();
let apiKey = '';
let markerDir = '';

interface RawResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** One raw HTTP/1.1 request to the control plane: path and Host exactly as given. */
function raw(
  path: string,
  opts: { method?: string; host?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        host: '127.0.0.1',
        port: CP_PORT,
        method: opts.method ?? 'GET',
        path,
        headers: {
          host: opts.host ?? `localhost:${CP_PORT}`,
          ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }),
        );
      },
    );
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const withKey = () => ({ 'x-api-key': apiKey });
const fromAs = (r: RawResponse) => String(r.headers['x-powered-by'] ?? '').includes('Next.js');

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);
  const sp = new SPClient(SP_URL);
  const user = await sp.register('WebSecUser', `websec-${Date.now()}@test.com`);
  apiKey = user.apiKey;

  // No default connectors: nothing in this suite needs one, and npm installs
  // would only slow it down.
  const prev = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
  process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';
  try {
    await pm.startGateway({
      port: MCP_PORT,
      cpPort: CP_PORT,
      spUrl: SP_URL,
      spApiKey: apiKey,
      profilesDir: PROFILES_DIR,
    });
  } finally {
    if (prev === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = prev;
  }
  markerDir = mkdtempSync(join(tmpdir(), 'hap-e2e-websec-'));
}, 300_000);

afterAll(async () => {
  await pm.killAll();
  if (markerDir) rmSync(markerDir, { recursive: true, force: true });
});

describe('B — the API key guard and the /api proxy read the same path', () => {
  it('control: /api/groups with the key reaches the Authority Server; without it, 401', async () => {
    const ok = await raw('/api/groups', { headers: withKey() });
    expect(ok.status).toBe(200);
    expect(fromAs(ok), 'the control must prove the AS marker header').toBe(true);
    const noKey = await raw('/api/groups');
    expect(noKey.status).toBe(401);
    expect(fromAs(noKey)).toBe(false);
  });

  for (const path of ['/api\\groups', '/api%5Cgroups', '/api%5cgroups', '/api\\as\\pubkey', '//api/groups', '/api/../api/groups']) {
    it(`${JSON.stringify(path)} without the key is refused and never reaches the Authority Server`, async () => {
      const r = await raw(path);
      expect([400, 401], `${path} → ${r.status} ${r.body.slice(0, 200)}`).toContain(r.status);
      expect(fromAs(r), `${path} was proxied to the Authority Server`).toBe(false);
    });
  }

  it('/apix is not /api: never proxied (with or without the key)', async () => {
    for (const headers of [{}, withKey()]) {
      const r = await raw('/apix', { headers });
      expect(fromAs(r), `/apix was proxied to the Authority Server (${r.status})`).toBe(false);
    }
  });
});

describe('A2 — a foreign Host is refused on every route', () => {
  const FOREIGN = `rebind.attacker.example:${CP_PORT}`;

  it('/auth/login', async () => {
    const r = await raw('/auth/login', { method: 'POST', host: FOREIGN, headers: withKey(), body: '{}' });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body)).toEqual({ error: 'Forbidden host' });
  });

  it('/api (with a valid key)', async () => {
    const r = await raw('/api/groups', { host: FOREIGN, headers: withKey() });
    expect(r.status).toBe(403);
    expect(fromAs(r)).toBe(false);
    expect(JSON.parse(r.body)).toEqual({ error: 'Forbidden host' });
  });

  it('/internal', async () => {
    const r = await raw('/internal/event', { method: 'POST', host: FOREIGN, body: '{"type":"x"}' });
    expect(r.status).toBe(403);
    expect(JSON.parse(r.body)).toEqual({ error: 'Forbidden host' });
  });

  it('the UI and /health', async () => {
    for (const path of ['/', '/health']) {
      const r = await raw(path, { host: FOREIGN });
      expect(r.status, path).toBe(403);
    }
  });

  it('control: the same requests with Host localhost / 127.0.0.1 are not refused for their host', async () => {
    for (const host of [`localhost:${CP_PORT}`, `127.0.0.1:${CP_PORT}`]) {
      const api = await raw('/api/groups', { host, headers: withKey() });
      expect(api.status, host).toBe(200);
      const health = await raw('/health', { host });
      expect(health.status, host).toBe(200);
    }
    // Same account signs in again: accepted.
    const login = await raw('/auth/login', { method: 'POST', headers: withKey(), body: '{}' });
    expect(login.status).toBe(200);
  });
});

describe('A4 — no free-form connector start', () => {
  it('POST /mcp/integrations with an arbitrary command is refused and nothing runs', async () => {
    const marker = join(markerDir, 'spawned');
    const r = await raw('/mcp/integrations', {
      method: 'POST',
      headers: withKey(),
      body: JSON.stringify({
        id: 'websec-evil',
        name: 'Evil',
        command: process.execPath,
        args: ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran')`],
        envKeys: {},
        profile: null,
        enabled: true,
      }),
    });
    expect(r.status, r.body.slice(0, 300)).toBeGreaterThanOrEqual(400);
    await new Promise((res) => setTimeout(res, 3_000));
    expect(existsSync(marker), 'the posted command was spawned').toBe(false);
    const list = await raw('/mcp/integrations', { headers: withKey() });
    expect(list.status).toBe(200);
    const ids = ((JSON.parse(list.body) as { integrations?: Array<{ id: string }> }).integrations ?? []).map((i) => i.id);
    expect(ids).not.toContain('websec-evil');
  });
});

describe('A1 + A5 — the OAuth start and callback', () => {
  let state = '';

  beforeAll(async () => {
    // An OAuth client for the LinkedIn connector, as the Integrations card saves it.
    const put = await raw('/vault/credentials/linkedin', {
      method: 'PUT',
      headers: withKey(),
      body: JSON.stringify({ clientId: 'e2e-websec-client', clientSecret: 'e2e-websec-secret' }),
    });
    expect(put.status, put.body).toBe(200);
  });

  it('start sends the browser to the provider with a random state', async () => {
    const r = await raw('/auth/oauth/linkedin/start');
    expect(r.status).toBe(302);
    const location = new URL(String(r.headers.location));
    state = location.searchParams.get('state') ?? '';
    expect(state.length, `no state in ${location.toString()}`).toBeGreaterThanOrEqual(32);
    expect(location.searchParams.get('client_id')).toBe('e2e-websec-client');
  });

  it('A1: the error the provider (or an attacker) puts in the callback is shown as text', async () => {
    const payload = '<script>alert(document.domain)</script>';
    const r = await raw(
      `/auth/oauth/linkedin/callback?state=${encodeURIComponent(state)}&error=${encodeURIComponent(payload)}`,
    );
    expect(r.status).toBe(400);
    expect(r.body).not.toContain(payload);
    expect(r.body).toContain('&lt;script&gt;alert(document.domain)&lt;/script&gt;');
  });

  it('A5: the state was single-use — the same state again is refused', async () => {
    const r = await raw(`/auth/oauth/linkedin/callback?state=${encodeURIComponent(state)}&code=attacker-code`);
    expect(r.status).toBe(400);
    expect(r.body).toContain('Sign-in not accepted');
  });

  it('A5: a callback without state, with a made-up state, or with an error and no state is refused before anything else', async () => {
    for (const qs of ['code=attacker-code', 'state=made-up&code=attacker-code', `error=${encodeURIComponent('<b>x</b>')}`]) {
      const r = await raw(`/auth/oauth/linkedin/callback?${qs}`);
      expect(r.status, qs).toBe(400);
      expect(r.body, qs).toContain('Sign-in not accepted');
      expect(r.body, qs).not.toContain('<b>x</b>');
    }
  });

  it('A5: a state issued for one connector is refused for another', async () => {
    const start = await raw('/auth/oauth/linkedin/start');
    const s = new URL(String(start.headers.location)).searchParams.get('state') ?? '';
    expect(s).not.toBe('');
    const r = await raw(`/auth/oauth/mail/callback?state=${encodeURIComponent(s)}&code=attacker-code`);
    expect(r.status).toBe(400);
    expect(r.body).toContain('Sign-in not accepted');
  });
});
