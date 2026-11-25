/**
 * Signing in to a gateway that already belongs to someone (security review
 * 2026-11, finding A3 — the part Maria approved 2026-11-12).
 *
 * Real Authority Server, real gateway (control plane + MCP server), two real
 * accounts: Anna owns the gateway, Mallory has a valid key of her own.
 *
 *  - A wrong key, or Mallory's key, never signs Anna out.
 *  - While Anna is signed in, Mallory is refused with the approved sentence.
 *  - Anna has a mandate on the gateway but no connector credential. Signed
 *    out, Mallory's sign-in is still not a silent account switch: it asks
 *    for the wipe, and Anna's mandate stays readable for Anna.
 *  - A vault from before the verifier existed (the test removes it from the
 *    file, which is what such a vault looks like) still detects Mallory and
 *    gains the verifier at Anna's next sign-in.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { ProcessManager } from '../src/helpers/process-manager';
import { SPClient } from '../src/helpers/sp-client';
import { computeBoundsHash, hashGateContent, hashExecutionContext } from '../src/helpers/crypto';
import { PROFILE_V07, profileHashFor } from '../src/helpers/profiles';

const SP_PORT = 19540;
const CP_PORT = 19541;
const MCP_PORT = 19542;
const SP_URL = `http://localhost:${SP_PORT}`;
const CP_URL = `http://localhost:${CP_PORT}`;
const PROFILES_DIR = `${process.cwd()}/../hap-profiles`;
const PROFILE = PROFILE_V07.customers;
const SENTENCE = 'This gateway is signed in to another account. Sign out first, then sign in with the new one.';

const pm = new ProcessManager();
let annaKey = '';
let malloryKey = '';
let authorizationId = '';
let dataDir = '';

const login = (key: string, body: Record<string, unknown> = {}) =>
  fetch(`${CP_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
    body: JSON.stringify(body),
  });
const logout = (key: string) => fetch(`${CP_URL}/auth/logout`, { method: 'POST', headers: { 'X-API-Key': key } });
const health = async () => (await fetch(`${CP_URL}/health`)).json() as Promise<{ vaultUnlocked: boolean }>;
const authed = (key: string, path: string, init: RequestInit = {}) =>
  fetch(`${CP_URL}${path}`, { ...init, headers: { 'Content-Type': 'application/json', 'X-API-Key': key, ...(init.headers ?? {}) } });

/** Anna is signed in and her key works on a guarded route. */
async function expectAnnaSignedIn() {
  expect((await health()).vaultUnlocked).toBe(true);
  expect((await authed(annaKey, '/mcp/integrations')).status).toBe(200);
}

/** Anna's mandate content, read back through the gateway with her key. */
async function annaMandateIntent(): Promise<string | undefined> {
  const r = await authed(annaKey, `/gate-content?path=${encodeURIComponent(authorizationId)}`);
  expect(r.status).toBe(200);
  const body = await r.json() as { entry?: { gateContent?: { intent?: string } } | null };
  return body.entry?.gateContent?.intent;
}

/** Each signed-out case starts from Anna signed in, then signing out — so
 *  it does not depend on what an earlier case did to the session. */
async function annaSignsOut() {
  if (!(await health()).vaultUnlocked) expect((await login(annaKey)).status).toBe(200);
  expect((await logout(annaKey)).status).toBe(200);
  expect((await health()).vaultUnlocked).toBe(false);
}

const vaultFile = () => join(dataDir, 'vault.enc.json');
const readVault = () => JSON.parse(readFileSync(vaultFile(), 'utf-8')) as { verifier?: unknown; credentials: Record<string, unknown> };

beforeAll(async () => {
  pm.buildGateway();
  await pm.startSP(SP_PORT);
  const sp = new SPClient(SP_URL);
  const stamp = Date.now();
  const anna = await sp.register('Anna', `switch-anna-${stamp}@test.com`);
  const mallory = await sp.register('Mallory', `switch-mallory-${stamp}@test.com`);
  annaKey = anna.apiKey;
  malloryKey = mallory.apiKey;

  const prev = process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
  process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = '1';
  try {
    await pm.startGateway({ port: MCP_PORT, cpPort: CP_PORT, spUrl: SP_URL, spApiKey: annaKey, profilesDir: PROFILES_DIR });
  } finally {
    if (prev === undefined) delete process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS;
    else process.env.SUVEREN_DISABLE_AUTO_INTEGRATIONS = prev;
  }
  dataDir = pm.getDataDir();

  // Anna grants a mandate and the gateway stores its content (encrypted
  // with her vault key), the way the mandate page does.
  const bounds = {
    profile: PROFILE, read_access: 'unlimited', export_access: 'none',
    write_daily_max: 5, delete_daily_max: 1, setup_daily_max: 0,
  };
  const boundsHash = computeBoundsHash(bounds, ['profile', 'read_access', 'export_access', 'write_daily_max', 'delete_daily_max', 'setup_daily_max']);
  const contextHash = computeBoundsHash({}, []);
  const intent = 'Anna: keep the customer list current.';
  const att = await sp.submitMandate(annaKey, {
    profile_id: PROFILE,
    profile_hash: profileHashFor(PROFILE, PROFILES_DIR),
    group_id: await sp.getPersonalGroupId(annaKey),
    domain: 'owner',
    did: anna.user.did,
    bounds,
    bounds_hash: boundsHash,
    scope_hash: contextHash,
    gate_content_hashes: hashGateContent({ intent }),
    execution_context_hash: hashExecutionContext({ profile: PROFILE, domain: 'owner' }),
    commitment_mode: 'automatic',
  });
  authorizationId = att.authorization_id;
  const push = await authed(annaKey, '/gate-content', {
    method: 'POST',
    body: JSON.stringify({ authorizationId, boundsHash, contextHash, context: {}, path: PROFILE, gateContent: { intent } }),
  });
  expect(push.status, await push.clone().text()).toBe(200);
  expect(await annaMandateIntent()).toBe(intent);
  // Anna's mandate is sealed on disk. (The vault holds no connector
  // credential; its only credential is the gateway's own E2EE key pair,
  // written in the background after sign-in.)
  expect(existsSync(join(dataDir, 'gates.enc.json'))).toBe(true);
  expect(Object.keys(readVault().credentials).filter(k => k !== 'e2eKey')).toEqual([]);
}, 300_000);

afterAll(async () => {
  await pm.killAll();
});

describe('A3 — another key never ends Anna\'s session', () => {
  it('a wrong key is refused and Anna stays signed in', async () => {
    const r = await login('not-a-real-key-0000');
    expect(r.status).toBeGreaterThanOrEqual(400);
    await expectAnnaSignedIn();
  });

  it('Mallory, while Anna is signed in, gets the approved sentence — even when confirming a wipe', async () => {
    for (const body of [{}, { confirmWipe: true }]) {
      const r = await login(malloryKey, body);
      expect(r.status).toBe(409);
      expect(await r.json()).toEqual({ error: 'signed_in_to_another_account', message: SENTENCE });
      await expectAnnaSignedIn();
    }
    expect(await annaMandateIntent()).toBe('Anna: keep the customer list current.');
  });
});

describe('A3 — signed out: Mallory never takes over Anna\'s gateway silently', () => {
  it('control: with the vault as sign-in leaves it, the wipe is asked for and nothing changes', async () => {
    await annaSignsOut();
    const before = readFileSync(join(dataDir, 'gates.enc.json'), 'utf-8');

    const r = await login(malloryKey);
    expect(r.status).toBe(409);
    expect((await r.json() as { error?: string }).error).toBe('different_account');
    expect((await health()).vaultUnlocked).toBe(false);
    expect(readFileSync(join(dataDir, 'gates.enc.json'), 'utf-8')).toBe(before);

    expect((await login(annaKey)).status).toBe(200);
    expect(await annaMandateIntent()).toBe('Anna: keep the customer list current.');
  });

  it('a mandate but no credential at all, in a vault from before the verifier: still detected, and the vault gains the verifier', async () => {
    await annaSignsOut();
    // What such a vault looks like on disk: Anna's mandate in gates.enc.json,
    // no credential in vault.enc.json (the E2EE key pair was never written —
    // it is written in the background after sign-in, and nothing retries it),
    // and no verifier (a vault from before it existed).
    const v = readVault();
    v.credentials = {};
    delete v.verifier;
    writeFileSync(vaultFile(), JSON.stringify(v, null, 2));

    const r = await login(malloryKey);
    expect(r.status, 'Mallory took over the gateway silently').toBe(409);
    expect((await r.json() as { error?: string }).error).toBe('different_account');
    expect((await health()).vaultUnlocked).toBe(false);
    expect(readVault().verifier).toBeUndefined();

    expect((await login(annaKey)).status).toBe(200);
    expect(readVault().verifier, 'the old vault gained its verifier').toBeTruthy();
    expect(await annaMandateIntent()).toBe('Anna: keep the customer list current.');
  });
});
