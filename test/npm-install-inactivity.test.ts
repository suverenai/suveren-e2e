/**
 * A connector install on a dead network fails with a clear error instead of hanging forever.
 *
 * Found 2026-11-19: a full run hung overnight in `npm install` (the network dropped; npm never
 * returned), and the gateway's installs are serialised, so every later activation would have waited
 * too. The gateway now ends an install that shows no progress for SUVEREN_NPM_INSTALL_IDLE_MS
 * (default 5 minutes): no output from npm and no change in its target folder.
 *
 * Real path: the MCP server from the build, a registry the test runs itself that ACCEPTS connections
 * and never answers (what a dead network looks like to npm), npm's own timeouts set far beyond the
 * gateway's limit, and a package name nothing has preinstalled. The activation must fail with the
 * gateway's message well before npm itself would give up. Fails on a gateway without the limit: the
 * activation never ends and the test times out.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProcessManager } from '../src/helpers/process-manager.js';
import { GatewayClient } from '../src/helpers/gateway-client.js';
import { GW_DIR, newSecret, startMcpServer, type StackOptions } from '../src/helpers/gateway-stack.js';
import { e2ePort } from '../src/helpers/ports.js';

const MCP_PORT = e2ePort(19411);
const REGISTRY_PORT = e2ePort(19412);
const IDLE_MS = 15_000;
const available = existsSync(join(GW_DIR, 'apps', 'mcp-server', 'src', 'lib', 'inactivity-watch.ts'));

const pm = new ProcessManager();
const dataDir = mkdtempSync(join(tmpdir(), 'hap-e2e-npm-idle-'));
const secret = newSecret();
const stack: StackOptions = {
  dataDir, ports: { cp: e2ePort(19410), mcp: MCP_PORT }, secret, asUrl: `http://localhost:${e2ePort(19413)}`,
  extraEnv: {
    SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1',
    SUVEREN_OFFLINE: '',
    SUVEREN_NPM_INSTALL_IDLE_MS: String(IDLE_MS),
    npm_config_registry: `http://127.0.0.1:${REGISTRY_PORT}/`,
    // npm's own limits far beyond the gateway's: only the gateway's watch can end this install.
    npm_config_fetch_timeout: '600000',
    npm_config_fetch_retries: '0',
    npm_config_fetch_retry_maxtimeout: '600000',
  },
};
const mcpInternal = new GatewayClient(`http://localhost:${MCP_PORT}`, secret);

let registry: Server;
const sockets = new Set<Socket>();
let connections = 0;

describe.skipIf(!available)('npm install inactivity limit (real gateway, a registry that never answers)', () => {
  beforeAll(async () => {
    registry = createServer((s) => { connections += 1; sockets.add(s); s.on('close', () => sockets.delete(s)); /* accept, never answer */ });
    await new Promise<void>((r) => registry.listen(REGISTRY_PORT, '127.0.0.1', () => r()));
    pm.buildGateway();
    await startMcpServer(pm, stack, 'mcp');
  }, 300_000);

  afterAll(async () => {
    for (const s of sockets) s.destroy();
    registry?.close();
    await pm.killAll();
    rmSync(dataDir, { recursive: true, force: true });
  }, 30_000);

  it('the activation fails with the gateway\'s message after the limit, not npm\'s, and not never', async () => {
    const started = Date.now();
    await mcpInternal.addIntegration({
      id: 'idle-probe', name: 'Idle probe', command: 'node', args: ['-e', '0'], envKeys: {}, profile: null, enabled: true,
      npmPackage: '@humanagencyp/e2e-npm-idle-probe',
    } as Parameters<GatewayClient['addIntegration']>[0]).catch(() => undefined);
    let row: { error?: string; running?: boolean } | undefined;
    while (Date.now() - started < IDLE_MS * 6) {
      row = (await mcpInternal.integrations()).find((i) => i.id === 'idle-probe');
      if (row?.error) break;
      await new Promise((r) => setTimeout(r, 1_000));
    }
    const took = Date.now() - started;
    expect(row?.error, JSON.stringify(row)).toMatch(/made no progress/);
    expect(row?.running).not.toBe(true);
    // Ended by the watch: not before the limit, and long before npm's own 10-minute timeout.
    expect(took).toBeGreaterThanOrEqual(IDLE_MS - 1_000);
    expect(took).toBeLessThan(IDLE_MS * 6);
    expect(connections, 'npm reached the registry and waited on it').toBeGreaterThan(0);
  }, 180_000);
});
