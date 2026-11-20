/**
 * Global setup of the phone app suite (device-keys plan step 11): the real Authority Server and the real phone app, built from
 * source and served as static files, exactly as the app is deployed (no server code, DEC-1).
 *
 *   - the Authority Server: `next start` from the checkout, a throwaway Postgres database, SUVEREN_DEVICE_KEYS=on and
 *     SUVEREN_APP_ORIGIN set to the origin the app is served from (a passkey is only accepted when it was made there)
 *   - the app: `vite build` of apps/approve with VITE_AS_URL pointing at that Authority Server, served by a small static server
 *   - a second static server on the same host and another port: a look-alike origin, for the passkey made "somewhere else"
 *
 * No gateway is started: the gateway side of pairing is not built yet, and the suite plays that side itself
 * (src/helpers/phone-app.ts).
 *
 * Needs SUVEREN_DB_URL (a Postgres, as every Authority Server suite) and checkouts that have the phone routes and the app. When one
 * is missing the suite skips with the reason (HAP_E2E_PHONE_UNAVAILABLE) instead of failing, except with HAP_E2E_PHONE_STRICT=1 (CI).
 *
 * Where things are: the same sibling layout as the rest of this suite (src/helpers/as-dir.ts). HAP_E2E_APPROVE_DIR names the
 * app's folder when it is not suveren-gateway/apps/approve next to this checkout.
 */
import { execFileSync, execSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { createServer } from 'node:https';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AS_DIR } from '../../src/helpers/as-dir';
import { ProcessManager } from '../../src/helpers/process-manager';
import { GW_DIR, newSecret, startControlPlane, startMcpServer, type StackOptions } from '../../src/helpers/gateway-stack';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const APP_DIR = process.env.HAP_E2E_APPROVE_DIR ?? join(ROOT, 'suveren-gateway', 'apps', 'approve');

// Ports are not in any lane of the machine map; HAP_E2E_PHONE_*_PORT moves them when another run holds one.
const AS_PORT = Number(process.env.HAP_E2E_PHONE_AS_PORT ?? 19940);
const APP_PORT = Number(process.env.HAP_E2E_PHONE_APP_PORT ?? 19941);
const LOOKALIKE_PORT = Number(process.env.HAP_E2E_PHONE_LOOKALIKE_PORT ?? 19942);
// A gateway of its own with the switch on (control plane + MCP server, its own data folder) for the gateway-page journeys
// against the phone ("Give on your phone", DEC-90). The default browser suite's gateway is not touched.
const GW_CP_PORT = Number(process.env.HAP_E2E_PHONE_GW_CP_PORT ?? 19943);
const GW_MCP_PORT = Number(process.env.HAP_E2E_PHONE_GW_MCP_PORT ?? 19944);

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
};

/** Static files with the single-page fallback of any static host; `/__blank` is a document with nothing in it. */
function serve(dir: string, port: number, tls: { key: Buffer; cert: Buffer }): Promise<Server> {
  const server = createServer(tls, (req, res) => {
    const path = decodeURIComponent((req.url ?? '/').split('?')[0]);
    res.setHeader('Cache-Control', 'no-store');
    if (path === '/__blank') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><title>blank</title>');
      return;
    }
    const file = normalize(join(dir, path));
    const inside = file.startsWith(dir);
    const exists = inside && existsSync(file) && statSync(file).isFile();
    const target = exists ? file : join(dir, 'index.html');
    if (!exists && extname(path) !== '') { res.writeHead(404); res.end('not found'); return; }
    res.writeHead(200, { 'Content-Type': MIME[extname(target)] ?? 'application/octet-stream' });
    res.end(readFileSync(target));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, () => resolve(server));
  });
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const unavailable = (reason: string): (() => Promise<void>) => {
    // CI sets HAP_E2E_PHONE_STRICT=1: there a missing piece is a broken checkout, and a whole suite skipped would read as green.
    if (process.env.HAP_E2E_PHONE_STRICT === '1') throw new Error(`phone suite cannot run: ${reason}`);
    process.env.HAP_E2E_PHONE_UNAVAILABLE = reason;
    console.error(`[E2E] phone suite skipped: ${reason}`);
    return async () => undefined;
  };
  if (!process.env.SUVEREN_DB_URL) return unavailable('SUVEREN_DB_URL is not set (the Authority Server needs a Postgres)');
  if (!existsSync(join(AS_DIR, 'src', 'app', 'api', 'devices', 'pairings', '[id]', 'passkey', 'route.ts'))) {
    return unavailable(`the Authority Server checkout at ${AS_DIR} has no phone routes (stage D1)`);
  }
  if (!existsSync(join(APP_DIR, 'package.json'))) return unavailable(`the phone app is not at ${APP_DIR} (HAP_E2E_APPROVE_DIR)`);
  if (!existsSync(join(APP_DIR, 'node_modules'))) return unavailable(`${APP_DIR} has no node_modules (run pnpm install in its workspace)`);

  const asUrl = `http://localhost:${AS_PORT}`;
  // The app is served over https, as it is deployed. A built Authority Server refuses an http app origin even on localhost:
  // Next inlines process.env.NODE_ENV as "production" at build time (define-env-plugin), so app-origin.ts's dev-lane allowance
  // for http://localhost never applies to `next build` + `next start`, whatever NODE_ENV the process gets. An https origin is
  // accepted, so the suite takes the production shape instead of loosening that check. The certificate is self-signed and
  // made here; the browsers are told to accept it (ignoreHTTPSErrors in playwright.phone.config.ts).
  const appUrl = `https://localhost:${APP_PORT}`;
  const lookalikeUrl = `https://localhost:${LOOKALIKE_PORT}`;

  // Builds (HAP_E2E_SKIP_BUILD=1 reuses the Authority Server's `.next`, as in the vitest run; the app is always built, it is quick
  // and it carries the Authority Server's address).
  if (process.env.HAP_E2E_SKIP_BUILD !== '1') {
    console.error('[E2E] Building Authority Server (phone suite)...');
    execSync('npm run build', { cwd: AS_DIR, stdio: 'pipe', timeout: 300_000, env: { ...process.env, SUVEREN_ALLOW_EPHEMERAL: '1' } });
  }
  const outDir = mkdtempSync(join(tmpdir(), 'hap-e2e-approve-'));
  console.error('[E2E] Building the phone app...');
  const requireFromApp = createRequire(join(APP_DIR, 'package.json'));
  const viteBin = join(dirname(requireFromApp.resolve('vite/package.json')), 'bin', 'vite.js');
  execFileSync(process.execPath, [viteBin, 'build', '--outDir', outDir, '--emptyOutDir', '--logLevel', 'warn'], {
    cwd: APP_DIR, stdio: 'pipe', timeout: 180_000,
    env: { ...process.env, VITE_AS_URL: asUrl, VITE_BUILD_COMMIT: 'e2e' },
  });

  const pm = new ProcessManager();
  const asProc = await pm.startSP(AS_PORT, { name: 'as-phone', env: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_APP_ORIGIN: appUrl } });
  // The Authority Server's console mailer prints every email (EMAIL_TRANSPORT unset: lib/email ConsoleProvider). The cases run
  // in other processes, so its output is also written to a file they read: the recovery hand-off's link reaches the "phone"
  // the way an email would, by its text (stage D3, replacing the recovery code). The whole output, as it comes: the mailer
  // prints an email's body as ONE multi-line log, so only its first line starts with "[Email]" and the link is on a later one
  // (a line filter dropped it: run 44710456133); a chunk can also end in the middle of a line.
  const asLog = join(outDir, '..', `as-phone-mail-${process.pid}.log`);
  writeFileSync(asLog, '');
  asProc.stdout?.on('data', (chunk: Buffer) => appendFileSync(asLog, chunk));
  const tlsDir = mkdtempSync(join(tmpdir(), 'hap-e2e-approve-tls-'));
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', join(tlsDir, 'key.pem'), '-out', join(tlsDir, 'cert.pem'),
  ], { stdio: 'pipe', timeout: 30_000 });
  const tls = { key: readFileSync(join(tlsDir, 'key.pem')), cert: readFileSync(join(tlsDir, 'cert.pem')) };
  rmSync(tlsDir, { recursive: true, force: true });
  const app = await serve(outDir, APP_PORT, tls);
  const lookalike = await serve(outDir, LOOKALIKE_PORT, tls);

  // The chain gateway: only when the gateway checkout is built (the CI job builds it for the main suite first). Without it, the
  // cases that need it skip with that reason; in CI (strict) that is a failure, not a skip.
  let gwDir: string | null = null;
  const gwSecret = newSecret();
  if (existsSync(join(GW_DIR, 'apps', 'control-plane', 'dist', 'index.mjs')) && existsSync(join(GW_DIR, 'apps', 'mcp-server', 'dist', 'http.mjs'))) {
    gwDir = mkdtempSync(join(tmpdir(), 'hap-e2e-phone-gw-'));
    const stack: StackOptions = {
      dataDir: gwDir, ports: { cp: GW_CP_PORT, mcp: GW_MCP_PORT }, secret: gwSecret, asUrl,
      extraEnv: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_DISABLE_AUTO_INTEGRATIONS: '1' },
    };
    await startControlPlane(pm, stack, 'gw-phone-cp');
    await startMcpServer(pm, stack, 'gw-phone-mcp');
    process.env.HAP_E2E_PHONE_GW_URL = `http://localhost:${GW_CP_PORT}`;
    delete process.env.HAP_E2E_PHONE_GW_UNAVAILABLE;
  } else {
    const reason = `the gateway at ${GW_DIR} is not built (apps/control-plane/dist, apps/mcp-server/dist)`;
    if (process.env.HAP_E2E_PHONE_STRICT === '1') throw new Error(`phone suite cannot run: ${reason}`);
    process.env.HAP_E2E_PHONE_GW_UNAVAILABLE = reason;
  }

  Object.assign(process.env, {
    HAP_E2E_PHONE_AS_URL: asUrl,
    HAP_E2E_PHONE_APP_URL: appUrl,
    HAP_E2E_PHONE_LOOKALIKE_URL: lookalikeUrl,
    HAP_E2E_PHONE_DB_URL: pm.asDatabaseUrl() ?? '',
    HAP_E2E_PHONE_MAIL_LOG: asLog,
  });
  delete process.env.HAP_E2E_PHONE_UNAVAILABLE;
  console.error(`[E2E] Phone stack ready: AS ${asUrl}, app ${appUrl}, look-alike ${lookalikeUrl}.`);

  return async () => {
    for (const s of [app, lookalike]) {
      s.closeAllConnections();
      await new Promise<void>((r) => s.close(() => r()));
    }
    await pm.killAll();
    if (gwDir) rmSync(gwDir, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
    rmSync(asLog, { force: true });
  };
}
