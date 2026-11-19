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
 * is missing the suite skips with the reason (HAP_E2E_PHONE_UNAVAILABLE) instead of failing.
 *
 * Where things are: the same sibling layout as the rest of this suite (src/helpers/as-dir.ts). HAP_E2E_APPROVE_DIR names the
 * app's folder when it is not suveren-gateway/apps/approve next to this checkout.
 */
import { execFileSync, execSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AS_DIR } from '../../src/helpers/as-dir';
import { ProcessManager } from '../../src/helpers/process-manager';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const APP_DIR = process.env.HAP_E2E_APPROVE_DIR ?? join(ROOT, 'suveren-gateway', 'apps', 'approve');

// Ports are not in any lane of the machine map; HAP_E2E_PHONE_*_PORT moves them when another run holds one.
const AS_PORT = Number(process.env.HAP_E2E_PHONE_AS_PORT ?? 19940);
const APP_PORT = Number(process.env.HAP_E2E_PHONE_APP_PORT ?? 19941);
const LOOKALIKE_PORT = Number(process.env.HAP_E2E_PHONE_LOOKALIKE_PORT ?? 19942);

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
};

/** Static files with the single-page fallback of any static host; `/__blank` is a document with nothing in it. */
function serve(dir: string, port: number): Promise<Server> {
  const server = createServer((req, res) => {
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
  const appUrl = `http://localhost:${APP_PORT}`;
  const lookalikeUrl = `http://localhost:${LOOKALIKE_PORT}`;

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
  await pm.startSP(AS_PORT, { name: 'as-phone', env: { SUVEREN_DEVICE_KEYS: 'on', SUVEREN_APP_ORIGIN: appUrl } });
  const app = await serve(outDir, APP_PORT);
  const lookalike = await serve(outDir, LOOKALIKE_PORT);

  Object.assign(process.env, {
    HAP_E2E_PHONE_AS_URL: asUrl,
    HAP_E2E_PHONE_APP_URL: appUrl,
    HAP_E2E_PHONE_LOOKALIKE_URL: lookalikeUrl,
    HAP_E2E_PHONE_DB_URL: pm.asDatabaseUrl() ?? '',
  });
  delete process.env.HAP_E2E_PHONE_UNAVAILABLE;
  console.error(`[E2E] Phone stack ready: AS ${asUrl}, app ${appUrl}, look-alike ${lookalikeUrl}.`);

  return async () => {
    for (const s of [app, lookalike]) {
      s.closeAllConnections();
      await new Promise<void>((r) => s.close(() => r()));
    }
    await pm.killAll();
    rmSync(outDir, { recursive: true, force: true });
  };
}
