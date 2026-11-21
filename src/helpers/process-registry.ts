/**
 * Process bookkeeping shared by the vitest harness (ProcessManager) and the
 * Playwright harness (e2e/fixtures.ts): every server the harness starts is
 * tracked, can be stopped as a whole process group, is stopped when the
 * runner exits or is signalled, and is checked for at the end of a run.
 *
 * Why this exists. Full runs used to leave Authority Servers (`next-server`)
 * and gateway control planes behind with parent pid 1, a few dozen per run.
 * The causes, all fixed here or in the callers:
 *
 *  1. A suite builds its stack in a helper (`boot()`), and the helper throws
 *     half way (port busy, sign-in refused). The ProcessManager only lived in
 *     that helper's local variable, so the suite's afterAll had nothing to
 *     call killAll() on. Fix: every ProcessManager registers itself, and a
 *     vitest setup file stops all of them after each file, pass or fail.
 *  2. The runner dies before teardown (Ctrl-C, a CI timeout, a vitest worker
 *     killed by the pool). Children were spawned `detached` (own process
 *     group), so they do NOT die with the runner. Fix: exit/SIGINT/SIGTERM
 *     hooks kill every tracked group synchronously.
 *  3. Playwright's globalTeardown does not run when globalSetup throws, and
 *     the servers were not detached, so only the top process was signalled.
 *     Fix: startServers() cleans up after itself on failure.
 *  4. A process frozen with SIGSTOP (as-frozen-retry) never acts on SIGTERM.
 *     Fix: SIGCONT first.
 *  5. Signalling only the leader and treating its exit as "gone" left forked
 *     workers alive. Fix: wait until the whole group is gone, then SIGKILL it.
 *
 * Because vitest runs suites in worker processes and the run ends in another
 * process, every started process is also written to a pid directory
 * (HAP_E2E_PID_DIR, created by beginRun()); finishRun() reads it, warns about
 * anything still alive (with pids) and kills it.
 */
import type { ChildProcess } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { connect } from 'node:net';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ─── Process groups ─────────────────────────────────────────────────────────

// Windows has no process groups and no signals besides "end it": the leader stands for the group, and its whole
// tree is ended with `taskkill /T /F` (which also reaches children that Next forks). SIGCONT does not exist there.
const WINDOWS = process.platform === 'win32';

/** True while any process of the group led by `pid` exists (on Windows: while the leader exists). */
export function groupAlive(pid: number): boolean {
  try {
    process.kill(WINDOWS ? pid : -pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function signalGroup(pid: number, sig: NodeJS.Signals): void {
  if (WINDOWS) {
    if (sig === 'SIGCONT') return;
    try { execFileSync('taskkill', ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore' }); } catch { /* already gone */ }
    return;
  }
  try {
    process.kill(-pid, sig);
  } catch {
    try { process.kill(pid, sig); } catch { /* already gone */ }
  }
}

async function waitGroupGone(pid: number, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (groupAlive(pid)) {
    if (Date.now() > deadline) return false;
    await sleep(50);
  }
  return true;
}

/**
 * Stop the whole process group led by `pid` and wait until it is really gone:
 * SIGCONT (a frozen process cannot handle anything else), SIGTERM, then
 * SIGKILL for whatever is left after `termMs` — including children that
 * outlived their leader.
 */
export async function stopGroup(pid: number, termMs = 5_000): Promise<boolean> {
  if (!groupAlive(pid)) return true;
  signalGroup(pid, 'SIGCONT');
  signalGroup(pid, 'SIGTERM');
  if (await waitGroupGone(pid, termMs)) return true;
  signalGroup(pid, 'SIGKILL');
  return waitGroupGone(pid, 3_000);
}

// ─── Tracking ───────────────────────────────────────────────────────────────

interface Tracked {
  pid: number;
  name: string;
  cmd: string;
}

const live = new Map<number, Tracked>();
let hooksInstalled = false;

function recordPath(pid: number): string | null {
  const dir = process.env.HAP_E2E_PID_DIR;
  return dir && existsSync(dir) ? join(dir, `${pid}.json`) : null;
}

/** Kill every group tracked by THIS process, synchronously (exit hooks). */
export function killTrackedSync(): void {
  for (const { pid } of live.values()) {
    signalGroup(pid, 'SIGCONT');
    signalGroup(pid, 'SIGKILL');
  }
}

function installHooks(): void {
  if (hooksInstalled) return;
  hooksInstalled = true;
  process.on('exit', killTrackedSync);
  for (const [sig, num] of [['SIGINT', 2], ['SIGTERM', 15], ['SIGHUP', 1]] as const) {
    process.on(sig, () => {
      killTrackedSync();
      // Another handler (Playwright's, vitest's) owns graceful shutdown: let it.
      // Otherwise we are the only listener, which swallows the signal — exit
      // the way the default action would have.
      if (process.listenerCount(sig) <= 1) process.exit(128 + num);
    });
  }
}

/**
 * Register a spawned child. Spawn it with `detached: true` so the group
 * (pgid === pid) can be signalled as a whole.
 */
export function trackProcess(proc: ChildProcess, name: string, cmd: string): void {
  if (!proc.pid) return;
  const pid = proc.pid;
  installHooks();
  live.set(pid, { pid, name, cmd });
  const file = recordPath(pid);
  if (file) writeFileSync(file, JSON.stringify({ pid, name, cmd, owner: process.pid }));
  proc.once('exit', () => {
    // The leader is gone; keep the record while forked workers may remain, so
    // the end-of-run check still sees them.
    if (!groupAlive(pid)) untrack(pid);
  });
}

/** Forget a process whose group is confirmed gone. */
export function untrack(pid: number): void {
  live.delete(pid);
  const file = recordPath(pid);
  if (file) rmSync(file, { force: true });
}

export function isRunning(proc: ChildProcess): boolean {
  return proc.exitCode == null && proc.signalCode == null;
}

/** Stop one tracked child (whole group) and forget it. */
export async function stopTracked(proc: ChildProcess, termMs?: number): Promise<void> {
  if (!proc.pid) return;
  await stopGroup(proc.pid, termMs);
  untrack(proc.pid);
}

// ─── Ports ──────────────────────────────────────────────────────────────────

function connects(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host, port });
    const done = (v: boolean) => { s.destroy(); resolve(v); };
    s.setTimeout(1_000, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

/** True when something already listens on `port` (IPv4 or IPv6 loopback). */
export async function portInUse(port: number): Promise<boolean> {
  return (await connects('127.0.0.1', port)) || (await connects('::1', port));
}

/** Who holds the port, best effort ("node (pid 1234)"); empty when unknown. */
export function portHolder(port: number): string {
  try {
    const out = execFileSync('lsof', ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-Fpc'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const pid = /^p(\d+)/m.exec(out)?.[1];
    const cmd = /^c(.+)$/m.exec(out)?.[1];
    return pid ? `${cmd ?? 'process'} (pid ${pid})` : '';
  } catch {
    return '';
  }
}

/** Fail fast, before spawning: a busy fixed port would otherwise let the new
 *  process die with EADDRINUSE while the OLD one answers the health check. */
export async function assertPortFree(port: number, what: string): Promise<void> {
  if (!(await portInUse(port))) return;
  const holder = portHolder(port);
  throw new Error(
    `Cannot start ${what}: port ${port} is in use by another process${holder ? ` — ${holder}` : ''}. ` +
    'Probably a leftover of an earlier run; stop it (or pick another port) and run again.',
  );
}

// ─── Run bracket (global setup / teardown) ──────────────────────────────────

/** SIGKILL every group recorded in the pid directory, synchronously. The
 *  runner's last resort: a test worker that was killed hard (the pool does
 *  that on SIGINT/SIGTERM) cannot run its own exit hooks. */
function sweepSync(dir: string): void {
  if (!existsSync(dir)) return;
  for (const f of readdirSync(dir)) {
    try {
      const { pid } = JSON.parse(readFileSync(join(dir, f), 'utf8')) as Tracked;
      if (groupAlive(pid)) {
        signalGroup(pid, 'SIGCONT');
        signalGroup(pid, 'SIGKILL');
      }
    } catch { /* unreadable record */ }
  }
  rmSync(dir, { recursive: true, force: true });
}

/** Create the pid directory. Call from global setup, before any spawn: workers
 *  and Playwright workers inherit the env var. Also makes the runner sweep it
 *  when it exits or is signalled before the end-of-run check could run. */
export function beginRun(): void {
  const dir = mkdtempSync(join(tmpdir(), 'hap-e2e-pids-'));
  mkdirSync(dir, { recursive: true });
  process.env.HAP_E2E_PID_DIR = dir;
  process.on('exit', () => sweepSync(dir));
  for (const [sig, num] of [['SIGINT', 2], ['SIGTERM', 15], ['SIGHUP', 1]] as const) {
    process.on(sig, () => {
      sweepSync(dir);
      if (process.listenerCount(sig) <= 1) process.exit(128 + num);
    });
  }
}

/**
 * Call at the very end of global teardown. Anything the harness started that
 * is still alive is a leak: list it (pids), kill it, and say so. Returns the
 * leaked records.
 */
export async function finishRun(): Promise<Tracked[]> {
  const dir = process.env.HAP_E2E_PID_DIR;
  if (!dir || !existsSync(dir)) return [];

  const leaked: Tracked[] = [];
  for (const f of readdirSync(dir)) {
    let rec: Tracked;
    try {
      rec = JSON.parse(readFileSync(join(dir, f), 'utf8')) as Tracked;
    } catch { continue; }
    if (groupAlive(rec.pid)) leaked.push(rec);
  }

  if (leaked.length > 0) {
    console.error(
      `[E2E] WARNING: ${leaked.length} process group(s) started by this run were still alive at the end ` +
      `(pids ${leaked.map((l) => l.pid).join(', ')}):\n` +
      leaked.map((l) => `[E2E]   pid ${l.pid}  ${l.name}  ${l.cmd}`).join('\n') +
      '\n[E2E] Killing them now. Something started a server and did not stop it — see src/helpers/process-registry.ts.',
    );
    for (const l of leaked) await stopGroup(l.pid, 1_000);
  }
  rmSync(dir, { recursive: true, force: true });
  delete process.env.HAP_E2E_PID_DIR;
  return leaked;
}
