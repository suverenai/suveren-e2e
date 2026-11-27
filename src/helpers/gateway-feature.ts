import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * "Does the gateway under test have feature X?" — the guard behind every skip that depends on it.
 *
 * A test that checks for a gateway file and skips when it is missing hides a regression by design:
 * when the device-keys work moved the approval card to packages/approval-card (2026-11-18), 15
 * Playwright and at least 2 vitest tests went green by skipping, and nobody saw it. So each check
 * names the gateway release that shipped the feature. Against an older gateway the test may still
 * skip (CI runs the journeys against several gateway refs). Against that release or newer a missing
 * feature is an error, raised when the test file loads, so the run fails with the reason.
 */
const GW_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'suveren-gateway');

let cachedVersion: string | null | undefined;
/** The version of the gateway checkout under test (its root package.json), or null if unreadable. */
export function gatewayVersion(gwDir: string = GW_DIR): string | null {
  if (gwDir === GW_DIR && cachedVersion !== undefined) return cachedVersion;
  let v: string | null = null;
  try { v = (JSON.parse(readFileSync(join(gwDir, 'package.json'), 'utf8')) as { version?: string }).version ?? null; } catch { v = null; }
  if (gwDir === GW_DIR) cachedVersion = v;
  return v;
}

/** a >= b for plain x.y.z versions (a pre-release suffix is ignored). */
export function versionAtLeast(a: string, b: string): boolean {
  const n = (s: string) => s.replace(/-.*$/, '').split('.').map(x => Number(x) || 0);
  const [x, y] = [n(a), n(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return true;
}

/**
 * `present` as given, but throws when the feature is missing from a gateway that should have it.
 * `since` = the first gateway release that shipped it (git tag --contains of the commit that added it).
 */
export function gatewayHas(feature: string, since: string, present: boolean, gwDir: string = GW_DIR): boolean {
  if (present) return true;
  const v = gatewayVersion(gwDir);
  if (v && versionAtLeast(v, since)) {
    throw new Error(
      `gateway ${v} should have "${feature}" (shipped in ${since}), but this suite cannot find it. ` +
      'A file moved or was renamed, or the check is stale: fix the check, do not let the test skip.',
    );
  }
  return false;
}
