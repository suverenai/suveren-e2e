/**
 * The ERP journey's expected VIES day (src/helpers/vies-day.ts) uses the same clock and the
 * same time zone as the gateway's `|date` (fix/check-date-local): the local day of the
 * computer they both run on. Offline: no server.
 *
 * The time zone is a property of the process (TZ), and the test runner's process.env does
 * not reach Node's clock, so each zone runs the helper in a child process of its own with a
 * fixed clock — the fake clock of this test.
 */
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { viesCheckedDay } from '../src/helpers/vies-day.js';

const HELPER = join(import.meta.dirname, '..', 'src', 'helpers', 'vies-day.ts');

/** viesCheckedDay(at) on a computer in time zone `tz`. */
function dayIn(tz: string, at: string): string {
  const code = `import(${JSON.stringify(HELPER)}).then(m => process.stdout.write(m.viesCheckedDay(new Date(${JSON.stringify(at)}))))`;
  return execFileSync(process.execPath, ['--experimental-strip-types', '--no-warnings', '--input-type=module', '-e', code], {
    env: { ...process.env, TZ: tz }, encoding: 'utf8',
  });
}

describe('the VIES check day the card shows', () => {
  it('at 23:30 UTC on a computer in Vienna: the Vienna day, already the next one (the batch 9 failure)', () => {
    // What erp-mcp stores (checked_at) is UTC; the card shows the person's own day.
    expect(new Date('2026-11-21T23:30:00Z').toISOString().slice(0, 10)).toBe('2026-11-21');
    expect(dayIn('Europe/Vienna', '2026-11-21T23:30:00Z')).toBe('2026-11-22');
  });

  it('at 00:30 Vienna time (23:30 UTC the day before): the Vienna day, not yesterday', () => {
    expect(dayIn('Europe/Vienna', '2026-11-20T23:30:00Z')).toBe('2026-11-21');
  });

  it('at 23:30 UTC on a computer in UTC (the Linux CI runner): the UTC day', () => {
    expect(dayIn('UTC', '2026-11-21T23:30:00Z')).toBe('2026-11-21');
  });

  it('in this process: the day of its own clock and zone', () => {
    const at = new Date('2026-11-21T12:00:00Z');
    const own = new Intl.DateTimeFormat('en-CA', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(at);
    expect(viesCheckedDay(at)).toBe(own);
  });
});
