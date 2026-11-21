/**
 * The ERP journey's expected VIES day (src/helpers/vies-day.ts) uses the same clock as
 * the connector and the gateway. Offline: no server.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { viesCheckedDay } from '../src/helpers/vies-day.js';

const viennaDay = (d: Date) => new Intl.DateTimeFormat('en-CA', {
  timeZone: 'Europe/Vienna', year: 'numeric', month: '2-digit', day: '2-digit',
}).format(d);

describe('the VIES check day the card shows', () => {
  afterEach(() => { vi.useRealTimers(); });

  it('at 23:30 UTC it is the UTC day, while Vienna is already on the next day', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-11-21T23:30:00Z'));
    const now = new Date();
    // What erp-mcp stores (checked_at) and what the gateway's |date prints.
    const stored = now.toISOString();
    expect(stored.slice(0, 10)).toBe('2026-11-21');
    expect(viesCheckedDay(Date.now())).toBe('2026-11-21');
    // The old expectation (TODAY_VIENNA) was the next day here: the cause of the 23:00–24:00 UTC failures.
    expect(viennaDay(now)).toBe('2026-11-22');
    expect(viesCheckedDay(now)).not.toBe(viennaDay(now));
  });

  it('at noon UTC both clocks agree', () => {
    expect(viesCheckedDay(new Date('2026-11-21T12:00:00Z'))).toBe('2026-11-21');
  });
});
