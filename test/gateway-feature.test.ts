/**
 * The skip guard (src/helpers/gateway-feature.ts): a gateway feature check may let a test skip only
 * against a gateway older than the release that shipped the feature. Pure helper, no servers.
 */
import { describe, it, expect } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gatewayHas, gatewayVersion, versionAtLeast } from '../src/helpers/gateway-feature.js';

function gatewayAt(version: string | null): string {
  const dir = mkdtempSync(join(tmpdir(), 'gw-feature-'));
  if (version) writeFileSync(join(dir, 'package.json'), JSON.stringify({ version }));
  return dir;
}

describe('skip guard for gateway features', () => {
  it('compares plain versions numerically', () => {
    expect(versionAtLeast('0.45.0', '0.45.0')).toBe(true);
    expect(versionAtLeast('0.45.0', '0.9.0')).toBe(true);
    expect(versionAtLeast('0.31.1', '0.31.2')).toBe(false);
    expect(versionAtLeast('1.0.0-rc.1', '1.0.0')).toBe(true);
  });

  it('a present feature is present, whatever the version', () => {
    const dir = gatewayAt('0.1.0');
    try { expect(gatewayHas('x', '0.30.0', true, dir)).toBe(true); } finally { rmSync(dir, { recursive: true }); }
  });

  it('a missing feature may skip against an older gateway', () => {
    const dir = gatewayAt('0.29.9');
    try { expect(gatewayHas('x', '0.30.0', false, dir)).toBe(false); } finally { rmSync(dir, { recursive: true }); }
  });

  it('a missing feature fails against the release that shipped it or newer', () => {
    const dir = gatewayAt('0.45.0');
    try {
      expect(() => gatewayHas('approval row', '0.31.0', false, dir))
        .toThrow('gateway 0.45.0 should have "approval row" (shipped in 0.31.0)');
    } finally { rmSync(dir, { recursive: true }); }
  });

  it('an unreadable gateway version lets the test skip (no gateway checkout beside the suite)', () => {
    const dir = gatewayAt(null);
    try {
      expect(gatewayVersion(dir)).toBeNull();
      expect(gatewayHas('x', '0.30.0', false, dir)).toBe(false);
    } finally { rmSync(dir, { recursive: true }); }
  });
});
