/**
 * One switch to run two copies of the suite side by side on one machine ("worlds").
 *
 * HAP_E2E_PORT_OFFSET is added to every fixed port the suite uses (Authority Servers, gateways,
 * stubs), in the vitest suites and the Playwright configs alike, and names the Playwright run's
 * database apart (see `worldDbName`). Unset or 0: every port and database is exactly as before.
 *
 * The suite's fixed ports lie between 13000 and 19999. The offset must be a multiple of 10000, so the
 * shifted ranges never overlap (0 → 13000–19999, 10000 → 23000–29999, 20000 → 33000–39999), and at
 * most 20000, so they stay below the range macOS and Linux hand out for outgoing connections (from
 * 32768 on Linux, 49152 on macOS — 33000–39999 is clear of macOS but not of Linux; use 10000 there).
 *
 * A world is one folder (suveren-e2e beside its own suveren-gateway, suveren-as, …): its builds, its
 * test-results/ and its temp files are its own already. What two worlds would share is the ports and
 * the Playwright run's database; this file moves both. The vitest suites create a throwaway database
 * with a random name per suite, so they never shared one.
 *
 * Not moved: the three addresses in test/as-url-cli.test.ts (SAVED/ENV/FLAG), which are only
 * compared as text — nothing listens on them.
 */
const raw = process.env.HAP_E2E_PORT_OFFSET ?? '0';
export const PORT_OFFSET = Number(raw);

if (!Number.isInteger(PORT_OFFSET) || PORT_OFFSET < 0 || PORT_OFFSET % 10000 !== 0 || PORT_OFFSET > 20000) {
  throw new Error(`HAP_E2E_PORT_OFFSET must be 0, 10000 or 20000 (got "${raw}")`);
}

/** A fixed port of the suite, moved by the world's offset. */
export const e2ePort = (n: number): number => n + PORT_OFFSET;

/** The database a world uses where the suite would otherwise use `name` itself. Unchanged at offset 0. */
export const worldDbName = (name: string): string => (PORT_OFFSET === 0 ? name : `${name}_w${PORT_OFFSET / 10000}`);
