/**
 * "Turn on Touch ID for approvals" on a computer set up WITHOUT a check key (no Touch ID helper at set-up): the Authority
 * Server's half, through a real browser (Chromium) against the real Authority Server.
 *
 * The computer is played here, as elsewhere in this suite (src/helpers/phone-app.ts): real Ed25519 keys, a real platform
 * check key (ECDSA P-256), real chain entries built with hap-core. What the gateway's control plane does on its side (the
 * recovery code signs, the helper makes the key and checks, the callback, the finish) is covered by the control plane's route
 * tests with the fake helper (apps/control-plane/src/routes/__tests__/device-recovery.test.ts): CI runs on Linux, and the
 * gateway only uses a signed macOS helper, so the gateway page's Touch ID step is checked by hand on a Mac.
 *
 * The journey: a root-signed `set` (the recovery code's key) naming the computer and its NEW Touch ID key, checked by that
 * key → staged at the Authority Server → the account gets an email → the link, in the browser where the computer opened the
 * confirm page → the confirm page says what it does and shows the six digits → Confirm → the loopback redirect carries a
 * code → the computer redeems it → the chain names the computer's Touch ID key. And the refusals: a `set` that clears a check
 * key is never staged and nothing is mailed.
 */
import { test, expect, type Page } from '@playwright/test';
import type pg from 'pg';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { buildEntry, signEntry, type ChainEntry, type CheckKey } from '@humanagencyp/hap-core/device-keys';
import {
  checkOver, chainOf, connectDb, enrolmentCode, entryHash, headOf, http, newDevice, newPerson, newRoot, randomBytes, show,
  stackFromEnv, until, verifiedChain, b64uEncode, type PhoneStack,
} from '../../src/helpers/phone-app';
import { genesisEntry } from '../../src/helpers/device-chain';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE;
test.skip(!!unavailable, `phone suite not available: ${unavailable}`);
const chromiumOnly = ({ browserName }: { browserName: string }) => browserName !== 'chromium';

let stack: PhoneStack;
let db: pg.Client;
test.beforeAll(async () => {
  if (unavailable) return;
  stack = stackFromEnv();
  db = await connectDb(stack);
});
test.afterAll(async () => { await db?.end().catch(() => undefined); });

function mailLines(): string[] {
  const f = process.env.HAP_E2E_PHONE_MAIL_LOG;
  if (!f) throw new Error('the global setup keeps no mail log');
  return readFileSync(f, 'utf8').split('\n').filter(Boolean);
}

const PORT = 41987;
const b64u = (b: Buffer): string => b.toString('base64url');

async function newPlatformKey(): Promise<{ check: CheckKey; priv: webcrypto.CryptoKey }> {
  const kp = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;
  return { check: { type: 'platform', pub: b64uEncode(new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey))) }, priv: kp.privateKey };
}

/** A person whose computer was set up WITHOUT a check key: a genesis whose device has no check. */
async function computerWithoutTouchId(label: string) {
  const p = await newPerson(stack, 'Owner without Touch ID');
  const code = await enrolmentCode(stack, db, p);
  const root = await newRoot();
  const dev = await newDevice(label);
  dev.record.check = null;
  dev.record.keystore = 'software';
  const g = await genesisEntry(root, dev);
  g.checks = [];
  const res = await http(stack.asUrl, 'POST', '/api/devices/chain', { body: { entry: g, enrolment_code: code } });
  if (res.status !== 201) throw new Error(`genesis without a check key refused: ${show(res)}`);
  return { p, root, dev, g };
}

async function rootSet(root: Awaited<ReturnType<typeof newRoot>>, prev: ChainEntry, targetKeyId: string, check: CheckKey | null, priv: webcrypto.CryptoKey | null): Promise<ChainEntry> {
  const e = buildEntry({ root_did: root.did, seq: prev.seq + 1, prev: await entryHash(prev), op: 'set', created_at: Math.floor(Date.now() / 1000), signer: 'root', target: targetKeyId, check });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, 'root', root.privateSeed)];
  e.checks = priv ? [{ by: targetKeyId, check: await checkOver(priv, h) }] : [];
  return e;
}

async function shot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: test.info().outputPath(`${name}.png`), fullPage: true });
  await test.info().attach(name, { path: test.info().outputPath(`${name}.png`), contentType: 'image/png' });
}

test.describe('turn on Touch ID for approvals on a computer set up without it (root-signed set, real Authority Server)', () => {
  test.skip(chromiumOnly, 'one browser is enough for the Authority Server pages; the gateway page\'s Touch ID step is checked by hand on a Mac');

  test('recovery code + email link: the confirm page says what it does, the computer redeems, the chain names its Touch ID key', async ({ browser }) => {
    const { p, root, dev, g } = await computerWithoutTouchId('Office Mac');
    expect((await verifiedChain(stack, p, root.did)).devices[dev.record.key_id].check).toBeNull();

    // The computer: a new Touch ID key, a root-signed `set` checked by it, PKCE and a loopback state as the gateway makes them.
    const key = await newPlatformKey();
    const entry = await rootSet(root, g, dev.record.key_id, key.check, key.priv);
    const verifier = b64u(Buffer.from(randomBytes(32)));
    const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    const state = b64u(Buffer.from(randomBytes(32)));
    const stateHash = createHash('sha256').update(state, 'utf8').digest('base64url');
    const before = mailLines().length;
    const staged = await http(stack.asUrl, 'POST', '/api/devices/recovery/handoffs', { body: { entry, code_challenge: challenge, port: PORT, state_hash: stateHash } });
    expect(staged.status, show(staged)).toBe(201);
    const handoff = staged.json.handoff_id as string;
    expect((await chainOf(stack, p, root.did)).entries).toHaveLength(1); // staged, not appended

    const context = await browser.newContext();
    const page = await context.newPage();
    // The computer opened this page in the person's browser; before the email link it only says "check your email".
    const pageUrl = `${stack.asUrl}/recover?${new URLSearchParams({ handoff, port: String(PORT), state }).toString()}`;
    await page.goto(pageUrl);
    await shot(page, '1-confirm-page-before-link');

    // The email: what it asks, and the link.
    const link = await until('the email for the Touch ID set', async () => {
      const hit = mailLines().slice(before).find((l) => l.includes('/recover/link?token='));
      return hit ? /https?:\/\/\S+\/recover\/link\?token=[A-Za-z0-9_-]+/.exec(hit)![0] : undefined;
    }, 20_000);
    expect(mailLines().slice(before).join('\n')).toContain('turn on Touch ID on one of your computers');

    const mail = await context.newPage();
    await mail.goto(link.replace(/^https?:\/\/[^/]+/, stack.asUrl));
    await shot(mail, '2-email-link');
    await mail.getByRole('button', { name: 'Continue' }).click();
    await expect(mail.getByText('Go back to the page your computer opened in this browser')).toBeVisible();
    await shot(mail, '3-link-continued');

    // Back on the page the computer opened: it now shows what the change does and the six digits, then Confirm.
    // The Authority Server answers Confirm with a 302 to the computer's loopback address. Nothing listens there in this test
    // (the computer is played here), so the request itself is read; page.route does not see the target of a redirect.
    let callback: URL | null = null;
    page.on('request', (r) => {
      const u = new URL(r.url());
      if ((u.hostname === '127.0.0.1' || u.hostname === 'localhost') && u.port === String(PORT)) callback = u;
    });
    await page.goto(pageUrl);
    await expect(page.getByText('This turns on Touch ID on')).toBeVisible();
    await expect(page.locator('strong', { hasText: 'Office Mac' })).toBeVisible();
    await expect(page.getByText('removes', { exact: false })).toHaveCount(0);
    const six = (await page.locator('.code').textContent())!.trim();
    expect(six).toMatch(/^\d{6}$/);
    await shot(page, '4-confirm-page');
    await page.getByRole('button', { name: 'Confirm the recovery' }).click();
    await until('the loopback redirect', async () => callback ?? undefined, 20_000);
    expect(callback!.pathname).toBe('/recover/callback');
    expect(callback!.searchParams.get('state')).toBe(state);
    const code = callback!.searchParams.get('code')!;

    // The computer redeems the code with its verifier: the head is the entry it built.
    const redeemed = await http(stack.asUrl, 'POST', '/api/devices/recovery/redeem', { body: { code, code_verifier: verifier } });
    expect(redeemed.status, show(redeemed)).toBe(200);
    const h = await headOf(entry);
    expect(redeemed.json).toMatchObject({ head: h, entry_hash: h.hash });

    // The chain, verified from the genesis on, names the computer's new Touch ID key.
    const after = await verifiedChain(stack, p, root.did);
    expect(after.devices[dev.record.key_id].check).toEqual(key.check);
    const stored = (await chainOf(stack, p, root.did)).entries[1];
    expect(stored).toMatchObject({ op: 'set', signer: 'root', target: dev.record.key_id });
    await context.close();
  });

  test('a root-signed set that would CLEAR a check key is never staged and nothing is mailed', async () => {
    const { root, dev, g } = await computerWithoutTouchId('Spare Mac');
    const before = mailLines().length;
    const clear = await rootSet(root, g, dev.record.key_id, null, null);
    const r = await http(stack.asUrl, 'POST', '/api/devices/recovery/handoffs', {
      body: { entry: clear, code_challenge: createHash('sha256').update('v', 'ascii').digest('base64url'), port: PORT, state_hash: createHash('sha256').update('s', 'utf8').digest('base64url') },
    });
    expect(r.status, show(r)).toBe(400);
    expect(mailLines().slice(before).filter((l) => l.includes('/recover/link?token='))).toHaveLength(0);
  });
});
