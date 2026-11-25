/**
 * The phone approval app, part 1 (device-keys plan step 11), against the REAL stack: the real Authority Server (flag on, app
 * address set), the real phone app built from source and served as static files, a real browser.
 *
 * What is real: the app (its keys, its passkey, its screens), the Authority Server (every refusal below is its own or the app's),
 * and the cryptography on both sides. What the test plays itself: the COMPUTER. The gateway side of pairing ("Add this computer",
 * admitting a phone) is not built in the gateway page yet, so a computer with a check key is made here from hap-core's device-keys
 * module (src/helpers/phone-app.ts): the Authority Server and the phone verify what it sends exactly as they would from a gateway.
 *
 * Seams, and why they keep the flow real:
 *   - Passkeys: Chromium's CDP virtual authenticator (WebAuthn.addVirtualAuthenticator, internal transport, user verification on,
 *     presence simulated). The app calls navigator.credentials.create/get itself; the attestation and the assertions are what a
 *     browser makes, at the app's own origin. WebKit has no virtual authenticator, so every case that needs a passkey is skipped
 *     there, and one case checks that the app starts and names what the browser lacks.
 *   - QR scanning: the app's own scanner (getUserMedia, a canvas, the bundled jsQR decoder, then driver.scanned(text)) runs
 *     unchanged. Only the camera is replaced: navigator.mediaDevices.getUserMedia returns a canvas stream on which the test
 *     draws the QR it wants the phone to "see". The decoding and everything after it is the app's own code path.
 *   - The enrolment code: the Authority Server hands it only to a dashboard session opened from an email link; nothing in a test
 *     clicks an email, so that session row is inserted into the throwaway database (same as test/team-member-list.test.ts).
 *   - The identity code "on the other screen": there is no second screen for a phone-first registration yet (the gateway page and
 *     suveren.ai show no identity code for it). The code is derived independently here, from the recovery code the app shows and
 *     from the root DID in the chain the Authority Server serves, and compared with what the app shows.
 *
 * Needs SUVEREN_DB_URL; see e2e/phone/global-setup.ts. Run: npx playwright test -c playwright.phone.config.ts
 */
import { test, expect, type Browser, type BrowserContext, type CDPSession, type Page } from '@playwright/test';
import type pg from 'pg';
import { buildDeviceRecord, buildEntry, deriveRootKey, ed25519PublicKey, encodeCoseEc2, generateRecoveryCode, keyIdOf, rootKeyFromRecoveryCode, signEntry } from '@humanagencyp/hap-core/device-keys';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  computeBoundsHash, computeExecutionContextHash, computeIntentHash, computeProfileHash, computeScopeHash, encryptProposalContent, type MandatePayload,
} from '@humanagencyp/hap-core';
import { buildReceipt, grantHash, signObject, verifyGrant, type MandateGrant } from '@humanagencyp/hap-core/device-keys';
import { grantMembersOf, newMandateId, signedGrant } from '../../src/helpers/mandate-grant';
import {
  asKeyHex, chainOf, clearMailboxes, codeOf, computerAnswersJoin, computerWithChain, connectDb, enrolmentCode, headOf, http,
  identityCodeOf, mailboxRow, newJoiner, newPairing, newPerson, newRoot, nowSec, openMailbox,
  pairingQr, qrMatrix, readBox, show, signinBody, stackFromEnv, until, verifiedChain, waitForMessage,
  b64uEncode, b64uDecode, newDevice, entryHash, randomBytes, checkOver, sessionFor,
  type Computer, type PhoneStack, type Root,
} from '../../src/helpers/phone-app';
import { buildChangeRequest, verifyPhoneAnswer } from '../../src/helpers/change-request';
import { expectStampCentred } from './stamp-centre';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE;
const PROFILES_DIR = process.env.HAP_E2E_PROFILES_DIR ?? join(import.meta.dirname, '..', '..', '..', 'hap-profiles');
test.skip(!!unavailable, `phone suite not available: ${unavailable}`);

const NO_VIRTUAL_AUTHENTICATOR = 'WebKit has no virtual authenticator (no WebAuthn CDP domain), so a passkey cannot be made or used in an automated run. Covered by Chromium; by hand on a real iPhone.';
const chromiumOnly = ({ browserName }: { browserName: string }) => browserName !== 'chromium';

let stack: PhoneStack;
let db: pg.Client;
test.beforeAll(async () => {
  if (unavailable) return;
  stack = stackFromEnv();
  db = await connectDb(stack);
});
test.afterAll(async () => { await db?.end().catch(() => undefined); });

// ─── The phone: a browser context with a passkey store and a camera ───────────────────────────────

/** Replaces only the camera: a canvas stream that shows `window.__qr` (a boolean matrix), redrawn ten times a second. */
function cameraSeam(): void {
  const w = window as unknown as { __qr: boolean[][] | null };
  w.__qr = null;
  if (!navigator.mediaDevices) return;
  navigator.mediaDevices.getUserMedia = async () => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d')!;
    const px = 6;
    const quiet = 4;
    const draw = () => {
      const m = w.__qr;
      const n = m ? m.length : 21;
      canvas.width = canvas.height = (n + quiet * 2) * px;
      ctx.fillStyle = '#fff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      if (m) {
        ctx.fillStyle = '#000';
        m.forEach((row, r) => row.forEach((dark, c) => { if (dark) ctx.fillRect((c + quiet) * px, (r + quiet) * px, px, px); }));
      }
    };
    draw();
    setInterval(draw, 100);
    return canvas.captureStream(10);
  };
}

interface Phone { context: BrowserContext; page: Page; cdp?: CDPSession }

async function newPhone(browser: Browser, o: { passkeys: boolean }): Promise<Phone> {
  // No service worker: a cached shell would hide a rebuilt app.
  // ignoreHTTPSErrors: the app's certificate is self-signed (global-setup.ts).
  const context = await browser.newContext({ serviceWorkers: 'block', viewport: { width: 390, height: 844 }, ignoreHTTPSErrors: true });
  await context.addInitScript(cameraSeam);
  const page = await context.newPage();
  let cdp: CDPSession | undefined;
  if (o.passkeys) {
    cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
    });
  }
  return { context, page, cdp };
}

/**
 * The computer takes the phone's grant in, as a gateway does: it finds the grant at the Authority Server and answers with its signed
 * receipt. `afterMs`: how long the computer takes (the gateway's background check runs every 5 s).
 */
async function computerTakesIt(comp: Computer, token: string, mandateId: string, version: number, afterMs: number): Promise<void> {
  const row = await until(`the phone's grant of ${mandateId} v${version}`, async () => {
    const g = await http(stack.asUrl, 'GET', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, { token });
    return ((g.json?.grants ?? []) as Array<{ mandate_version: number; grant: MandateGrant }>).find((r) => r.mandate_version === version);
  }, 30_000);
  await new Promise((r) => setTimeout(r, afterMs));
  const now = await chainOf(stack, comp, comp.root.did);
  const receipt = buildReceipt({ mandate_id: mandateId, mandate_version: version, grant_hash: await grantHash(row.grant), key_id: comp.dev.record.key_id, chain_seq: now.head.seq, chain_head: now.head.hash, received_at: nowSec() });
  const rec = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(mandateId)}/receipts`, { token, body: { receipt, sig: await signObject(receipt, comp.dev.seed) } });
  expect([200, 201], show(rec)).toContain(rec.status);
}

/** After the touch: "Signing…" while the computer takes it in, then "Signed" by itself — never the not-received warning first
 *  (dev lane 2026-11-23: the warning came after 4 s, the person tried again, the gateway had it seconds later). */
async function signedWithoutAlarm(page: Page, take: Promise<void>): Promise<void> {
  // Record it if the warning appears at any moment, even for one frame (a check at the end could miss one that came and went).
  await page.evaluate(() => {
    const w = window as unknown as { __sawAlarm?: boolean };
    w.__sawAlarm = false;
    new MutationObserver(() => { if (document.querySelector('[data-testid="decision-unknown"]')) w.__sawAlarm = true; })
      .observe(document.body, { childList: true, subtree: true });
  });
  await expect(page.getByTestId('decision-working')).toBeVisible({ timeout: 15_000 });
  await take;
  await expect(page.getByTestId('decision-stamp')).toContainText('Signed', { timeout: 15_000 });
  expect(await page.evaluate(() => (window as unknown as { __sawAlarm?: boolean }).__sawAlarm), 'no "not received" warning while the computer takes it in').toBe(false);
}

/** Hold a QR in front of the phone's camera, then press the app's own "Scan the code". */
async function scan(page: Page, text: string): Promise<void> {
  await page.evaluate((m) => { (window as unknown as { __qr: boolean[][] }).__qr = m; }, qrMatrix(text));
  await page.getByRole('button', { name: 'Scan the code' }).click();
}

const READY = 'It is now one of your devices.';

/** The computer opens a mailbox and holds its QR in front of the phone. */
async function offerQr(comp: Awaited<ReturnType<typeof computerWithChain>>, o: { expiresAt?: number } = {}) {
  const pairing = await newPairing();
  const head = await headOf(comp.entries[0]);
  const expiresAt = o.expiresAt ?? nowSec() + 600;
  const qr = pairingQr(pairing, { asUrl: stack.asUrl, asKey: await asKeyHex(stack), expiresAt, admitter: { root_did: comp.root.did, head, key_id: comp.dev.record.key_id } });
  return { pairing, qr, expiresAt };
}

async function startJoin(phone: Phone, qr: string): Promise<void> {
  await phone.page.goto(stack.appUrl);
  // DEC-83 (gateway 1de2ba3): with phone-first setup off the app opens straight on "Add this phone to your account".
  await expect(phone.page.getByRole('heading', { name: 'Add this phone to your account' })).toBeVisible({ timeout: 20_000 });
  await scan(phone.page, qr);
}

/**
 * A phone in an account, the only way a phone gets one (DEC-83: phone-first setup is off): the test-computer, which holds the
 * chain and a check key, admits it through the app's own "Add this phone to your account" screens. Returns the phone, the account's
 * person (the computer's) and the root.
 */
async function joinedPhone(browser: Browser, phoneLabel: string, computerLabel: string, root?: Root): Promise<Phone & { person: Computer; root: Root }> {
  const comp = await computerWithChain(stack, db, computerLabel, root);
  const { pairing, qr } = await offerQr(comp);
  expect((await openMailbox(stack, comp, pairing)).status).toBe(201);
  const phone = await newPhone(browser, { passkeys: true });
  await startJoin(phone, qr);
  await phone.page.getByRole('button', { name: 'Add this phone to it' }).click({ timeout: 20_000 });
  await phone.page.locator('#join-name').fill(phoneLabel);
  await phone.page.getByRole('button', { name: 'Continue' }).click();
  const answered = await computerAnswersJoin(stack, comp, pairing);
  expect(answered.matches).toBe(true);
  await expect(phone.page.getByTestId('compare-code')).toHaveText(answered.code, { timeout: 20_000 });
  const res = await answered.confirm();
  expect(res.status, show(res)).toBe(201);
  await expect(phone.page.getByText(READY)).toBeVisible({ timeout: 20_000 });
  return { ...phone, person: comp, root: comp.root };
}

/** From the "app closed" screen to the signed-in app: the passkey's touch, then the Devices tab. */
async function openDevices(page: Page): Promise<void> {
  await page.goto(stack.appUrl);
  await page.getByRole('button', { name: 'Open with a touch' }).click();
  await page.getByRole('tab', { name: 'Devices', exact: true }).click();
  await expect(page.getByTestId('device-list')).toBeVisible({ timeout: 15_000 });
}

// The name only (the shared row's `row-name`), not its tag or its detail line.
const deviceNames = (page: Page) => page.getByTestId('device-row').getByTestId('row-name').allTextContents();

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// No phone-first setup (DEC-83)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test.describe('phone-first setup is off', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('a phone that is not paired opens straight on adding itself to an account', async ({ browser }) => {
    const phone = await newPhone(browser, { passkeys: true });
    await phone.page.goto(stack.appUrl);
    // DEC-83 (gateway 1de2ba3): no choice screen; the app opens straight on adding the phone.
    await expect(phone.page.getByRole('heading', { name: 'Add this phone to your account' })).toBeVisible({ timeout: 20_000 });
    await expect(phone.page.getByRole('button', { name: 'Set up my account on this phone' })).toHaveCount(0);
    await expect(phone.page.locator('#setup-code')).toHaveCount(0);
    // One way in: besides the day/dark switch (◑), the only button is "Scan the code".
    await expect(phone.page.getByRole('button', { name: 'Scan the code' })).toBeVisible();
    await expect(phone.page.getByRole('button')).toHaveCount(2);
    await expect(phone.page.getByRole('button', { name: '◑' })).toHaveCount(1);
    await phone.context.close();
  });

  test('an approve-app genesis posted directly is refused with PHONE_GENESIS_OFF', async ({ browser }) => {
    // Everything else about the request is genuine: a real passkey made in a real browser at the app's own address, the challenge
    // of this device key, a valid entry with the phone's check. Only the switch (DEC-83) stands in the way.
    const page0 = await newPhone(browser, { passkeys: true });
    await page0.page.goto(`${stack.appUrl}/__blank`);
    const person = await newPerson(stack, 'Phone first');
    const code = await enrolmentCode(stack, db, person);
    const root = await newRoot();
    const seed = randomBytes(32);
    const keyId = await keyIdOf(await ed25519PublicKey(seed));
    const made = await page0.page.evaluate(async (keyIdText) => {
      const enc = new TextEncoder();
      const label = enc.encode('suveren-passkey-register-v1');
      const id = enc.encode(keyIdText);
      const input = new Uint8Array(label.length + 1 + id.length);
      input.set(label, 0); input.set(id, label.length + 1);
      const challenge = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
      const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const cred = (await navigator.credentials.create({ publicKey: {
        rp: { id: 'localhost', name: 'Suveren' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'x', displayName: 'x' },
        challenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none', timeout: 60_000,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      } })) as PublicKeyCredential;
      const r = cred.response as AuthenticatorAttestationResponse;
      return {
        cred_id: b64u(cred.rawId), spki: Array.from(new Uint8Array(r.getPublicKey()!)),
        client_data_json: b64u(r.clientDataJSON), attestation_object: b64u(r.attestationObject),
      };
    }, keyId);
    const spki = Uint8Array.from(made.spki);
    const pub = b64uEncode(encodeCoseEc2(spki.slice(27, 59), spki.slice(59, 91)));
    const check = { type: 'webauthn' as const, rp_id: 'localhost', cred_id: made.cred_id, pub };
    const signPub = await ed25519PublicKey(seed);
    const record = await buildDeviceRecord({ sign_pub: b64uEncode(signPub), read_pub: b64uEncode(randomBytes(32)), kind: 'approve-app', label: 'Phone first', keystore: 'platform', check }, signPub);
    const entry = buildEntry({ root_did: root.did, seq: 0, prev: null, op: 'genesis', created_at: nowSec(), signer: 'root', device: record });
    const hash = await entryHash(entry);
    entry.sigs = [await signEntry(entry, 'root', root.privateSeed), await signEntry(entry, record.key_id, seed)];
    const proof = await page0.page.evaluate(async ({ credId, h }) => {
      const dec = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const challenge = Uint8Array.from(h.slice('sha256:'.length).match(/../g)!.map((x) => parseInt(x, 16)));
      const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const a = (await navigator.credentials.get({ publicKey: {
        challenge, rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: dec(credId) }], userVerification: 'required',
      } })) as PublicKeyCredential;
      const r = a.response as AuthenticatorAssertionResponse;
      return { authenticatorData: b64u(r.authenticatorData), clientDataJSON: b64u(r.clientDataJSON), signature: b64u(r.signature) };
    }, { credId: made.cred_id, h: hash });
    entry.checks = [{ by: record.key_id, check: proof }];

    const res = await http(stack.asUrl, 'POST', '/api/devices/chain', {
      body: { entry, enrolment_code: code, passkey: { cred_id: made.cred_id, pub, rp_id: 'localhost', client_data_json: made.client_data_json, attestation_object: made.attestation_object } },
    });
    expect(res.status, show(res)).toBe(409);
    expect(codeOf(res)).toBe('PHONE_GENESIS_OFF');
    expect((await db.query(`select root_did from users where id = $1`, [person.userId])).rows[0].root_did).toBeNull();
    await page0.context.close();
  });

  test('a computer-made genesis (gateway kind, no passkey) is still accepted', async () => {
    // The switch is about phones only: the computer's own start of an account is the path every phone now follows.
    const comp = await computerWithChain(stack, db, 'Office computer');
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// A computer with its check key admits a phone (shown_by: admitter)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test.describe('a computer admits the phone', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('a phone joining a chain made on a computer keeps the root DID; both show the same identity and comparison codes', async ({ browser }) => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    const { pairing, qr } = await offerQr(comp);
    expect((await openMailbox(stack, comp, pairing)).status).toBe(201);
    const phone = await newPhone(browser, { passkeys: true });
    await startJoin(phone, qr);

    // 1. Before any key is made, the phone shows whose account this is: the identity code of the root DID in the QR.
    await expect(phone.page.getByTestId('review-identity')).toHaveText(await identityCodeOf(comp.root.did), { timeout: 20_000 });
    await expect(phone.page.getByTestId('review-made')).toContainText('Office computer');
    expect(await deviceNames(phone.page)).toEqual(['Office computer']);
    await phone.page.getByRole('button', { name: 'Add this phone to it' }).click();
    await phone.page.locator('#join-name').fill('My iPhone');
    await phone.page.getByRole('button', { name: 'Continue' }).click();

    // 2. The computer answers; the phone and the computer show the same six digits.
    const answered = await computerAnswersJoin(stack, comp, pairing);
    expect(answered.matches, 'the open must match the commit').toBe(true);
    await expect(phone.page.getByTestId('compare-code')).toHaveText(answered.code, { timeout: 20_000 });
    // DEC-96: the phone says first that the next step is on the computer, and names it.
    await expect(phone.page.getByRole('heading', { name: 'Now on your computer' })).toBeVisible();
    await expect(phone.page.getByTestId('compare-next')).toHaveText('On Office computer, tap this number.');
    await phone.page.screenshot({ path: test.info().outputPath('dec96-1-phone-compare.png'), fullPage: true });

    // 3. The mailbox rows hold neither the secret nor the code.
    const row = (await mailboxRow(db, pairing))!;
    expect(row.columns.sort()).not.toContain('secret');
    for (const leaked of [b64uEncode(pairing.secret), b64uEncode(pairing.macKey), Buffer.from(pairing.secret).toString('hex'), Buffer.from(pairing.macKey).toString('hex'), `"${answered.code}"`]) {
      expect(row.text, 'the mailbox row must not hold the secret, the MAC key or the code').not.toContain(leaked);
    }

    // 4. Until the computer confirms, the phone is not a device: it is in no chain, so it has no session and reads nothing.
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(1);
    await expect(phone.page.getByRole('tab', { name: 'Devices', exact: true })).toHaveCount(0);

    // 5. The computer confirms with its check; the phone is added under the SAME root DID.
    const res = await answered.confirm();
    expect(res.status, show(res)).toBe(201);
    await expect(phone.page.getByText(READY)).toBeVisible({ timeout: 20_000 });
    const after = await verifiedChain(stack, comp, comp.root.did); // hap-core verifies the served chain from the genesis on
    expect(Object.keys(after.devices)).toHaveLength(2);
    expect((await db.query(`select did, root_did from users where id = $1`, [comp.userId])).rows[0]).toEqual({ did: comp.root.did, root_did: comp.root.did });
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(2);

    // 6. The phone's own screens: the same identity code, both devices.
    // DEC-96 (revises DEC-85): the join's done screen offers nothing about the recovery code, only Continue.
    await expect(phone.page.getByTestId('rotate-offer')).toHaveCount(0);
    await phone.page.screenshot({ path: test.info().outputPath('dec96-2-phone-joined.png'), fullPage: true });
    await phone.page.getByRole('button', { name: 'Continue' }).click();
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    await phone.page.getByRole('tab', { name: 'Devices', exact: true }).click();
    await expect(phone.page.getByTestId('identity-code')).toHaveText(await identityCodeOf(comp.root.did), { timeout: 15_000 });
    expect(await deviceNames(phone.page)).toEqual(['Office computer', 'My iPhone']);
    // DEC-96: replacing the recovery code is a plain section under Devices, with the one-sentence why.
    await expect(phone.page.getByTestId('rotate-section')).toContainText('Replace it if anyone could have seen your screen when you set up.');
    await phone.page.screenshot({ path: test.info().outputPath('dec96-3-phone-devices.png'), fullPage: true });
    await phone.context.close();
  });

  test('a second device with the name of another device is refused (joining)', async ({ browser }) => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    const { pairing, qr } = await offerQr(comp);
    expect((await openMailbox(stack, comp, pairing)).status).toBe(201);
    const phone = await newPhone(browser, { passkeys: true });
    await startJoin(phone, qr);
    await phone.page.getByRole('button', { name: 'Add this phone to it' }).click({ timeout: 20_000 });
    await phone.page.locator('#join-name').fill('office computer'); // same name, other case: still the same name
    await phone.page.getByRole('button', { name: 'Continue' }).click();
    await expect(phone.page.getByText('Another device in your account has this name. Use another name.')).toBeVisible();
    // Nothing was sent: no commit in the mailbox, no key made for a refused name.
    expect((await readBox(stack, pairing))?.messages.commit).toBeUndefined();
    await phone.context.close();
  });

  test('an expired QR is refused by the app, and an expired mailbox by the Authority Server', async ({ browser }) => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    // (a) The QR's own expiry: the app reads it and refuses before it touches the server.
    const old = await offerQr(comp, { expiresAt: nowSec() - 5 });
    const phone = await newPhone(browser, { passkeys: true });
    await startJoin(phone, old.qr);
    await expect(phone.page.getByText('This code has run out. Show a new one and scan it again.')).toBeVisible({ timeout: 20_000 });
    await expect(phone.page.getByTestId('review-identity')).toHaveCount(0);
    await phone.context.close();

    // (b) The mailbox's expiry: a mailbox that ran out answers like none, and takes no message.
    const short = await offerQr(comp);
    expect((await openMailbox(stack, comp, short.pairing, nowSec() + 2)).status).toBe(201);
    expect(await readBox(stack, short.pairing)).not.toBeNull();
    await new Promise((r) => setTimeout(r, 3500));
    expect(await readBox(stack, short.pairing)).toBeNull();
    const late = await http(stack.asUrl, 'POST', `/api/devices/pairings/${short.pairing.pairingId}/messages`, { body: { kind: 'commit', body: { c: `sha256:${'0'.repeat(64)}` }, mac: b64uEncode(randomBytes(32)) } });
    expect(late.status, show(late)).toBe(404);
    expect(codeOf(late)).toBe('NO_PAIRING');
  });

  test('a QR that the computer never opened is not open: the app says so', async ({ browser }) => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    const { qr } = await offerQr(comp); // no mailbox
    const phone = await newPhone(browser, { passkeys: true });
    await startJoin(phone, qr);
    await expect(phone.page.getByText('This code is not open any more. Show a new one and scan it again.')).toBeVisible({ timeout: 20_000 });
    await phone.context.close();
  });

  test('a passkey made at a look-alike origin is refused at the pairing, and the add with that pairing id fails', async ({ browser }) => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    const { pairing } = await offerQr(comp);
    expect((await openMailbox(stack, comp, pairing)).status).toBe(201);
    // A real passkey from a real browser on the same host and another port: genuine, but its clientDataJSON names the wrong origin.
    const other = await newPhone(browser, { passkeys: true });
    await other.page.goto(`${stack.lookalikeUrl}/__blank`);
    const seed = randomBytes(32);
    const signPub = await ed25519PublicKey(seed);
    const keyId = await keyIdOf(signPub);
    const made = await other.page.evaluate(async (keyIdText) => {
      const enc = new TextEncoder();
      const label = enc.encode('suveren-passkey-register-v1');
      const id = enc.encode(keyIdText);
      const input = new Uint8Array(label.length + 1 + id.length);
      input.set(label, 0); input.set(id, label.length + 1);
      const challenge = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
      const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const cred = (await navigator.credentials.create({ publicKey: {
        rp: { id: 'localhost', name: 'Suveren' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'x', displayName: 'x' },
        challenge, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'none', timeout: 60_000,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      } })) as PublicKeyCredential;
      const r = cred.response as AuthenticatorAttestationResponse;
      return { cred_id: b64u(cred.rawId), spki: Array.from(new Uint8Array(r.getPublicKey()!)), client_data_json: b64u(r.clientDataJSON), attestation_object: b64u(r.attestationObject) };
    }, keyId);
    const spki = Uint8Array.from(made.spki);
    const pub = b64uEncode(encodeCoseEc2(spki.slice(27, 59), spki.slice(59, 91)));
    const registration = { cred_id: made.cred_id, pub, rp_id: 'localhost', client_data_json: made.client_data_json, attestation_object: made.attestation_object };

    // 1. The registration is refused where the new phone stores it.
    const stored = await http(stack.asUrl, 'POST', `/api/devices/pairings/${pairing.pairingId}/passkey`, { body: registration });
    expect(stored.status, show(stored)).toBe(400);
    expect(['PASSKEY_INVALID', 'PASSKEY_REQUIRED']).toContain(codeOf(stored));

    // 2. The computer's `add` of that phone, naming the pairing, fails: no registration is held under it.
    const check = { type: 'webauthn' as const, rp_id: 'localhost', cred_id: made.cred_id, pub };
    const record = await buildDeviceRecord({ sign_pub: b64uEncode(signPub), read_pub: b64uEncode(randomBytes(32)), kind: 'approve-app', label: 'Lookalike phone', keystore: 'platform', check }, signPub);
    const head = await headOf(comp.entries[0]);
    const entry = buildEntry({ root_did: comp.root.did, seq: 1, prev: head.hash, op: 'add', created_at: nowSec(), signer: comp.dev.record.key_id, device: record });
    const hash = await entryHash(entry);
    const proof = await other.page.evaluate(async ({ credId, h }) => {
      const dec = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const challenge = Uint8Array.from(h.slice('sha256:'.length).match(/../g)!.map((x) => parseInt(x, 16)));
      const b64u = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      const a = (await navigator.credentials.get({ publicKey: { challenge, rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: dec(credId) }], userVerification: 'required' } })) as PublicKeyCredential;
      const r = a.response as AuthenticatorAssertionResponse;
      return { authenticatorData: b64u(r.authenticatorData), clientDataJSON: b64u(r.clientDataJSON), signature: b64u(r.signature) };
    }, { credId: made.cred_id, h: hash });
    entry.sigs = [await signEntry(entry, comp.dev.record.key_id, comp.dev.seed), await signEntry(entry, record.key_id, seed)];
    entry.checks = [{ by: record.key_id, check: proof }, { by: comp.dev.record.key_id, check: await checkOver(comp.dev.checkPriv, hash) }];
    const add = await http(stack.asUrl, 'POST', '/api/devices/chain', { token: comp.token, body: { entry, pairing_id: pairing.pairingId } });
    expect(add.status, show(add)).toBe(400);
    expect(codeOf(add)).toBe('PASSKEY_REQUIRED');
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(1);
    await other.context.close();
  });

  test('a device that was never confirmed can neither read nor approve', async () => {
    const comp = await computerWithChain(stack, db, 'Office computer');
    const unconfirmed = await newDevice('Never confirmed');
    const head = await headOf(comp.entries[0]);
    // It can ask for a challenge and sign it with its own key, but it is in no chain: the Authority Server opens no session.
    const ch = await http(stack.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: unconfirmed.record.key_id } });
    expect(ch.status, show(ch)).toBe(200);
    const signin = await http(stack.asUrl, 'POST', '/api/devices/session', { body: await signinBody(comp.root, unconfirmed, head, ch.json) });
    expect(signin.status, show(signin)).toBe(401);
    expect(codeOf(signin)).toBe('NOT_ACTIVE');
    // Without a session nothing is read or decided.
    const list = await http(stack.asUrl, 'GET', '/api/proposals?approver=me', { token: b64uEncode(randomBytes(24)) });
    expect(list.status, show(list)).toBe(401);
    const approve = await http(stack.asUrl, 'POST', '/api/proposals/does-not-matter/approve', { token: b64uEncode(randomBytes(24)), body: {} });
    expect(approve.status, show(approve)).toBe(401);
  });

  test('every add sends the email and the notice on every other device', async () => {
    test.skip(true, 'NOT BUILT on the Authority Server: lib/device-keys/device-notices.ts is a seam with no sink ("no notification channel exists yet", push is step 15, the email notices 20.1). Un-skip when the notice exists.');
  });

  test('the app offers to replace the recovery code first (D3); the old mandates still gate', async () => {
    test.skip(true, 'The offer and the replacement are covered by "stage D3: replace the recovery code" below. Still NOT covered: that the old mandates gate a tool call afterwards (needs a gateway with the phone-admit path in this suite).');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Stage D3 on the phone: remove a device, replace the recovery code (DEC-85, DEC-86)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** The row of a device in the app's list, and its Remove button. */
const removeButtonOf = (page: Page, label: string) => page.getByTestId('device-row').filter({ hasText: label }).getByTestId('device-remove');

/** The emails the Authority Server printed (its console mailer), as the global setup kept them. */
function mailLines(): string[] {
  const f = process.env.HAP_E2E_PHONE_MAIL_LOG;
  if (!f) throw new Error('the global setup keeps no mail log');
  return readFileSync(f, 'utf8').split('\n').filter(Boolean);
}

test.describe('stage D3: remove a device from the phone', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('the phone removes a computer: the list after the change before the touch, then a remove the phone signed AND checked', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Remover Phone', 'Old Mac');
    await openDevices(phone.page);
    await removeButtonOf(phone.page, 'Old Mac').click();
    await expect(phone.page.getByRole('heading', { name: 'Remove "Old Mac"?' })).toBeVisible();
    await expect(phone.page.getByText('Your devices after this:')).toBeVisible();
    await phone.page.getByTestId('remove-confirm').click();
    await expect(phone.page.getByText('Old Mac was removed.')).toBeVisible({ timeout: 20_000 });

    const state = await verifiedChain(stack, phone.person, phone.root.did);
    const entries = (await chainOf(stack, phone.person, phone.root.did)).entries;
    const rm = entries[entries.length - 1];
    const phoneKey = Object.values(state.devices).find((d) => d.label === 'Remover Phone')!.key_id;
    expect(rm).toMatchObject({ op: 'remove', target: phone.person.dev.record.key_id, signer: phoneKey });
    expect(rm.checks.map((c: { by: string }) => c.by)).toEqual([phoneKey]);
    expect(state.devices[phone.person.dev.record.key_id].removed_seq).toBe(rm.seq);
    // The removed computer can no longer sign in.
    const ch = await http(stack.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: phone.person.dev.record.key_id } });
    if (ch.status === 200) {
      const r = await http(stack.asUrl, 'POST', '/api/devices/session', { body: await signinBody(phone.root, phone.person.dev, await headOf(entries[entries.length - 1]), ch.json) });
      expect(r.status, show(r)).not.toBe(200);
    }
    await phone.context.close();
  });

  test('the phone removes itself (DEC-85): the same touch, an entry signed by the phone alone, and the app starts again with the reason', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Leaving Phone', 'Staying Mac');
    await openDevices(phone.page);
    await removeButtonOf(phone.page, 'Leaving Phone').click();
    await expect(phone.page.getByRole('heading', { name: 'Remove this phone?' })).toBeVisible();
    await phone.page.getByTestId('remove-confirm').click();
    await expect(phone.page.getByText('Continue', { exact: true })).toBeVisible({ timeout: 20_000 });
    await phone.page.getByText('Continue', { exact: true }).click();
    await expect(phone.page.getByTestId('join-notice')).toContainText('This phone was removed from your account.');

    const entries = (await chainOf(stack, phone.person, phone.root.did)).entries;
    const rm = entries[entries.length - 1];
    expect(rm.op).toBe('remove');
    expect(rm.signer).toBe(rm.target);
    expect(rm.checks).toEqual([]);
    await verifiedChain(stack, phone.person, phone.root.did);
    await phone.context.close();
  });
});

test.describe('stage D3: replace the recovery code on the phone', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('from Devices (DEC-96: no offer after joining); old code, new code once, touch, the email link confirmed on the phone, the new root in force', async ({ browser }) => {
    const { seed, code: oldCode } = await generateRecoveryCode();
    const root = await deriveRootKey(seed);
    const phone = await joinedPhone(browser, 'Rotating Phone', 'Code Mac', root);
    const { page } = phone;
    // DEC-96 (revises DEC-85): the join's done screen offers nothing; replacing is a plain section under Devices.
    await expect(page.getByTestId('rotate-offer')).toHaveCount(0);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Open with a touch' }).click();
    await page.getByRole('tab', { name: 'Devices', exact: true }).click();
    await page.getByTestId('rotate-section').getByRole('button', { name: 'Make a new code' }).click();

    await page.getByTestId('old-code').fill(oldCode);
    await page.getByRole('button', { name: 'Continue' }).click();
    const newCode = (await page.getByTestId('new-code').textContent({ timeout: 20_000 }))!.trim();
    expect(newCode).not.toBe(oldCode);
    await page.getByTestId('new-code-again').fill(newCode);
    const before = mailLines().length;
    await page.getByTestId('rotate-confirm').click();
    const confirmCode = (await page.getByTestId('rotate-confirm-code').textContent({ timeout: 20_000 }))!.trim();
    expect(confirmCode).toMatch(/^\d{6}$/);
    // Nothing is in the chain before the email link is confirmed.
    expect((await chainOf(stack, phone.person, root.did)).entries).toHaveLength(2);

    // The email, as the phone's mail app would show it; the codes are in no email.
    const link = await until('the recovery email', async () => {
      const hit = mailLines().slice(before).find((l) => l.includes('/recover/link?token='));
      return hit ? /https?:\/\/\S+\/recover\/link\?token=[A-Za-z0-9_-]+/.exec(hit)![0] : undefined;
    }, 20_000);
    expect(mailLines().slice(before).join('\n')).toContain('open this link on your phone');
    expect(mailLines().join('\n')).not.toContain(oldCode);
    expect(mailLines().join('\n')).not.toContain(newCode);

    // The link opens in the phone's browser (another page of the same browser): Continue, then the confirm page shows the same six digits.
    const mail = await phone.context.newPage();
    await mail.goto(link.replace(/^https?:\/\/[^/]+/, stack.asUrl));
    await mail.getByRole('button', { name: 'Continue' }).click();
    await expect(mail.locator('.code')).toHaveText(confirmCode);
    await mail.getByRole('button', { name: 'Confirm the recovery' }).click();
    await expect(mail.getByRole('heading', { name: 'Done' })).toBeVisible();

    await expect(page.getByText('Done. Your new recovery code works. The old one does not.')).toBeVisible({ timeout: 20_000 });
    const state = await verifiedChain(stack, phone.person, root.did);
    expect(state.root_pub).toBe(b64uEncode((await rootKeyFromRecoveryCode(newCode)).publicKey));
    const rot = (await chainOf(stack, phone.person, root.did)).entries[2];
    expect(rot.op).toBe('rotate-root');
    expect(rot.sigs.map((x: { by: string }) => x.by)).toEqual(['root', Object.values(state.devices).find((d) => d.label === 'Rotating Phone')!.key_id]);
    await phone.context.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// The phone admits a gateway (shown_by: joiner)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// Stage D3: a computer's change to a connector login, confirmed on the phone (plan 7 phone path, 20.4)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test.describe('stage D3: confirm a computer\'s change to a connector login on the phone', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  /** The computer (played here, without using its check key: the phone path) sends a sealed, signed request to the phone. */
  async function sendChange(phone: Awaited<ReturnType<typeof joinedPhone>>, phoneLabel: string, o: { kind?: 'replace' | 'remove' } = {}) {
    const chain = await verifiedChain(stack, phone.person, phone.root.did);
    const ph = Object.values(chain.devices).find((d) => d.label === phoneLabel && d.removed_seq === null)!;
    const kind = o.kind ?? 'replace';
    const sent = await buildChangeRequest({
      computer: phone.person.dev, chain, phones: { [ph.key_id]: ph.read_pub }, kind, name: 'gmail', connector: 'Gmail', now: nowSec(),
      fields: kind === 'remove' ? [] : [{ key: 'clientId', label: 'Client ID', secret: false, old: 'old.apps.example', new: 'new.apps.example' }, { key: 'clientSecret', label: 'Client secret', secret: true }],
      change: { route: 'credentials', op: kind === 'remove' ? 'delete' : 'put-merge', fields: kind === 'remove' ? undefined : { clientId: 'new.apps.example', clientSecret: 'new-secret' } },
    });
    const r = await http(stack.asUrl, 'POST', '/api/devices/confirmations', { token: phone.person.token, body: sent.body });
    expect(r.status, show(r)).toBe(201);
    return { sent, chain, phoneKeyId: ph.key_id };
  }

  async function openRequests(page: Page): Promise<void> {
    await page.goto(stack.appUrl);
    await page.getByRole('button', { name: 'Open with a touch' }).click();
  }

  async function answerOf(phone: Awaited<ReturnType<typeof joinedPhone>>, requestId: string) {
    return until('the phone\'s answer at the Authority Server', async () => {
      const r = await http(stack.asUrl, 'GET', `/api/devices/confirmations/${requestId}`, { token: phone.person.token });
      return r.status === 200 && r.json.status === 'answered' ? r.json.answer : undefined;
    }, 20_000);
  }

  test('the request opens full screen by itself; old value crossed out, the secret without a value; the touch; the computer verifies an allow against its own chain', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Confirm Phone', 'Home Mac');
    const { sent } = await sendChange(phone, 'Confirm Phone');
    await openRequests(phone.page);
    const card = phone.page.getByTestId('change-card');
    await expect(card).toBeVisible({ timeout: 20_000 });
    await expect(card.getByTestId('change-asked-by')).toHaveText('Asked by Home Mac.');
    await expect(card.getByTestId('change-sentence')).toContainText('Replace the login of "Gmail".');
    await expect(card.locator('.mc-old')).toHaveText('old.apps.example');
    await expect(card.locator('.mc-old')).toHaveCSS('text-decoration-line', 'line-through');
    await expect(card.locator('.mc-new').first()).toHaveText('new.apps.example');
    await expect(card).not.toContainText('new-secret');
    // the button is visible without scrolling (the gateway's pinned footer)
    await expect(card.getByTestId('change-confirm')).toBeInViewport();
    await card.getByTestId('change-confirm').click();
    await expect(card.getByTestId('change-stamp')).toContainText('Confirmed', { timeout: 20_000 });

    const answer = await answerOf(phone, sent.requestId);
    const chain = await verifiedChain(stack, phone.person, phone.root.did);
    expect(await verifyPhoneAnswer(answer, { chain, rootDid: phone.root.did, requestId: sent.requestId, changeHash: sent.changeHash, computerKeyId: phone.person.dev.record.key_id, now: nowSec() })).toBe('allow');
    // A second answer is refused: the first one stands.
    const again = await http(stack.asUrl, 'GET', '/api/devices/confirmations', { token: phone.person.token });
    expect(again.status).toBe(403); // a computer session never lists the phone's requests
    await phone.context.close();
  });

  test('"Do not allow": a signed deny without a touch; the phone says the computer keeps the login', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Deny Phone', 'Office Mac');
    const { sent } = await sendChange(phone, 'Deny Phone', { kind: 'remove' });
    await openRequests(phone.page);
    const card = phone.page.getByTestId('change-card');
    await expect(card.getByTestId('change-sentence')).toContainText('Remove the login of "Gmail".', { timeout: 20_000 });
    await card.getByTestId('change-deny').click();
    await expect(card.getByTestId('change-denied')).toHaveText('Not allowed. Office Mac keeps the login of "Gmail".', { timeout: 20_000 });
    await expect(card.getByTestId('change-dismiss')).toBeVisible();
    const answer = await answerOf(phone, sent.requestId);
    expect(answer.check).toBeUndefined();
    const chain = await verifiedChain(stack, phone.person, phone.root.did);
    expect(await verifyPhoneAnswer(answer, { chain, rootDid: phone.root.did, requestId: sent.requestId, changeHash: sent.changeHash, computerKeyId: phone.person.dev.record.key_id, now: nowSec() })).toBe('deny');
    await phone.context.close();
  });

  test('a request whose sealed content the server changed is never shown; the server refuses an unsigned request and a wrap for a computer', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Tamper Phone', 'Lab Mac');
    const { sent, chain, phoneKeyId } = await sendChange(phone, 'Tamper Phone');
    const ct = Buffer.from(sent.body.ciphertext as string, 'base64url');
    ct[ct.length - 5] ^= 1;
    await db.query('update change_confirmations set ciphertext = $1 where request_id = $2', [ct.toString('base64url'), sent.requestId]);
    await openRequests(phone.page);
    await expect(phone.page.getByTestId('list-empty')).toBeVisible({ timeout: 20_000 });
    await expect(phone.page.getByTestId('change-card')).toHaveCount(0);

    // Signed by another key while naming this computer: refused.
    const other = await newDevice('Not this computer');
    const forged = await buildChangeRequest({ computer: other, chain, phones: { [phoneKeyId]: chain.devices[phoneKeyId].read_pub }, kind: 'remove', name: 'gmail', connector: 'Gmail', fields: [], change: {}, now: nowSec() });
    (forged.body.envelope as Record<string, unknown>).gateway_key_id = phone.person.dev.record.key_id;
    const r1 = await http(stack.asUrl, 'POST', '/api/devices/confirmations', { token: phone.person.token, body: forged.body });
    expect(codeOf(r1), show(r1)).toBe('BAD_SIGNATURE');
    // A wrap for the computer itself (not a phone): refused.
    const toComputer = await buildChangeRequest({ computer: phone.person.dev, chain, phones: { [phone.person.dev.record.key_id]: chain.devices[phoneKeyId].read_pub }, kind: 'remove', name: 'gmail', connector: 'Gmail', fields: [], change: {}, now: nowSec() });
    const r2 = await http(stack.asUrl, 'POST', '/api/devices/confirmations', { token: phone.person.token, body: toComputer.body });
    expect(codeOf(r2), show(r2)).toBe('NOT_YOUR_PHONE');
    await phone.context.close();
  });
});

test.describe('the phone admits a computer', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);
  test.describe.configure({ mode: 'serial' });

  let phone: Awaited<ReturnType<typeof joinedPhone>>;
  const PHONE_LABEL = 'Admitting phone';
  test.beforeAll(async ({ browser }) => { phone = await joinedPhone(browser, PHONE_LABEL, 'Admit host computer'); });
  test.afterAll(async () => { await phone?.context.close(); });
  // A person may hold five open pairings; every case here opens one.
  test.afterEach(async () => { await clearMailboxes(db, phone.person.userId); });

  async function startAdmit(qr: string): Promise<void> {
    await openDevices(phone.page);
    await phone.page.getByRole('button', { name: 'Add a computer' }).click();
    await scan(phone.page, qr);
  }
  const deviceCount = async () => (await chainOf(stack, phone.person, phone.root.did)).entries.length;

  test('the app admits a gateway; both show the same comparison code; the gateway is in the chain', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, 'New office computer');
    await startAdmit(joiner.qr);
    const shown = await joiner.run();
    expect(shown.commitStatus).toBe(201);
    await expect(phone.page.getByRole('heading', { name: 'Add "New office computer"?' })).toBeVisible({ timeout: 20_000 });
    // The computer's code is one of the three the phone offers.
    const choices = await phone.page.getByTestId('code-choice').allTextContents();
    expect(choices).toHaveLength(3);
    expect(choices).toContain(shown.code);
    // DEC-96: the phone says the computer is ready, above the three numbers.
    await expect(phone.page.getByTestId('other-ready')).toHaveText('Your computer is ready. Tap the number it shows.');
    await phone.page.screenshot({ path: test.info().outputPath('dec96-4-phone-admit-choose.png'), fullPage: true });

    // The mailbox rows hold neither the secret nor the code.
    const row = (await mailboxRow(db, joiner.pairing))!;
    for (const leaked of [b64uEncode(joiner.pairing.secret), b64uEncode(joiner.pairing.macKey), Buffer.from(joiner.pairing.secret).toString('hex'), `"${shown.code}"`]) {
      expect(row.text).not.toContain(leaked);
    }
    // Nothing is in the chain until the person taps the code.
    expect(await deviceCount()).toBe(before);

    await phone.page.getByTestId('code-choice').filter({ hasText: shown.code }).click();
    await expect(phone.page.getByText('"New office computer" was added')).toBeVisible({ timeout: 20_000 });
    expect(await deviceCount()).toBe(before + 1);
    const done = await waitForMessage(stack, joiner.pairing, 'done');
    expect(done.body.entry_hash).toBe(await entryHash((await chainOf(stack, phone.person, phone.root.did)).entries.at(-1)!));
    expect(await deviceNames(phone.page)).toContain('New office computer');
  });

  test('a wrong tap ends the pairing and adds nothing', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, 'Computer wrong tap');
    await startAdmit(joiner.qr);
    const shown = await joiner.run();
    await expect(phone.page.getByTestId('code-choice').first()).toBeVisible({ timeout: 20_000 });
    const wrong = (await phone.page.getByTestId('code-choice').allTextContents()).find((c) => c !== shown.code)!;
    await phone.page.getByTestId('code-choice').filter({ hasText: wrong }).click();
    await expect(phone.page.getByText('That was not the code. Nothing was added.')).toBeVisible();
    expect(await deviceCount()).toBe(before);
    expect((await waitForMessage(stack, joiner.pairing, 'done')).body).toEqual({ refused: 'CODE_MISMATCH' });
  });

  test('a commit with a wrong MAC is refused by the phone', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, 'Computer wrong mac');
    await startAdmit(joiner.qr);
    await joiner.run({ wrongMacCommit: true }); // the Authority Server cannot tell: it holds no MAC key
    await expect(phone.page.getByText('Something is wrong with this pairing. Nothing was added. Start again.')).toBeVisible({ timeout: 20_000 });
    expect(await deviceCount()).toBe(before);
    expect((await waitForMessage(stack, joiner.pairing, 'done')).body).toEqual({ refused: 'BAD_MESSAGE' });
  });

  test('a second commit is refused by the Authority Server; the first stands', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, 'Computer second commit');
    await startAdmit(joiner.qr);
    const shown = await joiner.run({ secondCommit: true });
    expect(shown.commitStatus).toBe(201);
    expect(shown.secondCommitStatus).toBe(409);
    const box = await readBox(stack, joiner.pairing);
    expect(box?.raw.filter((m) => (m as { kind: string }).kind === 'commit')).toHaveLength(1);
    // The pairing goes on with the first commit and completes.
    await expect(phone.page.getByTestId('code-choice').first()).toBeVisible({ timeout: 20_000 });
    await phone.page.getByTestId('code-choice').filter({ hasText: shown.code }).click();
    await expect(phone.page.getByText('"Computer second commit" was added')).toBeVisible({ timeout: 20_000 });
    expect(await deviceCount()).toBe(before + 1);
  });

  test('an open that does not match its commit is refused by the phone', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, 'Computer swapped entry');
    await startAdmit(joiner.qr);
    await joiner.run({ openOtherEntry: true });
    await expect(phone.page.getByText('Something is wrong with this pairing. Nothing was added. Start again.')).toBeVisible({ timeout: 20_000 });
    await expect(phone.page.getByTestId('code-choice')).toHaveCount(0);
    expect(await deviceCount()).toBe(before);
    expect((await waitForMessage(stack, joiner.pairing, 'done')).body).toEqual({ refused: 'COMMIT_MISMATCH' });
  });

  test('a second device with the name of another device is refused (admitting)', async () => {
    const before = await deviceCount();
    const joiner = await newJoiner(stack, PHONE_LABEL.toUpperCase()); // the phone's own name, other case
    await startAdmit(joiner.qr);
    await joiner.run();
    await expect(phone.page.getByText('Another device in your account has this name. Use another name.')).toBeVisible({ timeout: 20_000 });
    expect(await deviceCount()).toBe(before);
  });

  test('an expired QR is refused by the phone before it opens a mailbox', async () => {
    const before = await deviceCount();
    const pairing = await newPairing();
    const qr = pairingQr(pairing, { asUrl: stack.asUrl, asKey: await asKeyHex(stack), expiresAt: nowSec() - 5 });
    await startAdmit(qr);
    await expect(phone.page.getByText('This code has run out. Show a new one and scan it again.')).toBeVisible({ timeout: 20_000 });
    expect(await readBox(stack, pairing)).toBeNull(); // no mailbox was made
    expect(await deviceCount()).toBe(before);
  });

  test('a device that never completed the pairing cannot sign in', async () => {
    const joiner = await newJoiner(stack, 'Computer left unconfirmed');
    await startAdmit(joiner.qr);
    await joiner.run();
    await expect(phone.page.getByTestId('code-choice').first()).toBeVisible({ timeout: 20_000 });
    // The computer's key is in an `open` message, not in the chain: it gets no session.
    const head = (await chainOf(stack, phone.person, phone.root.did)).head;
    const ch = await http(stack.asUrl, 'POST', '/api/devices/challenge', { body: { key_id: joiner.device.record.key_id } });
    const res = await http(stack.asUrl, 'POST', '/api/devices/session', { body: await signinBody(phone.root, joiner.device, head, ch.json) });
    expect(res.status, show(res)).toBe(401);
    expect(codeOf(res)).toBe('NOT_ACTIVE');
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// WebKit: what is possible
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test.describe('stage D3: give a mandate on the phone (plan 4.4 Transport, DEC-86)', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('a computer prepares a give for the phone; the phone shows exactly that and gives it with one touch; the Authority Server stores a grant that verifies with exactly those members; "Signed" once the computer\'s receipt verifies', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Giving Phone', 'Office Mac');
    const comp = phone.person;
    // The phone joined: the chain moved; the computer signs in again at the new head (as a gateway does).
    const chain = await chainOf(stack, comp, comp.root.did);
    const state = await verifiedChain(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const phoneKey = Object.values(state.devices).find((d) => d.label === 'Giving Phone')!.key_id;

    // What the computer prepares (the gateway's `sendToPhone`): the mandate the AS will sign, its plaintext, sealed to every device.
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const scope = { currency: 'EUR' };
    const intent = 'Follow up quotes that wait two days.';
    const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
    const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
    const mandateId = newMandateId();
    const authorizationId = `authz_${randomUUID()}`;
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(bounds as never, profile),
      scope_hash: computeScopeHash(scope as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash(intent) }, commitment_mode: 'review',
      issued_at: nowSec(), expires_at: nowSec() + 3600,
    } as unknown as MandatePayload;
    const place = { authorization_id: authorizationId, group_id: groupId, replaces: null, chain_dids: [comp.root.did] };
    const content = { v: 2, mandate_id: mandateId, mandate_version: 1, scope, intent, give: { op: 'grant', profile, bounds, payload, place, title: 'Quotes', prepared_at: nowSec() } };
    const readers = Object.values(state.devices).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    const prep = await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: mandateId, mandate_version: 1, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } });
    expect(prep.status, show(prep)).toBe(201);

    // The phone: opened with a touch, the give opens full screen by itself (DEC-86), with what the computer prepared.
    await phone.page.goto(stack.appUrl);
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    const card = phone.page.getByTestId('give-card');
    await expect(card).toBeVisible({ timeout: 20_000 });
    await expect(card.getByTestId('give-title')).toHaveText('Give the mandate for Quotes');
    await expect(card.getByTestId('give-from')).toContainText('Prepared on Office Mac');
    await expect(card.getByTestId('give-intent')).toHaveText(intent);
    await expect(card.getByTestId('mandate-summary')).toBeVisible();
    await card.getByTestId('btn-give').click();
    // The computer takes it in after 6 s (its background check runs every 5 s): the phone keeps "Signing…" and then shows "Signed".
    await signedWithoutAlarm(phone.page, computerTakesIt(comp, token, mandateId, 1, 6_000));
    // "Signed" times away after a moment (the panel's rule after a decision): look at it while it is on screen.
    await expectStampCentred(phone.page.getByTestId('decision-stamp'), 'phone app, give signed');
    await phone.page.screenshot({ path: test.info().outputPath('g1-phone-signed-after-computer.png'), fullPage: true });

    // At the Authority Server: one grant, by the phone, WITH its check, whose members are exactly the ones rebuilt from the mandate.
    const grants = await http(stack.asUrl, 'GET', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, { token });
    expect(grants.status, show(grants)).toBe(200);
    const rows = grants.json.grants as Array<{ op: string; grant: MandateGrant; sig: string; check: unknown }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].op).toBe('grant');
    expect(rows[0].grant.key_id).toBe(phoneKey);
    expect(rows[0].check).toBeTruthy();
    const members = grantMembersOf(payload, { authorizationId, groupId, replaces: null, chainDids: [comp.root.did] });
    await verifyGrant({ grant: rows[0].grant, sig: rows[0].sig, check: rows[0].check as never }, { chain: await verifiedChain(stack, comp, comp.root.did), mandateFields: members, expect: { ops: ['grant'], mandate_id: mandateId, mandate_version: 1 } });

    await phone.context.close();
  });

  test('an open app shows what a push announces at once (dev lane 2026-11-23: the card came ~5 s after the notice), not at its next refresh', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Open Phone', 'Office Mac');
    const comp = phone.person;
    await phone.page.goto(stack.appUrl);
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    await expect(phone.page.getByRole('tab', { name: 'Requests' }).or(phone.page.getByRole('button', { name: 'Requests', exact: true })).first()).toBeVisible({ timeout: 20_000 });

    // The computer prepares a give while the app is open (the gateway's `sendToPhone`).
    const chain = await chainOf(stack, comp, comp.root.did);
    const state = await verifiedChain(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const scope = { currency: 'EUR' };
    const intent = 'Follow up quotes that wait two days.';
    const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
    const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
    const mandateId = newMandateId();
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(bounds as never, profile),
      scope_hash: computeScopeHash(scope as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash(intent) }, commitment_mode: 'review',
      issued_at: nowSec(), expires_at: nowSec() + 3600,
    } as unknown as MandatePayload;
    const content = { v: 2, mandate_id: mandateId, mandate_version: 1, scope, intent, give: { op: 'grant', profile, bounds, payload, place: { authorization_id: `authz_${randomUUID()}`, group_id: groupId, replaces: null, chain_dids: [comp.root.did] }, title: 'Quotes', prepared_at: nowSec() } };
    const readers = Object.values(state.devices).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    const prep = await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: mandateId, mandate_version: 1, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } });
    expect(prep.status, show(prep)).toBe(201);

    // Without a push the open app does not see it yet (its own refresh is every 30 s): the push is what makes it appear.
    await phone.page.waitForTimeout(1_500);
    await expect(phone.page.getByTestId('give-card')).toHaveCount(0);

    // The push. Seam: this browser blocks service workers (a cached shell would hide a rebuilt app, newPhone above), so the message
    // the app's service worker sends to open windows on a push (public/sw.js `tellOpenWindows`, covered by apps/approve
    // sw-push.test.ts) is dispatched on the app's service-worker container here; what the app does with it is its own code.
    const t0 = Date.now();
    await phone.page.evaluate(() => navigator.serviceWorker.dispatchEvent(new MessageEvent('message', { data: { t: 'pushed' } })));
    await expect(phone.page.getByTestId('give-card')).toBeVisible({ timeout: 1_000 });
    const ms = Date.now() - t0;
    test.info().annotations.push({ type: 'push-to-card-ms', description: String(ms) });
    await phone.page.screenshot({ path: test.info().outputPath('p1-card-after-push.png'), fullPage: true });
    expect(ms, 'the card is on screen within a second of the push').toBeLessThanOrEqual(1_000);
    await phone.context.close();
  });

  test('opened with a touch over a slow network (150 ms per request, as a phone over Tailscale): the waiting give is on screen within 2.5 s', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Slow Phone', 'Office Mac');
    const comp = phone.person;
    const chain = await chainOf(stack, comp, comp.root.did);
    const state = await verifiedChain(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const scope = { currency: 'EUR' };
    const intent = 'Follow up quotes that wait two days.';
    const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
    const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
    const mandateId = newMandateId();
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(bounds as never, profile),
      scope_hash: computeScopeHash(scope as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash(intent) }, commitment_mode: 'review',
      issued_at: nowSec(), expires_at: nowSec() + 3600,
    } as unknown as MandatePayload;
    const content = { v: 2, mandate_id: mandateId, mandate_version: 1, scope, intent, give: { op: 'grant', profile, bounds, payload, place: { authorization_id: `authz_${randomUUID()}`, group_id: groupId, replaces: null, chain_dids: [comp.root.did] }, title: 'Quotes', prepared_at: nowSec() } };
    const readers = Object.values(state.devices).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    expect((await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: mandateId, mandate_version: 1, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } })).status).toBe(201);

    // Every request to the Authority Server takes 150 ms more (a phone over Tailscale), and is counted.
    let requests = 0;
    await phone.page.route(`${stack.asUrl}/**`, async (route) => { requests++; await new Promise((r) => setTimeout(r, 150)); await route.fallback(); });
    await phone.page.goto(stack.appUrl);
    const openBtn = phone.page.getByRole('button', { name: 'Open with a touch' });
    await expect(openBtn).toBeVisible({ timeout: 20_000 });
    requests = 0;
    const t0 = Date.now();
    await openBtn.click();
    await expect(phone.page.getByTestId('give-card')).toBeVisible({ timeout: 20_000 });
    const ms = Date.now() - t0;
    test.info().annotations.push({ type: 'open-to-card-ms', description: `${ms} ms, ${requests} requests` });
    console.log(`[PHONE-TIMING] open with a touch -> give on screen: ${ms} ms, ${requests} requests at +150 ms`);
    await phone.page.screenshot({ path: test.info().outputPath('t1-slow-open-card.png'), fullPage: true });
    expect(ms, `on screen after ${ms} ms (${requests} requests)`).toBeLessThanOrEqual(2_500);
    await phone.context.close();
  });

  test('a give whose limits differ from what the mandate names is not offered: no button, nothing signed', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Careful Phone', 'Other Mac');
    const comp = phone.person;
    const chain = await chainOf(stack, comp, comp.root.did);
    const state = await verifiedChain(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const mandateId = newMandateId();
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(bounds as never, profile),
      scope_hash: computeScopeHash({ currency: 'EUR' } as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash('x') }, commitment_mode: 'review', issued_at: nowSec(), expires_at: nowSec() + 3600,
    };
    // shown: 99,999 per offer; hashed: 1,000
    const content = { v: 2, mandate_id: mandateId, mandate_version: 1, scope: { currency: 'EUR' }, intent: 'x', give: { op: 'grant', profile, bounds: { ...bounds, value_max: 99999 }, payload, place: { authorization_id: `authz_${randomUUID()}`, group_id: 'g', replaces: null, chain_dids: [comp.root.did] }, title: 'Lie', prepared_at: nowSec() } };
    const readers = Object.values(state.devices).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    expect((await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: mandateId, mandate_version: 1, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } })).status).toBe(201);
    await phone.page.goto(stack.appUrl);
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    await expect(phone.page.getByRole('tab', { name: 'Requests' }).or(phone.page.getByRole('button', { name: 'Requests', exact: true })).first()).toBeVisible({ timeout: 20_000 });
    await phone.page.waitForTimeout(3000);
    await expect(phone.page.getByTestId('give-card')).toHaveCount(0);
    await expect(phone.page.getByTestId('give-row')).toHaveCount(0);
    const grants = await http(stack.asUrl, 'GET', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, { token });
    expect(grants.json.grants ?? []).toHaveLength(0);
    await phone.context.close();
  });
});

test.describe('stage D3: change a mandate on the phone (mockup B1, DEC-90)', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  /** A computer of the person prepares a give (or a change) for the phone, sealed to every device: the gateway's `sendToPhone`. */
  async function seal(comp: any, token: string, state: any, content: Record<string, unknown>, version: number) {
    const readers = Object.values(state.devices as Record<string, any>).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    const prep = await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: content.mandate_id, mandate_version: version, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } });
    expect(prep.status, show(prep)).toBe(201);
  }

  async function givenV1(browser: any, label: string, comp_label: string) {
    const phone = await joinedPhone(browser, label, comp_label);
    const comp = phone.person;
    const chain = await chainOf(stack, comp, comp.root.did);
    const state = await verifiedChain(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const scope = { currency: 'EUR' };
    const intent = 'Follow up quotes that wait two days.';
    const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
    const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
    const mandateId = newMandateId();
    const authz1 = `authz_${randomUUID()}`;
    const mk = (b: Record<string, unknown>, expires: number) => ({
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(b as never, profile),
      scope_hash: computeScopeHash(scope as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash(intent) }, commitment_mode: 'review',
      issued_at: nowSec(), expires_at: expires,
    } as unknown as MandatePayload);
    const p1 = mk(bounds, nowSec() + 3600);
    await seal(comp, token, state, { v: 2, mandate_id: mandateId, mandate_version: 1, scope, intent, give: { op: 'grant', profile, bounds, payload: p1, place: { authorization_id: authz1, group_id: groupId, replaces: null, chain_dids: [comp.root.did] }, title: 'Quotes', prepared_at: nowSec() } }, 1);
    await phone.page.goto(stack.appUrl);
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    const card = phone.page.getByTestId('give-card');
    await expect(card.getByTestId('give-title')).toHaveText('Give the mandate for Quotes', { timeout: 20_000 });
    await card.getByTestId('btn-give').click();
    await signedWithoutAlarm(phone.page, computerTakesIt(comp, token, mandateId, 1, 0));
    return { phone, comp, token, state, profile, bounds, scope, intent, groupId, mandateId, authz1, mk, p1 };
  }

  test('the phone shows the change with the old value crossed out, checked against version 1\'s grant, and grants version 2 with one touch', async ({ browser }) => {
    const v = await givenV1(browser, 'Changing Phone', 'Office Mac');
    const bounds2 = { ...v.bounds, value_max: 3000 };
    const p2 = v.mk(bounds2, (v.p1 as any).expires_at);
    const authz2 = `authz_${randomUUID()}`;
    const previous = { profile: v.profile, bounds: v.bounds, scope: v.scope, intent: v.intent, expires_at: (v.p1 as any).expires_at, mandate_version: 1 };
    await seal(v.comp, v.token, v.state, { v: 2, mandate_id: v.mandateId, mandate_version: 2, scope: v.scope, intent: v.intent, give: { op: 'change', profile: v.profile, bounds: bounds2, payload: p2, place: { authorization_id: authz2, group_id: v.groupId, replaces: v.authz1, chain_dids: [v.comp.root.did] }, title: 'Quotes', prepared_at: nowSec(), previous } }, 2);

    await v.phone.page.reload();
    await v.phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    const card = v.phone.page.getByTestId('give-card');
    await expect(card.getByTestId('give-title')).toHaveText('Change the mandate for Quotes', { timeout: 20_000 });
    // the gateway's change rows: the old value crossed out, then the new one
    const row = card.locator('[data-testid="change-row"]').filter({ hasText: '3' }).first();
    await expect(row).toBeVisible();
    const old = row.locator('.mc-old');
    await expect(old).toBeVisible();
    expect(await old.evaluate((el) => getComputedStyle(el).textDecorationLine)).toContain('line-through');
    // the differences stand apart from the line above them, as on the gateway (dev lane screenshot: glued)
    expect(await card.getByTestId('change-diff').evaluate((el) => parseFloat(getComputedStyle(el).marginTop))).toBeGreaterThan(0);
    await v.phone.page.screenshot({ path: test.info().outputPath('g2-phone-change-card.png'), fullPage: true });
    await card.getByTestId('btn-give').click();
    await signedWithoutAlarm(v.phone.page, computerTakesIt(v.comp, v.token, v.mandateId, 2, 3_000));

    const grants = await http(stack.asUrl, 'GET', `/api/mandates/${encodeURIComponent(v.mandateId)}/grants`, { token: v.token });
    const rows = grants.json.grants as Array<{ op: string; mandate_version: number; grant: MandateGrant; sig: string; check: unknown }>;
    const second = rows.find((r) => r.mandate_version === 2)!;
    expect(second.op).toBe('change');
    expect(second.check).toBeTruthy();
    const members = grantMembersOf(p2, { authorizationId: authz2, groupId: v.groupId, replaces: v.authz1, chainDids: [v.comp.root.did] });
    await verifyGrant({ grant: second.grant, sig: second.sig, check: second.check as never }, { chain: await verifiedChain(stack, v.comp, v.comp.root.did), mandateFields: members, expect: { ops: ['change'], mandate_id: v.mandateId, mandate_version: 2 } });
    await v.phone.context.close();
  });

  test('a change whose "old" values differ from what version 1 granted is not shown: no card, nothing signed', async ({ browser }) => {
    const v = await givenV1(browser, 'Wary Phone', 'Other Mac');
    const bounds2 = { ...v.bounds, value_max: 3000 };
    const p2 = v.mk(bounds2, (v.p1 as any).expires_at);
    // shown as "before": 50 per offer; version 1 granted 1,000
    const previous = { profile: v.profile, bounds: { ...v.bounds, value_max: 50 }, scope: v.scope, intent: v.intent, expires_at: (v.p1 as any).expires_at, mandate_version: 1 };
    await seal(v.comp, v.token, v.state, { v: 2, mandate_id: v.mandateId, mandate_version: 2, scope: v.scope, intent: v.intent, give: { op: 'change', profile: v.profile, bounds: bounds2, payload: p2, place: { authorization_id: `authz_${randomUUID()}`, group_id: v.groupId, replaces: v.authz1, chain_dids: [v.comp.root.did] }, title: 'Quotes', prepared_at: nowSec(), previous } }, 2);
    await v.phone.page.reload();
    await v.phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    await expect(v.phone.page.getByRole('tab', { name: 'Requests' }).or(v.phone.page.getByRole('button', { name: 'Requests', exact: true })).first()).toBeVisible({ timeout: 20_000 });
    await v.phone.page.waitForTimeout(3000);
    await expect(v.phone.page.getByTestId('give-card')).toHaveCount(0);
    const grants = await http(stack.asUrl, 'GET', `/api/mandates/${encodeURIComponent(v.mandateId)}/grants`, { token: v.token });
    expect((grants.json.grants as Array<{ mandate_version: number }>).filter((r) => r.mandate_version === 2)).toHaveLength(0);
    await v.phone.context.close();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// The phone's home screen (the maintainer on an iPhone, 2026-11-23): Waiting holds only waiting items, the empty text sits right under
// its heading, "Your mandates" shows the gateway's titles and the end as a date and time.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** A live mandate of the computer's person, granted on the computer (its check) and signed by the Authority Server, as a gateway does. */
async function liveMandate(comp: Computer, o: { profileDir: string; bounds: Record<string, string | number>; scope: Record<string, string>; title: string; intent: string }): Promise<{ authorizationId: string; title: string }> {
  const dir = join(PROFILES_DIR, o.profileDir);
  const newest = readdirSync(dir).filter((f) => f.endsWith('.profile.json')).sort((a, b) => parseFloat(a) - parseFloat(b)).pop()!;
  const profile = JSON.parse(readFileSync(join(dir, newest), 'utf8'));
  const bounds = { profile: profile.id, ...o.bounds };
  const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
  const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
  const chain = await chainOf(stack, comp, comp.root.did);
  const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
  const mandateId = newMandateId();
  const authorizationId = `authz_${randomUUID()}`;
  const expiresAt = nowSec() + 6 * 3600;
  const request = {
    profile_id: profile.id, profile_hash: computeProfileHash(profile), group_id: groupId, bounds,
    bounds_hash: computeBoundsHash(bounds as never, profile), scope_hash: computeScopeHash(o.scope as never, profile),
    domain: 'owner', did: comp.root.did, mandate_owners: [{ did: comp.root.did }], commitment_mode: 'review',
    gate_content_hashes: { intent: computeIntentHash(o.intent) }, execution_context_hash: computeExecutionContextHash(profile),
    supported_versions: ['0.8', '0.7'], title: o.title,
  };
  const payload = {
    mandate_id: mandateId, version: '0.8', profile_id: request.profile_id, profile_hash: request.profile_hash, bounds_hash: request.bounds_hash,
    scope_hash: request.scope_hash, execution_context_hash: request.execution_context_hash, issuer: 'did:key:z', mandate_owners: request.mandate_owners,
    gate_content_hashes: request.gate_content_hashes, commitment_mode: request.commitment_mode, issued_at: nowSec(), expires_at: expiresAt,
  } as unknown as MandatePayload;
  const grant = await http(stack.asUrl, 'POST', `/api/mandates/${encodeURIComponent(mandateId)}/grants`, {
    token, body: await signedGrant({ dev: comp.dev, ownerDid: comp.root.did, head: chain.head, mandateId, version: 1, members: grantMembersOf(payload, { authorizationId, groupId, replaces: null, chainDids: [comp.root.did] }) }),
  });
  expect(grant.status, show(grant)).toBe(201);
  const m = await http(stack.asUrl, 'POST', '/api/as/mandate', { apiKey: comp.apiKey, body: { ...request, authorization_id: authorizationId, mandate_id: mandateId, mandate_version: 1, expires_at: expiresAt } });
  expect(m.status, show(m)).toBeLessThan(300);
  return { authorizationId, title: o.title };
}

test.describe('the phone\'s home screen (maintainer 2026-11-23)', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('nothing waiting: the empty text right under "Waiting for you", no notes there, "Your mandates" with the gateway\'s titles and the end as date and time', async ({ browser }) => {
    const phone = await joinedPhone(browser, 'Home Phone', 'Office Mac');
    const comp = phone.person;
    const setupTitle = 'Setup: calendar, master-data, charge, publish, customers, purchase, deploy, records, email, reporting, files, sales, invoicing';
    await liveMandate(comp, { profileDir: 'delegation', bounds: { read_access: 'unlimited', brief_daily_max: 5, mandate_daily_max: 30 }, scope: { allowed_profiles: 'records', allowed_modes: 'review' }, title: setupTitle, intent: 'The AI prepares the mandates its work needs.' });
    await liveMandate(comp, { profileDir: 'sales', bounds: { read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 }, scope: { currency: 'EUR' }, title: 'Records · Meeting notes', intent: 'Keep short notes from meetings.' });
    // What the gateway's Mandates page shows as a mandate's title: the Authority Server's row title (`item.title`).
    const mine = await http(stack.asUrl, 'GET', '/api/mandates/mine?status=active', { apiKey: comp.apiKey });
    const gatewayTitles = (mine.json.mandates as Array<{ title?: string }>).map((r) => r.title).filter(Boolean).sort();
    expect(gatewayTitles).toEqual([setupTitle, 'Records · Meeting notes'].sort());

    await phone.page.goto(stack.appUrl);
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    const own = phone.page.getByTestId('own-mandate');
    await expect(own).toHaveCount(2, { timeout: 30_000 });
    const empty = phone.page.getByTestId('list-empty');
    await expect(empty).toHaveText('Nothing is waiting for you.');
    // Right under the heading and its line: above "Your mandates", nothing between but the intro line.
    const heading = phone.page.getByRole('heading', { name: 'Waiting for you' });
    const section = phone.page.getByTestId('own-mandates');
    const [hb, eb, sb] = await Promise.all([heading.boundingBox(), empty.boundingBox(), section.boundingBox()]);
    expect(eb!.y).toBeGreaterThan(hb!.y);
    expect(eb!.y).toBeLessThan(sb!.y);
    // No mandate notes under "Waiting for you" (between the heading and "Your mandates").
    await expect(phone.page.getByText(/was given on/)).toHaveCount(0);
    // The titles are the gateway's, without "The mandate for"; the end is a date and time, never "today".
    const titles = (await phone.page.getByTestId('own-mandate-title').allTextContents()).sort();
    expect(titles).toEqual(gatewayTitles);
    for (const u of await phone.page.getByTestId('own-mandate-until').allTextContents()) {
      expect(u).toMatch(/^Active until .*\d{4}.*\d{1,2}:\d{2}/);
      expect(u).not.toMatch(/today/i);
    }
    // "Your mandates" is a section heading: smaller than the screen's heading.
    const sizes = await phone.page.evaluate(() => ({
      h1: parseFloat(getComputedStyle(document.querySelector('.device-screen h1')!).fontSize),
      h2: parseFloat(getComputedStyle(document.querySelector('[data-testid="own-mandates"] h2')!).fontSize),
    }));
    expect(sizes.h2).toBeLessThan(sizes.h1);
    // The tabs are inside the screen, not above it.
    const tabs = await phone.page.getByTestId('app-nav').boundingBox();
    expect(tabs!.y).toBeGreaterThanOrEqual(0);
    const path = test.info().outputPath('home-1-nothing-waiting.png');
    await phone.page.screenshot({ path, fullPage: true });
    await test.info().attach('home-1-nothing-waiting', { path, contentType: 'image/png' });

    // A mandate to give waits: it is the waiting item, the empty text is gone, and it sits above "Your mandates".
    const state = await verifiedChain(stack, comp, comp.root.did);
    const chain = await chainOf(stack, comp, comp.root.did);
    const token = await sessionFor(stack, comp.root, comp.dev, chain.head);
    const profile = JSON.parse(readFileSync(join(PROFILES_DIR, 'sales', '0.4.profile.json'), 'utf8'));
    const bounds = { profile: profile.id, read_access: 'unlimited', value_max: 1000, discount_max: 10, order_value_daily_max: 5000, quote_daily_max: 10, send_daily_max: 10, order_daily_max: 0, setup_daily_max: 0 };
    const scope = { currency: 'EUR' };
    const intent = 'Follow up quotes that wait two days.';
    const groups = await http(stack.asUrl, 'GET', '/api/groups', { apiKey: comp.apiKey });
    const groupId = (groups.json.groups as Array<{ id: string; isPersonal?: boolean }>).find((g) => g.isPersonal)!.id;
    const mandateId = newMandateId();
    const payload = {
      mandate_id: mandateId, version: '0.8', profile_id: profile.id, profile_hash: computeProfileHash(profile), bounds_hash: computeBoundsHash(bounds as never, profile),
      scope_hash: computeScopeHash(scope as never, profile), execution_context_hash: computeExecutionContextHash(profile), issuer: 'did:key:z',
      mandate_owners: [{ did: comp.root.did }], gate_content_hashes: { intent: computeIntentHash(intent) }, commitment_mode: 'review',
      issued_at: nowSec(), expires_at: nowSec() + 3600,
    } as unknown as MandatePayload;
    const place = { authorization_id: `authz_${randomUUID()}`, group_id: groupId, replaces: null, chain_dids: [comp.root.did] };
    const content = { v: 2, mandate_id: mandateId, mandate_version: 1, scope, intent, give: { op: 'grant', profile, bounds, payload, place, title: 'Quotes', prepared_at: nowSec() } };
    const readers = Object.values(state.devices).filter((d) => d.removed_seq === null).map((d) => ({ did: d.key_id, publicKey: b64uDecode(d.read_pub) }));
    const sealed = await encryptProposalContent(content, readers);
    const prep = await http(stack.asUrl, 'POST', '/api/mandates/prepared', { token, body: { mandate_id: mandateId, mandate_version: 1, ciphertext: sealed.content.ciphertext, device_keys: sealed.content.encrypted_keys } });
    expect(prep.status, show(prep)).toBe(201);
    await phone.page.getByRole('button', { name: 'Refresh' }).click();
    // The give opens full screen by itself (DEC-86); Cancel goes back to the list, where it is the one waiting row.
    const card = phone.page.getByTestId('give-card');
    await expect(card).toBeVisible({ timeout: 30_000 });
    await card.getByRole('button', { name: 'Cancel' }).click();
    const row = phone.page.getByTestId('give-row');
    await expect(row).toBeVisible({ timeout: 15_000 });
    await expect(phone.page.getByTestId('list-empty')).toHaveCount(0);
    const [rb, sb2] = await Promise.all([row.boundingBox(), phone.page.getByTestId('own-mandates').boundingBox()]);
    expect(rb!.y).toBeLessThan(sb2!.y);
    const path2 = test.info().outputPath('home-2-one-waiting.png');
    await phone.page.screenshot({ path: path2, fullPage: true });
    await test.info().attach('home-2-one-waiting', { path: path2, contentType: 'image/png' });
    await phone.context.close();
  });
});

test.describe('WebKit', () => {
  test.skip(({ browserName }) => browserName !== 'webkit', 'the Chromium run covers this with a passkey');

  test('the app starts, loads its own code, and names what this browser lacks (no passkey can be made in an automated WebKit)', async ({ browser }) => {
    const phone = await newPhone(browser, { passkeys: false });
    const errors: string[] = [];
    phone.page.on('pageerror', (e) => errors.push(e.message));
    await phone.page.goto(stack.appUrl);
    const welcome = phone.page.getByRole('button', { name: 'Set up my account on this phone' });
    const needs = phone.page.getByTestId('needs');
    await expect(welcome.or(needs)).toBeVisible({ timeout: 20_000 });
    if (await needs.isVisible()) {
      // It must say WHICH ability is missing, in the app's own sentences; the Ed25519 / X25519 sentence means this WebKit is too old.
      const lines = await needs.locator('li').allTextContents();
      test.info().annotations.push({ type: 'webkit-needs', description: lines.join(' | ') });
      for (const l of lines) expect(l).toMatch(/^(A screen lock|A newer system|A browser that can keep data|The app opened from its icon)/);
    } else {
      test.info().annotations.push({ type: 'webkit-needs', description: 'none: this WebKit reports a platform authenticator' });
    }
    expect(errors, 'no uncaught error while the app starts').toEqual([]);
    await phone.context.close();
  });
});
