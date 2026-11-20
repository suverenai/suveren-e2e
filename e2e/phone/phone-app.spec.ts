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
import { readFileSync } from 'node:fs';
import {
  asKeyHex, chainOf, clearMailboxes, codeOf, computerAnswersJoin, computerWithChain, connectDb, enrolmentCode, headOf, http,
  identityCodeOf, mailboxRow, newJoiner, newPairing, newPerson, newRoot, nowSec, openMailbox,
  pairingQr, qrMatrix, readBox, show, signinBody, stackFromEnv, until, verifiedChain, waitForMessage,
  b64uEncode, newDevice, entryHash, randomBytes, checkOver,
  type Computer, type PhoneStack, type Root,
} from '../../src/helpers/phone-app';
import { buildChangeRequest, verifyPhoneAnswer } from '../../src/helpers/change-request';

const unavailable = process.env.HAP_E2E_PHONE_UNAVAILABLE;
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
  const context = await browser.newContext({ serviceWorkers: 'block', viewport: { width: 390, height: 844 } });
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
  // DEC-83: a phone that is not paired opens straight on adding itself (apps/approve App.tsx): no start screen in between.
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
  await page.getByRole('button', { name: 'Devices', exact: true }).click();
  await expect(page.getByTestId('device-list')).toBeVisible({ timeout: 15_000 });
}

const deviceNames = (page: Page) => page.getByTestId('device-row').locator('.su-who > b').allTextContents();

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// No phone-first setup (DEC-83)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

test.describe('phone-first setup is off', () => {
  test.skip(chromiumOnly, NO_VIRTUAL_AUTHENTICATOR);

  test('a phone that is not paired opens straight on adding itself to an account', async ({ browser }) => {
    const phone = await newPhone(browser, { passkeys: true });
    await phone.page.goto(stack.appUrl);
    // DEC-83: no start screen; the one way in is adding this phone (apps/approve App.tsx).
    await expect(phone.page.getByRole('heading', { name: 'Add this phone to your account' })).toBeVisible({ timeout: 20_000 });
    await expect(phone.page.getByRole('button', { name: 'Scan the code' })).toBeVisible();
    await expect(phone.page.getByRole('button', { name: 'Set up my account on this phone' })).toHaveCount(0);
    await expect(phone.page.locator('#setup-code')).toHaveCount(0);
    // One way in: besides the day/dark switch, exactly one button.
    await expect(phone.page.getByRole('button')).toHaveCount(2);
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

    // 3. The mailbox rows hold neither the secret nor the code.
    const row = (await mailboxRow(db, pairing))!;
    expect(row.columns.sort()).not.toContain('secret');
    for (const leaked of [b64uEncode(pairing.secret), b64uEncode(pairing.macKey), Buffer.from(pairing.secret).toString('hex'), Buffer.from(pairing.macKey).toString('hex'), `"${answered.code}"`]) {
      expect(row.text, 'the mailbox row must not hold the secret, the MAC key or the code').not.toContain(leaked);
    }

    // 4. Until the computer confirms, the phone is not a device: it is in no chain, so it has no session and reads nothing.
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(1);
    await expect(phone.page.getByRole('button', { name: 'Devices', exact: true })).toHaveCount(0);

    // 5. The computer confirms with its check; the phone is added under the SAME root DID.
    const res = await answered.confirm();
    expect(res.status, show(res)).toBe(201);
    await expect(phone.page.getByText(READY)).toBeVisible({ timeout: 20_000 });
    const after = await verifiedChain(stack, comp, comp.root.did); // hap-core verifies the served chain from the genesis on
    expect(Object.keys(after.devices)).toHaveLength(2);
    expect((await db.query(`select did, root_did from users where id = $1`, [comp.userId])).rows[0]).toEqual({ did: comp.root.did, root_did: comp.root.did });
    expect((await chainOf(stack, comp, comp.root.did)).entries).toHaveLength(2);

    // 6. The phone's own screens: the same identity code, both devices.
    await phone.page.getByRole('button', { name: 'Continue' }).click();
    await phone.page.getByRole('button', { name: 'Open with a touch' }).click();
    await phone.page.getByRole('button', { name: 'Devices', exact: true }).click();
    await expect(phone.page.getByTestId('identity-code')).toHaveText(await identityCodeOf(comp.root.did), { timeout: 15_000 });
    expect(await deviceNames(phone.page)).toEqual(['Office computer', 'My iPhone']);
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

  test('offered on the join\'s done screen; old code, new code once, touch, the email link confirmed on the phone, the new root in force', async ({ browser }) => {
    const { seed, code: oldCode } = await generateRecoveryCode();
    const root = await deriveRootKey(seed);
    const phone = await joinedPhone(browser, 'Rotating Phone', 'Code Mac', root);
    const { page } = phone;
    await expect(page.getByTestId('rotate-offer')).toBeVisible();
    await page.getByRole('button', { name: 'Make a new code' }).click();
    await page.getByRole('button', { name: 'Open with a touch' }).click();

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
