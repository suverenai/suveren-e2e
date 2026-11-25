/**
 * A phone for server suites, without a browser: a real P-256 passkey, a WebAuthn registration the way a browser makes
 * one (attestation "none": clientDataJSON + an attestation object in CBOR), assertions over an object hash, and the
 * chain entry by which a computer admits the phone. Nothing here is a mock; the Authority Server verifies all of it.
 *
 * The browser suite (test:phone) drives the real app with a virtual authenticator instead; this file is for suites that
 * test the server side of something a phone does (notifications, stage D4).
 */
import { createHash, webcrypto } from 'node:crypto';
import {
  b64uEncode, buildEntry, buildSignin, ecdsaRawToDer, ed25519PublicKey, encodeCoseEc2, entryHash, keyIdOf, objectHash,
  randomBytes, signEntry, signObject,
  type ChainEntry, type CheckKey, type DeviceRecord, type WebauthnProof,
} from '@humanagencyp/hap-core/device-keys';
import { checkOver, type Device, type Root } from './device-chain.js';

const REGISTER_LABEL = 'suveren-passkey-register-v1';
const sha = (b: Uint8Array | string): Buffer => createHash('sha256').update(b).digest();

type C = number | string | Uint8Array | C[] | Map<C, C>;
function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
}
function cbor(v: C): Buffer {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}

export interface Phone extends Omit<Device, 'checkPriv'> {
  credId: Uint8Array;
  priv: webcrypto.CryptoKey;
  x: Uint8Array;
  y: Uint8Array;
  /** The app's origin the passkey was made at; its host is the relying party. */
  appOrigin: string;
}

export async function newPhone(appOrigin: string, label = `Phone ${Math.random().toString(36).slice(2, 6)}`): Promise<Phone> {
  const seed = randomBytes(32);
  const signPub = await ed25519PublicKey(seed);
  const kp = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey));
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  const credId = randomBytes(32);
  const check: CheckKey = { type: 'webauthn', rp_id: new URL(appOrigin).hostname, cred_id: b64uEncode(credId), pub: b64uEncode(encodeCoseEc2(x, y)) };
  const record: DeviceRecord = {
    key_id: await keyIdOf(signPub), sign_pub: b64uEncode(signPub), read_pub: b64uEncode(randomBytes(32)), kind: 'approve-app',
    label, keystore: 'platform', check,
  };
  return { seed, record, credId, priv: kp.privateKey, x, y, appOrigin };
}

/** The registration the app sends under a pairing id (`POST /api/devices/pairings/:id/passkey`). */
export function registration(p: Phone) {
  const rp = new URL(p.appOrigin).hostname;
  const challenge = b64uEncode(new Uint8Array(sha(Buffer.concat([Buffer.from(REGISTER_LABEL), Buffer.from([0]), Buffer.from(p.record.key_id)]))));
  const client = { type: 'webauthn.create', challenge, origin: p.appOrigin, crossOrigin: false };
  const cose = encodeCoseEc2(p.x, p.y);
  const authData = Buffer.concat([
    sha(rp), Buffer.from([0x45]), Buffer.from([0, 0, 0, 0]), Buffer.alloc(16),
    Buffer.from([p.credId.length >> 8, p.credId.length & 255]), Buffer.from(p.credId), Buffer.from(cose),
  ]);
  const att = cbor(new Map<C, C>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
  return {
    cred_id: b64uEncode(p.credId), pub: b64uEncode(cose), rp_id: rp,
    client_data_json: b64uEncode(new Uint8Array(Buffer.from(JSON.stringify(client)))),
    attestation_object: b64uEncode(new Uint8Array(att)),
  };
}

/** A passkey assertion over `hash` (`sha256:<hex>`). */
export async function assertion(p: Phone, hash: string): Promise<WebauthnProof> {
  const digest = Buffer.from(hash.slice('sha256:'.length), 'hex');
  const authData = Buffer.concat([sha(new URL(p.appOrigin).hostname), Buffer.from([0x05]), Buffer.from([0, 0, 0, 1])]);
  const cdj = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64uEncode(new Uint8Array(digest)), origin: p.appOrigin }));
  const sig = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, p.priv, Buffer.concat([authData, sha(cdj)])));
  return { authenticatorData: b64uEncode(new Uint8Array(authData)), clientDataJSON: b64uEncode(new Uint8Array(cdj)), signature: b64uEncode(ecdsaRawToDer(sig)) };
}

/** A computer (with its platform check) admits the phone: both sign, both check. */
export async function admitEntry(root: Root, prev: ChainEntry, computer: Device, phone: Phone): Promise<ChainEntry> {
  const e = buildEntry({
    root_did: root.did, seq: prev.seq + 1, prev: await entryHash(prev), op: 'add', created_at: Math.floor(Date.now() / 1000),
    signer: computer.record.key_id, device: phone.record,
  });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, computer.record.key_id, computer.seed), await signEntry(e, phone.record.key_id, phone.seed)];
  e.checks = [{ by: computer.record.key_id, check: await checkOver(computer.checkPriv, h) }, { by: phone.record.key_id, check: await assertion(phone, h) }];
  return e;
}

/** A computer removes a device. */
export async function removeEntry(root: Root, prev: ChainEntry, computer: Device, targetKeyId: string): Promise<ChainEntry> {
  const e = buildEntry({
    root_did: root.did, seq: prev.seq + 1, prev: await entryHash(prev), op: 'remove', created_at: Math.floor(Date.now() / 1000),
    signer: computer.record.key_id, target: targetKeyId,
  });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, computer.record.key_id, computer.seed)];
  e.checks = [{ by: computer.record.key_id, check: await checkOver(computer.checkPriv, h) }];
  return e;
}

/** The phone's sign-in body: signed by its device key, with its passkey's check over the sign-in's object hash. */
export async function phoneSigninBody(root: Root, p: Phone, head: { seq: number; hash: string }, challenge: { nonce: string; aud: string }) {
  const signin = buildSignin({
    aud: challenge.aud, root_did: root.did, key_id: p.record.key_id, nonce: challenge.nonce,
    chain_seq: head.seq, chain_head: head.hash, issued_at: Math.floor(Date.now() / 1000),
  });
  return { signin, sig: await signObject(signin, p.seed), check: await assertion(p, await objectHash(signin)) };
}
