/**
 * Device-chain fixtures for suites that talk to a real Authority Server over HTTP: real Ed25519 device keys, real
 * platform checks (ECDSA P-256 over the object hash), real chain entries built with hap-core's device-keys module.
 * Nothing here is a mock; the objects are signed here and the Authority Server verifies them itself.
 */
import { webcrypto } from 'node:crypto';
import {
  b64uEncode, buildEntry, buildSignin, deriveRootKey, ecdsaRawToDer, ed25519PublicKey, entryHash, keyIdOf,
  randomBytes, signEntry, signObject, type ChainEntry, type CheckKey, type DeviceRecord,
} from '@humanagencyp/hap-core/device-keys';

export interface Device {
  seed: Uint8Array;
  record: DeviceRecord;
  checkPriv: webcrypto.CryptoKey;
}

export async function newDevice(label = `Computer ${Math.random().toString(36).slice(2, 6)}`): Promise<Device> {
  const seed = randomBytes(32);
  const signPub = await ed25519PublicKey(seed);
  const kp = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;
  const check: CheckKey = { type: 'platform', pub: b64uEncode(new Uint8Array(await webcrypto.subtle.exportKey('raw', kp.publicKey))) };
  const record: DeviceRecord = {
    key_id: await keyIdOf(signPub), sign_pub: b64uEncode(signPub), read_pub: b64uEncode(randomBytes(32)), kind: 'gateway',
    label, keystore: 'platform', check,
  };
  return { seed, record, checkPriv: kp.privateKey };
}

/** A platform check: ECDSA P-256 over the 32 digest bytes of a `sha256:` hash, DER. */
export async function checkOver(priv: webcrypto.CryptoKey, hash: string): Promise<{ signature: string }> {
  const digest = Buffer.from(hash.slice('sha256:'.length), 'hex');
  const raw = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, digest));
  return { signature: b64uEncode(ecdsaRawToDer(raw)) };
}

export const newRoot = () => deriveRootKey(randomBytes(16));
export type Root = Awaited<ReturnType<typeof newRoot>>;

export async function genesisEntry(root: Root, first: Device): Promise<ChainEntry> {
  const e = buildEntry({ root_did: root.did, seq: 0, prev: null, op: 'genesis', created_at: Math.floor(Date.now() / 1000), signer: 'root', device: first.record });
  const h = await entryHash(e);
  e.sigs = [await signEntry(e, 'root', root.privateSeed), await signEntry(e, first.record.key_id, first.seed)];
  e.checks = [{ by: first.record.key_id, check: await checkOver(first.checkPriv, h) }];
  return e;
}

export async function headOf(entry: ChainEntry) {
  return { seq: entry.seq, hash: await entryHash(entry) };
}

/** The signed sign-in body for POST /api/devices/session, given the challenge the AS issued. */
export async function signinBody(root: Root, dev: Device, head: { seq: number; hash: string }, challenge: { nonce: string; aud: string }) {
  const signin = buildSignin({
    aud: challenge.aud, root_did: root.did, key_id: dev.record.key_id, nonce: challenge.nonce,
    chain_seq: head.seq, chain_head: head.hash, issued_at: Math.floor(Date.now() / 1000),
  });
  return { signin, sig: await signObject(signin, dev.seed) };
}
