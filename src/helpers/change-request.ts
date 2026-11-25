/**
 * The computer's side of a change to a connector login confirmed on the phone (device-keys plan 7 phone path, 20.4), for the phone
 * suite. The suite plays the computer (see e2e/phone/phone-app.spec.ts): this builds what a gateway without a check key sends, with
 * the same formats as the gateway (suveren-gateway packages/pairing change-confirmation.ts), and checks the phone's answer the way
 * the gateway does (its own verified chain, an active granting device, the head, the signature, the check, the request).
 *
 *   view       { typ: "suveren-change-request", v: 1, request, connector, fields, issued_at }
 *   sealing    AES-256-GCM under a fresh content key, IV || ct || tag, associated data "suveren-change-request" || 0x00 || request_id;
 *              the content key HPKE-wrapped (DHKEM X25519, HKDF-SHA256, AES-256-GCM) to the phone's reading key
 *   envelope   { typ: "suveren-gateway-envelope", v: 1, kind: "change-request", gateway_key_id, chain_seq, chain_head, content_hash,
 *              issued_at }, content_hash = objectHash(view), signed with the computer's device key
 */
import { createCipheriv, createHash, randomBytes as nodeRandom } from 'node:crypto';
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from '@hpke/core';
import {
  b64uBytes, b64uEncode, checkKeyAt, checkNamedHead, isActive, objectHash, signObject, signedBytes, verifyCheck, verifyEd25519,
  type ChainState,
} from '@humanagencyp/hap-core/device-keys';
import type { Device } from './device-chain';

export interface ChangeField { key: string; label?: string; secret: boolean; old?: string; new?: string }

export interface SentRequest {
  requestId: string;
  changeHash: string;
  view: Record<string, unknown>;
  body: Record<string, unknown>;
}

const suite = () => new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

/** The request a computer sends: sealed for `phones` (key id → reading public key, base64url), signed with `computer`. */
export async function buildChangeRequest(o: {
  computer: Device; chain: ChainState; phones: Record<string, string>;
  kind: 'replace' | 'remove'; name: string; connector: string; fields: ChangeField[]; change: unknown; ttlSeconds?: number; now: number;
}): Promise<SentRequest> {
  const requestId = b64uEncode(new Uint8Array(nodeRandom(16)));
  const changeHash = createHash('sha256').update(JSON.stringify(o.change)).digest('hex');
  const view = {
    typ: 'suveren-change-request', v: 1,
    request: { request_id: requestId, kind: o.kind, name: o.name, change_hash: changeHash, gateway_key_id: o.computer.record.key_id, expires_at: o.now + (o.ttlSeconds ?? 900) },
    connector: o.connector, fields: o.fields, issued_at: o.now,
  };
  const cek = new Uint8Array(nodeRandom(32));
  const iv = nodeRandom(12);
  const cipher = createCipheriv('aes-256-gcm', cek, iv);
  cipher.setAAD(Buffer.concat([Buffer.from('suveren-change-request', 'utf8'), Buffer.from([0]), Buffer.from(requestId, 'utf8')]));
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(view), 'utf8')), cipher.final(), cipher.getAuthTag()]);
  const ciphertext = Buffer.concat([iv, ct]).toString('base64url');
  const wraps: Record<string, { ct: string; enc: string }> = {};
  for (const [keyId, readPub] of Object.entries(o.phones)) {
    const s = suite();
    const sender = await s.createSenderContext({ recipientPublicKey: await s.kem.deserializePublicKey(b64uBytes(readPub, 32, 'read_pub')) });
    wraps[keyId] = { ct: b64uEncode(new Uint8Array(await sender.seal(cek))), enc: b64uEncode(new Uint8Array(sender.enc)) };
  }
  const envelope = {
    typ: 'suveren-gateway-envelope', v: 1, kind: 'change-request', gateway_key_id: o.computer.record.key_id,
    chain_seq: o.chain.head.seq, chain_head: o.chain.head.hash, content_hash: await objectHash(view), issued_at: o.now,
  };
  const body = { request_id: requestId, envelope, sender_sig: await signObject(envelope, o.computer.seed), ciphertext, device_keys: wraps };
  return { requestId, changeHash, view, body };
}

/** The gateway's check of the phone's answer (plan 7). Throws with a reason; returns the decision. */
export async function verifyPhoneAnswer(answer: { confirmation: Record<string, unknown>; sig: string; check?: unknown }, ctx: {
  chain: ChainState; rootDid: string; requestId: string; changeHash: string; computerKeyId: string; now: number;
}): Promise<'allow' | 'deny'> {
  const c = answer.confirmation;
  const members = ['typ', 'v', 'root_did', 'key_id', 'chain_seq', 'chain_head', 'request_id', 'change_hash', 'gateway_key_id', 'decision', 'confirmed_at'];
  if (Object.keys(c).sort().join() !== [...members].sort().join()) throw new Error('not exactly a change confirmation');
  if (c.typ !== 'suveren-change-confirmation' || c.v !== 1) throw new Error('wrong typ');
  if (c.root_did !== ctx.rootDid) throw new Error('wrong identity');
  if (c.request_id !== ctx.requestId || c.change_hash !== ctx.changeHash || c.gateway_key_id !== ctx.computerKeyId) throw new Error('another request');
  checkNamedHead(ctx.chain, c.chain_seq as number, c.chain_head as string);
  const dev = ctx.chain.devices[c.key_id as string];
  if (!dev || !isActive(ctx.chain, dev.key_id) || !dev.check || dev.key_id === ctx.computerKeyId) throw new Error('not an active granting device');
  if (!(await verifyEd25519(b64uBytes(dev.sign_pub, 32, 'sign_pub'), signedBytes(c), b64uBytes(answer.sig, 64, 'sig')))) throw new Error('bad signature');
  if (c.decision === 'allow') {
    const key = checkKeyAt(ctx.chain, dev.key_id, c.chain_seq as number);
    if (!key || !(await verifyCheck(key, await objectHash(c), answer.check))) throw new Error('bad check');
  } else if (c.decision !== 'deny') {
    throw new Error('no decision');
  }
  if ((c.confirmed_at as number) > ctx.now + 60) throw new Error('from the future');
  return c.decision as 'allow' | 'deny';
}
