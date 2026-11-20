/**
 * Mandate grants (device-keys plan 4.4, build step 13) for suites that talk to a real Authority Server over HTTP.
 *
 * Since stage B an account with a device chain gets a mandate only after a granting device stored a grant at
 * POST /api/mandates/:id/grants, signed with the device key and the device's check over the grant hash. The request
 * to /api/as/mandate then names `mandate_id` and `mandate_version`; the Authority Server checks the grant against
 * the mandate it is about to sign and refuses any difference (GRANT_MISMATCH).
 *
 * The grant's members are derived exactly as the Authority Server and the gateway derive them: the members of the
 * v0.8 owner-signature projection (hap-core `buildMandateProjection`; a member the mandate lacks is `null`), minus
 * the names the projection shares with the grant's fixed members, plus `authorization_id`, `group_id`, `chain_dids`
 * and `replaces`. The names are derived from the projection, never listed by hand. Nothing here is a mock: the
 * objects are signed here and the Authority Server verifies them itself.
 */
import { randomBytes as nodeRandomBytes } from 'node:crypto';
import { buildMandateProjection, type MandatePayload } from '@humanagencyp/hap-core';
import { b64uEncode, buildGrant, grantHash, randomBytes, signObject, type MandateGrant } from '@humanagencyp/hap-core/device-keys';

import { checkOver, type Device } from './device-chain.js';

const NOT_FROM_PROJECTION = new Set(['typ', 'owner_did', 'nonce', 'binding', 'signing_surface']);
const EXTRA_MEMBERS = ['authorization_id', 'group_id', 'chain_dids', 'replaces'] as const;

type ProjectionEntry = Parameters<typeof buildMandateProjection>[1];
const entryFor = (did: string): ProjectionEntry => ({ did, nonce: 'n', binding: 'b', signing_surface: 's' }) as unknown as ProjectionEntry;

function dummyPayload(): MandatePayload {
  return {
    mandate_id: 'm', version: '0.8', profile_id: 'p', profile_hash: 'h', bounds_hash: 'h', scope_hash: 'h',
    execution_context_hash: 'h', gate_content_hashes: {}, issuer: 'i', mandate_owners: [{ did: 'did:key:z' }],
    commitment_mode: 'review_above_cap', issued_at: 0, expires_at: 0,
    intent_disclosure_hash: 'h', disclose_fields: [], above_cap_caps: {}, above_cap_approvers: [], above_cap_approvals: 1,
  } as unknown as MandatePayload;
}

/** Every member (besides the fixed ones) a grant carries, sorted. */
export function grantFieldKeys(): string[] {
  const fromProjection = Object.keys(buildMandateProjection(dummyPayload(), entryFor('did:key:z'))).filter((k) => !NOT_FROM_PROJECTION.has(k));
  return [...fromProjection, ...EXTRA_MEMBERS].sort();
}

export interface GrantPlacement {
  authorizationId: string;
  groupId: string;
  replaces: string | null;
  /** The owner and the approvers that have a device chain, sorted ascending, each once. */
  chainDids: string[];
}

/** The grant's members for this mandate payload (the payload as the Authority Server will sign it). */
export function grantMembersOf(payload: MandatePayload, placement: GrantPlacement): Record<string, unknown> {
  const ownerDid = payload.mandate_owners?.[0]?.did;
  if (!ownerDid) throw new Error('the mandate names no owner');
  const projection = buildMandateProjection(payload, entryFor(ownerDid)) as unknown as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of grantFieldKeys()) {
    if ((EXTRA_MEMBERS as readonly string[]).includes(k)) continue;
    out[k] = projection[k] === undefined ? null : projection[k];
  }
  out.authorization_id = placement.authorizationId;
  out.group_id = placement.groupId;
  out.chain_dids = [...placement.chainDids].sort();
  out.replaces = placement.replaces;
  return out;
}

/** A fresh mandate id, as a gateway makes one (18 random bytes, base64url). */
export function newMandateId(): string {
  return nodeRandomBytes(18).toString('base64url');
}

/**
 * The signed `{ grant, sig, check }` body for POST /api/mandates/:id/grants: signed by `dev` (an active device of the
 * owner's chain that holds a check key) with its check over the grant hash, naming the chain head `head`.
 */
export async function signedGrant(args: {
  dev: Device;
  ownerDid: string;
  head: { seq: number; hash: string };
  mandateId: string;
  version: number;
  op?: 'grant' | 'change';
  members: Record<string, unknown>;
}): Promise<{ grant: MandateGrant; sig: string; check: { signature: string } }> {
  const grant = buildGrant({
    op: args.op ?? 'grant', owner_did: args.ownerDid, key_id: args.dev.record.key_id,
    chain_seq: args.head.seq, chain_head: args.head.hash,
    mandate_id: args.mandateId, mandate_version: args.version,
    granted_at: Math.floor(Date.now() / 1000), nonce: b64uEncode(randomBytes(16)),
  }, args.members);
  const sig = await signObject(grant, args.dev.seed);
  const check = await checkOver(args.dev.checkPriv, await grantHash(grant));
  return { grant, sig, check };
}
