/**
 * multisig.ts — Multi-Party Trust (M-of-N co-signing).
 *
 * ATP v2: Multi-Party Authorization — high-stakes agent actions that require
 * approval from M out of N designated signers before they are considered
 * authorized.
 * IETF ATP Draft §8 — Multi-Party Authorization
 *
 * Design notes:
 *   - Each signer signs `{ id, payload }` — the request identity plus the
 *     exact action being authorized.
 *   - Signatures are collected incrementally; `isAuthorized` checks whether
 *     M valid, distinct signer signatures have been gathered.
 *   - Duplicate signer IDs are deduplicated at collection time; only one
 *     signature per signer ID is accepted.
 *   - `isAuthorized` performs full Ed25519 signature verification against the
 *     caller-supplied public-key map.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { canonicalize, signCanonical, verifyCanonical, newUuid } from "./crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface MultiSigRequest {
  /** UUID v4 for this request. */
  id: string;
  /** The action/payload to be authorized. */
  payload: Record<string, unknown>;
  /** M — minimum number of valid signatures required. */
  requiredSigners: number;
  /** N — the allow-list of authorized signer IDs. */
  signers: string[];
  /** ISO 8601 — when the request was created. */
  createdAt: string;
  /** Collected signatures. */
  signatures: Array<{
    signerId: string;
    /** Ed25519 signature (base64) over canonicalize({ id, payload }). */
    signature: string;
    /** ISO 8601 — when this signature was added. */
    signedAt: string;
  }>;
}

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * Create a new MultiSigRequest with no signatures yet.
 *
 * @throws if requiredSigners > signers.length or < 1.
 */
export function createMultiSigRequest(
  payload: Record<string, unknown>,
  signers: string[],
  requiredSigners: number,
): MultiSigRequest {
  if (signers.length === 0) {
    throw new RangeError("ATP multisig: signers list must not be empty");
  }
  if (requiredSigners < 1) {
    throw new RangeError(`ATP multisig: requiredSigners must be >= 1, got ${requiredSigners}`);
  }
  if (requiredSigners > signers.length) {
    throw new RangeError(
      `ATP multisig: requiredSigners (${requiredSigners}) exceeds signers count (${signers.length})`,
    );
  }

  return {
    id: newUuid(),
    payload,
    requiredSigners,
    signers: [...new Set(signers)], // deduplicate
    createdAt: new Date().toISOString(),
    signatures: [],
  };
}

// ─── Add signature ───────────────────────────────────────────────────────────

/**
 * Add a signer's signature to a MultiSigRequest. Returns a new request
 * (the original is not mutated).
 *
 * Rules:
 *   - `signerId` must be in `request.signers`.
 *   - Duplicate signatures from the same signerId are replaced (last wins).
 *
 * The message signed is `{ id: request.id, payload: request.payload }`.
 */
export function addSignature(
  request: MultiSigRequest,
  signerId: string,
  keyPair: { privateKey: string },
): MultiSigRequest {
  if (!request.signers.includes(signerId)) {
    throw new Error(`ATP multisig: "${signerId}" is not in the authorized signers list`);
  }

  const message = { id: request.id, payload: request.payload };
  const signature = signCanonical(message, keyPair.privateKey);
  const signedAt = new Date().toISOString();

  // Replace any existing entry for this signer (idempotent re-sign).
  const filtered = request.signatures.filter((s) => s.signerId !== signerId);
  const newSig = { signerId, signature, signedAt };

  return {
    ...request,
    signatures: [...filtered, newSig],
  };
}

// ─── Check authorization ──────────────────────────────────────────────────────

/**
 * Determine whether a MultiSigRequest has collected enough valid signatures.
 *
 * Verification:
 *   1. The signer must be in `request.signers`.
 *   2. The signer's public key must be in `signerPublicKeys`.
 *   3. The Ed25519 signature over `{ id, payload }` must verify.
 *   4. At least `requiredSigners` such valid, distinct signatures must exist.
 */
export function isAuthorized(
  request: MultiSigRequest,
  signerPublicKeys: Map<string, string>,
): { authorized: boolean; signaturesCollected: number; required: number } {
  const message = { id: request.id, payload: request.payload };
  const seen = new Set<string>();
  let validCount = 0;

  for (const entry of request.signatures) {
    // Skip if not in authorized list.
    if (!request.signers.includes(entry.signerId)) continue;
    // Skip duplicates (shouldn't happen if addSignature is used, but be safe).
    if (seen.has(entry.signerId)) continue;

    const pubKey = signerPublicKeys.get(entry.signerId);
    if (!pubKey) continue;

    const ok = verifyCanonical(message, pubKey, entry.signature);
    if (ok) {
      seen.add(entry.signerId);
      validCount++;
    }
  }

  return {
    authorized: validCount >= request.requiredSigners,
    signaturesCollected: validCount,
    required: request.requiredSigners,
  };
}
