/**
 * delegation.ts — Parent→child trust delegation.
 *
 * ATP v2: Delegation chains — a parent agent delegates scoped authority to
 * child agents without requiring the child to hold an independent AIC.
 * IETF ATP Draft §6.2 — Trust Delegation
 *
 * Design notes:
 *   - DelegationCertificate is intentionally JSON-serialisable (no Date, no Buffer).
 *   - Signatures cover the canonical JSON of all non-signature fields.
 *   - delegatedScope MUST be a strict subset of the parent's scope.
 *   - maxDepth prevents unbounded re-delegation chains.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { canonicalize, signCanonical, verifyCanonical, newUuid } from "./crypto";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface DelegationCertificate {
  /** "atp:del:<uuid>" */
  id: string;
  parentAgentId: string;
  childAgentId: string;
  /** Subset of parent's scope granted to child. */
  delegatedScope: string[];
  /** Max further delegation depth (0 = terminal — child cannot re-delegate). */
  maxDepth: number;
  /** ISO 8601 */
  issuedAt: string;
  /** ISO 8601 */
  expiresAt: string;
  /** Ed25519 signature (base64) over canonicalized cert (without this field). */
  parentSignature: string;
  atpVersion: "2.0";
}

// ─── Create ──────────────────────────────────────────────────────────────────

/**
 * Create and sign a DelegationCertificate.
 *
 * The signature covers the canonical JSON of all fields except
 * `parentSignature` itself, preventing any field from being tampered with
 * post-issuance.
 */
export function createDelegation(params: {
  parentKeyPair: { privateKey: string; publicKey: string };
  parentAgentId: string;
  childAgentId: string;
  delegatedScope: string[];
  maxDepth?: number;
  ttlSeconds?: number;
}): DelegationCertificate {
  const now = new Date();
  const ttl = params.ttlSeconds ?? 3600;
  const expiresAt = new Date(now.getTime() + ttl * 1000);

  // Build the unsigned payload first so we can canonicalise it.
  const unsigned: Omit<DelegationCertificate, "parentSignature"> = {
    id: `atp:del:${newUuid()}`,
    parentAgentId: params.parentAgentId,
    childAgentId: params.childAgentId,
    delegatedScope: [...params.delegatedScope].sort(),
    maxDepth: params.maxDepth ?? 0,
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    atpVersion: "2.0",
  };

  const parentSignature = signCanonical(unsigned, params.parentKeyPair.privateKey);

  return { ...unsigned, parentSignature };
}

// ─── Verify single cert ───────────────────────────────────────────────────────

/**
 * Verify a DelegationCertificate:
 *   1. Signature must be valid (Ed25519 over canonical unsigned payload).
 *   2. Certificate must not be expired.
 */
export function verifyDelegation(
  cert: DelegationCertificate,
  parentPublicKey: string,
): { valid: boolean; reason?: string } {
  // Check expiry first (cheap).
  const now = Date.now();
  const expires = new Date(cert.expiresAt).getTime();
  if (isNaN(expires)) {
    return { valid: false, reason: "delegation: invalid expiresAt timestamp" };
  }
  if (now > expires) {
    return { valid: false, reason: "delegation: certificate has expired" };
  }

  // Reconstruct unsigned payload for sig verification.
  const { parentSignature, ...unsigned } = cert;
  const ok = verifyCanonical(unsigned, parentPublicKey, parentSignature);
  if (!ok) {
    return { valid: false, reason: "delegation: parentSignature is invalid" };
  }

  return { valid: true };
}

// ─── Verify delegation chain ──────────────────────────────────────────────────

/**
 * Verify a full delegation chain [root, ..., leaf]:
 *   1. Each certificate's parentSignature is valid (requires publicKeyMap).
 *   2. Each certificate has not expired.
 *   3. chain[i].childAgentId === chain[i+1].parentAgentId (chain linkage).
 *   4. chain[i].maxDepth >= remaining chain length (depth constraint).
 *   5. chain[i+1].delegatedScope ⊆ chain[i].delegatedScope (no widening).
 *
 * @param chain       Ordered list of delegation certs [root → leaf].
 * @param rootPublicKey  Ed25519 public key (base64) of the root parent agent.
 * @param publicKeyMap   Map of agentId → Ed25519 public key for every
 *                       intermediate agent in the chain. Without this, only
 *                       root signature + structural checks are performed.
 *                       Pass an empty Map to get structural-only validation.
 */
export function verifyDelegationChain(
  chain: DelegationCertificate[],
  rootPublicKey: string,
  publicKeyMap: Map<string, string> = new Map(),
): { valid: boolean; depth: number; reason?: string } {
  if (chain.length === 0) {
    return { valid: false, depth: 0, reason: "delegation chain is empty" };
  }

  // Verify root cert with the supplied public key.
  const rootResult = verifyDelegation(chain[0], rootPublicKey);
  if (!rootResult.valid) {
    return { valid: false, depth: 0, reason: `chain[0]: ${rootResult.reason}` };
  }

  for (let i = 1; i < chain.length; i++) {
    const prev = chain[i - 1];
    const curr = chain[i];

    // Chain linkage: child of previous must be parent of current.
    if (prev.childAgentId !== curr.parentAgentId) {
      return {
        valid: false,
        depth: i,
        reason: `chain[${i}]: parentAgentId "${curr.parentAgentId}" does not match chain[${i - 1}].childAgentId "${prev.childAgentId}"`,
      };
    }

    // Depth constraint: previous cert must allow further delegation.
    const remainingLinks = chain.length - i; // links still to traverse
    if (prev.maxDepth < remainingLinks) {
      return {
        valid: false,
        depth: i,
        reason: `chain[${i - 1}]: maxDepth ${prev.maxDepth} exceeded (need ${remainingLinks})`,
      };
    }

    // Scope non-widening: every scope item in curr must exist in prev.
    const prevScopeSet = new Set(prev.delegatedScope);
    for (const item of curr.delegatedScope) {
      if (!prevScopeSet.has(item)) {
        return {
          valid: false,
          depth: i,
          reason: `chain[${i}]: scope widening detected — "${item}" not in parent scope`,
        };
      }
    }

    // Full Ed25519 verification: chain[i] was signed by curr.parentAgentId.
    // rootPublicKey belongs to chain[0].parentAgentId (the root delegator).
    // Every other signer must be in publicKeyMap.
    const signerAgentId = curr.parentAgentId;
    const parentPubKey =
      signerAgentId === chain[0].parentAgentId
        ? rootPublicKey
        : publicKeyMap.get(signerAgentId);

    if (!parentPubKey) {
      return {
        valid: false,
        depth: i,
        reason: `chain[${i}]: no public key for signer "${signerAgentId}" in publicKeyMap — cannot verify signature`,
      };
    }

    const certResult = verifyDelegation(curr, parentPubKey);
    if (!certResult.valid) {
      return { valid: false, depth: i, reason: `chain[${i}]: ${certResult.reason}` };
    }
  }

  return { valid: true, depth: chain.length - 1 };
}
