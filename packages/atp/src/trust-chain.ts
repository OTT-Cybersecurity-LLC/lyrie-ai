/**
 * trust-chain.ts — Trust Chain rules.
 *
 * The fourth ATP primitive. A TrustChain is the verified, ordered ancestry
 * of AICs from a root operator-issued certificate down to a leaf sub-agent.
 *
 * The hard rule, enforced cryptographically: **every child's scope is a
 * subset of its parent's**. A spawned agent cannot exceed the authority of
 * the agent that spawned it. This is the rule that, had it existed in 2026,
 * would have prevented the MCP RCE family of privilege-escalation
 * vulnerabilities (CVE-2026-30615 et al.) — sub-agents and tool plugins
 * could not have silently widened their own permissions.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  AgentIdentityCertificate,
  CertId,
  TrustChain,
  VerificationResult,
} from "./types";
import { certIdOf, verifyAic, type VerifyAicOptions } from "./aic";
import { isScopeSubset } from "./scope";

// ─── Construction ────────────────────────────────────────────────────────────

/**
 * Build a TrustChain from an ordered list `[root, ..., leaf]`. Performs
 * structural setup only — call {@link verifyTrustChain} to enforce the
 * cryptographic invariants.
 */
export function buildTrustChain(chain: AgentIdentityCertificate[]): TrustChain {
  if (chain.length === 0) {
    throw new Error("ATP: trust chain must have at least one cert (the root)");
  }
  return {
    rootCertId: certIdOf(chain[0]!),
    chain,
    depth: chain.length - 1,
  };
}

// ─── Verification ────────────────────────────────────────────────────────────

export interface VerifyTrustChainOptions extends VerifyAicOptions {
  /**
   * Optional cap: reject chains deeper than this even if the parent's scope
   * `maxSubAgentDepth` would allow it. Useful as a global safety brake.
   */
  maxDepth?: number;
}

/**
 * Verify a TrustChain end-to-end:
 *   1. each AIC verifies on its own (signature, scope, expiry, revocation)
 *   2. parent/child links are correct (parentCertId chains to predecessor's CertId)
 *   3. each child's scope ⊆ parent's scope
 *   4. each child's `issuedAt` falls within its parent's validity window
 *   5. each level descends within parent's `maxSubAgentDepth`
 *   6. global maxDepth (if provided) is not exceeded
 *
 * Returns a `VerificationResult` with `details` populated when multiple
 * link errors are present, so audit tools can show every broken hop.
 */
export function verifyTrustChain(
  chain: TrustChain,
  opts: VerifyTrustChainOptions = {},
): VerificationResult {
  if (!Array.isArray(chain.chain) || chain.chain.length === 0) {
    return { valid: false, code: "ATP_CHAIN_BROKEN", reason: "empty chain" };
  }
  if (chain.chain.length - 1 !== chain.depth) {
    return {
      valid: false,
      code: "ATP_CHAIN_BROKEN",
      reason: `depth mismatch: chain has ${chain.chain.length} certs but depth=${chain.depth}`,
    };
  }
  if (opts.maxDepth !== undefined && chain.depth > opts.maxDepth) {
    return {
      valid: false,
      code: "ATP_CHAIN_DEPTH_EXCEEDED",
      reason: `depth ${chain.depth} > maxDepth ${opts.maxDepth}`,
    };
  }
  if (certIdOf(chain.chain[0]!) !== chain.rootCertId) {
    return { valid: false, code: "ATP_CHAIN_BROKEN", reason: "rootCertId does not match chain[0]" };
  }

  const details: Array<{ code: VerificationResult["code"] & string; reason: string; index?: number }> = [];

  for (let i = 0; i < chain.chain.length; i++) {
    const cert = chain.chain[i]!;
    const aic = verifyAic(cert, opts);
    if (!aic.valid) {
      details.push({ code: aic.code ?? "ATP_MALFORMED", reason: aic.reason ?? "invalid", index: i });
      continue; // keep collecting, but skip relational checks for this hop
    }

    if (i === 0) {
      // The root cert MUST NOT have a parent.
      if (cert.parentCertId !== undefined) {
        details.push({
          code: "ATP_CHAIN_BROKEN",
          reason: "root cert must not have a parentCertId",
          index: 0,
        });
      }
      continue;
    }

    const parent = chain.chain[i - 1]!;
    const parentId = certIdOf(parent);

    if (cert.parentCertId !== parentId) {
      details.push({
        code: "ATP_CHAIN_BROKEN",
        reason: `chain[${i}].parentCertId (${cert.parentCertId}) != chain[${i - 1}] CertId (${parentId})`,
        index: i,
      });
    }

    // Scope subset
    if (!isScopeSubset(cert.scope, parent.scope)) {
      details.push({
        code: "ATP_SCOPE_WIDENING",
        reason: `chain[${i}] scope is not a subset of chain[${i - 1}] scope`,
        index: i,
      });
    }

    // Issuance window — child must be issued during parent's validity window.
    if (cert.issuedAt < parent.issuedAt) {
      details.push({
        code: "ATP_TEMPORAL_OUT_OF_WINDOW",
        reason: `chain[${i}] issuedAt < parent issuedAt`,
        index: i,
      });
    }
    if (cert.issuedAt > parent.expiresAt) {
      details.push({
        code: "ATP_TEMPORAL_OUT_OF_WINDOW",
        reason: `chain[${i}] issuedAt > parent expiresAt`,
        index: i,
      });
    }

    // Sub-agent depth budget consumed by this hop.
    if (parent.scope.maxSubAgentDepth < chain.chain.length - i) {
      details.push({
        code: "ATP_CHAIN_DEPTH_EXCEEDED",
        reason: `chain[${i - 1}].scope.maxSubAgentDepth too small for descendants`,
        index: i,
      });
    }
  }

  if (details.length > 0) {
    return {
      valid: false,
      code: details[0]!.code,
      reason: details[0]!.reason,
      details,
    };
  }
  return { valid: true };
}

/**
 * Convenience: verify a chain and assert it ends with `expectedLeafCertId`.
 * Useful when the leaf AIC is the one presenting the chain to a peer/tool.
 */
export function verifyChainTerminatesAt(
  chain: TrustChain,
  expectedLeafCertId: CertId,
  opts?: VerifyTrustChainOptions,
): VerificationResult {
  const base = verifyTrustChain(chain, opts);
  if (!base.valid) return base;
  const actual = certIdOf(chain.chain[chain.chain.length - 1]!);
  if (actual !== expectedLeafCertId) {
    return {
      valid: false,
      code: "ATP_CHAIN_BROKEN",
      reason: `chain leaf ${actual} != expected ${expectedLeafCertId}`,
    };
  }
  return { valid: true };
}
