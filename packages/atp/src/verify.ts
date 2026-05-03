/**
 * verify.ts — Cross-primitive verification entry point.
 *
 * One function to rule them all: pass any ATP artifact and an optional
 * verification context, get a VerificationResult. Wraps the per-primitive
 * verifiers with a discriminator so callers don't have to know which
 * primitive type they're holding.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type {
  ActionReceipt,
  AgentIdentityCertificate,
  BreachAttestation,
  ScopeDeclaration,
  TrustChain,
  VerificationResult,
} from "./types";
import { verifyAic, type VerifyAicOptions } from "./aic";
import { verifyReceipt, type VerifyReceiptOptions } from "./receipt";
import { verifyTrustChain, type VerifyTrustChainOptions } from "./trust-chain";
import { verifyAttestation, type VerifyAttestationOptions } from "./breach";
import { validateScope } from "./scope";

export type AtpArtifact =
  | { kind: "aic"; cert: AgentIdentityCertificate }
  | { kind: "receipt"; receipt: ActionReceipt }
  | { kind: "scope"; scope: ScopeDeclaration }
  | { kind: "trust-chain"; chain: TrustChain }
  | { kind: "attestation"; attestation: BreachAttestation };

export type AtpVerifyContext =
  | { kind: "aic"; opts?: VerifyAicOptions }
  | { kind: "receipt"; opts: VerifyReceiptOptions }
  | { kind: "scope" }
  | { kind: "trust-chain"; opts?: VerifyTrustChainOptions }
  | { kind: "attestation"; opts: VerifyAttestationOptions };

/**
 * Verify any ATP artifact. The artifact and context kinds must match.
 */
export function verifyArtifact(
  artifact: AtpArtifact,
  context?: AtpVerifyContext,
): VerificationResult {
  if (context && context.kind !== artifact.kind) {
    return {
      valid: false,
      code: "ATP_MALFORMED",
      reason: `artifact kind ${artifact.kind} != context kind ${context.kind}`,
    };
  }
  switch (artifact.kind) {
    case "aic":
      return verifyAic(artifact.cert, context?.kind === "aic" ? context.opts : undefined);
    case "receipt": {
      if (!context || context.kind !== "receipt") {
        return { valid: false, code: "ATP_MALFORMED", reason: "receipt requires verify context with cert" };
      }
      return verifyReceipt(artifact.receipt, context.opts);
    }
    case "scope":
      return validateScope(artifact.scope);
    case "trust-chain":
      return verifyTrustChain(artifact.chain, context?.kind === "trust-chain" ? context.opts : undefined);
    case "attestation": {
      if (!context || context.kind !== "attestation") {
        return { valid: false, code: "ATP_MALFORMED", reason: "attestation requires verify context with cert" };
      }
      return verifyAttestation(artifact.attestation, context.opts);
    }
  }
}

/**
 * Best-effort artifact discriminator — sniffs which ATP primitive a JSON
 * blob is. Returns null if unrecognised. Useful for decoders that load
 * mixed audit logs and need to dispatch.
 */
export function detectArtifactKind(value: unknown): AtpArtifact["kind"] | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if ("agentSignature" in v && "action" in v && "result" in v) return "receipt";
  if ("stateHash" in v && "attestedAt" in v) return "attestation";
  if ("chain" in v && "rootCertId" in v) return "trust-chain";
  if ("publicKey" in v && "signature" in v && "scope" in v) return "aic";
  if ("allowedTools" in v && "maxSubAgentDepth" in v) return "scope";
  return null;
}
