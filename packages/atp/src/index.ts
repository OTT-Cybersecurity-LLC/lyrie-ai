/**
 * @lyrie/atp — Agent Trust Protocol v1.0 reference implementation.
 *
 * Public exports only. Submodules are internal — import from this entry
 * point so future re-organisation does not break consumers.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Types ───────────────────────────────────────────────────────────────────
export type {
  AgentIdentityCertificate,
  ActionReceipt,
  AgentState,
  AtpKeyPair,
  AtpVersion,
  BreachAttestation,
  CertId,
  ComplianceLevel,
  ScopeDeclaration,
  TrustChain,
  VerificationErrorCode,
  VerificationResult,
} from "./types";
export { ATP_VERSION } from "./types";

// ─── Crypto helpers (curated public surface) ─────────────────────────────────
export { generateKeyPair, sha256Hex, sha256BytesHex, canonicalize } from "./crypto";

// ─── AIC ─────────────────────────────────────────────────────────────────────
export {
  issueAic,
  certIdOf,
  verifyAic,
  RevocationRegistry,
} from "./aic";
export type { IssueAicInput, IssueAicResult, VerifyAicOptions } from "./aic";

// ─── Receipts ────────────────────────────────────────────────────────────────
export {
  signReceipt,
  addReceiverSignature,
  verifyReceipt,
  receiptsForCert,
} from "./receipt";
export type { SignReceiptInput, VerifyReceiptOptions } from "./receipt";

// ─── Scope (SDL) ─────────────────────────────────────────────────────────────
export {
  makeScope,
  parseScope,
  validateScope,
  isScopeSubset,
  mergeScopes,
  domainCovers,
  checkToolAllowed,
  checkDomainAllowed,
  checkTemporallyValid,
} from "./scope";
export type { ToolDecision } from "./scope";

// ─── Trust Chain ─────────────────────────────────────────────────────────────
export {
  buildTrustChain,
  verifyTrustChain,
  verifyChainTerminatesAt,
} from "./trust-chain";
export type { VerifyTrustChainOptions } from "./trust-chain";

// ─── Breach Attestation ──────────────────────────────────────────────────────
export {
  attestState,
  addAttestorSignature,
  verifyAttestation,
  hashAgentState,
  attestationHash,
  verifyAttestationChain,
} from "./breach";
export type { AttestStateInput, VerifyAttestationOptions } from "./breach";

// ─── Cross-primitive verification ────────────────────────────────────────────
export { verifyArtifact, detectArtifactKind } from "./verify";
export type { AtpArtifact, AtpVerifyContext } from "./verify";

// ─── Badge ───────────────────────────────────────────────────────────────────
export { generateBadge } from "./badge";
export type { BadgeOptions, BadgeOutput } from "./badge";
