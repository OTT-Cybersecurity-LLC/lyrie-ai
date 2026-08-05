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
export { ATP_VERSION, ATP_VERSION_2 } from "./types";

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

// ─── Delegation (v2) ─────────────────────────────────────────────────────────
export {
  createDelegation,
  verifyDelegation,
  verifyDelegationChain,
} from "./delegation";
export type { DelegationCertificate } from "./delegation";

// ─── Revocation (v2) ─────────────────────────────────────────────────────────
export {
  createRevocationList,
  isRevoked,
  safeIsRevoked,
  addRevocation,
  verifyRevocationList,
} from "./revocation";
export type { RevocationEntry, RevocationList, RevocationReason } from "./revocation";

// ─── Multi-Sig (v2) ──────────────────────────────────────────────────────────
export {
  createMultiSigRequest,
  addSignature,
  isAuthorized,
} from "./multisig";
export type { MultiSigRequest } from "./multisig";

// ─── Vaccine propagation (cross-agent signed rule push/pull) ────────────────
export {
  signVaccineRule,
  verifyVaccineRule,
  recordVaccineIngest,
  newVaccineRuleId,
  VaccineStore,
  VaccinePublisher,
  VaccineSubscriber,
  VACCINE_VERSION,
} from "./vaccine";
export type {
  VaccineRuleKind,
  VaccineSeverity,
  VaccineRuleBody,
  SignedVaccineRule,
  SignVaccineRuleInput,
  VerifyVaccineRuleOptions,
  RecordVaccineIngestInput,
  VaccineTransport,
  VaccineSubscriberHandler,
  VaccineSubscriberOptions,
  VaccineIngestResult,
} from "./vaccine";

// ─── Kill-switch (signed quarantine broadcast) ───────────────────────────────
export {
  signKillSwitchOrder,
  verifyKillSwitchOrder,
  recordKillSwitchEnforcement,
  KillSwitchBroadcaster,
  KillSwitchEnforcer,
  KILL_SWITCH_VERSION,
} from "./kill-switch";
export type {
  KillSwitchAction,
  KillSwitchOrderBody,
  SignedKillSwitchOrder,
  SignKillSwitchOrderInput,
  VerifyKillSwitchOrderOptions,
  RecordKillSwitchEnforcementInput,
  KillSwitchEnforcementHook,
  KillSwitchEnforcerOptions,
} from "./kill-switch";

// ─── Zero-knowledge-style pentest attestation ────────────────────────────────
export {
  createTrustScoreAttestation,
  verifyTrustScoreAttestation,
  ZK_ATTESTATION_VERSION,
} from "./zk-attestation";
export type {
  TrustScoreAttestation,
  CreateTrustScoreAttestationInput,
  VerifyTrustScoreAttestationOptions,
  TrustScoreAttestationVerification,
} from "./zk-attestation";
