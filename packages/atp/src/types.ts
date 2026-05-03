/**
 * ATP — Agent Trust Protocol v1.0
 *
 * Type definitions for the five ATP primitives:
 *   1. Agent Identity Certificate (AIC)
 *   2. Action Receipt
 *   3. Scope Declaration (SDL)
 *   4. Trust Chain
 *   5. Breach Attestation
 *
 * These types are the wire format. They are intentionally JSON-serialisable,
 * deterministic, and flat — no class instances, no Date objects, no Buffers.
 * Crypto uses Ed25519 throughout. All keys/signatures are base64-encoded
 * (standard, not URL-safe, not PEM) for cross-language interop.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

/** Protocol version this implementation produces and validates. */
export const ATP_VERSION = "1.0" as const;
export type AtpVersion = typeof ATP_VERSION;

// ─── Scope Declaration Language (SDL) ────────────────────────────────────────

/**
 * ScopeDeclaration — what an agent is authorised to do.
 *
 * Trust Chain rule: a child agent's scope MUST be a subset of its parent's
 * (see {@link mergeScopes}, {@link verifyTrustChain}). This is the invariant
 * that prevents the "spawn a sub-agent with broader powers" attack class.
 */
export interface ScopeDeclaration {
  version: AtpVersion;

  /** Allow-list of tools the agent may invoke. Empty array = no tools allowed. */
  allowedTools: string[];

  /** Optional explicit deny-list. Deny always wins over allow. */
  deniedTools?: string[];

  /**
   * Optional allow-list of network domains. Globs supported (`*.example.com`).
   * Absence means no network restriction is encoded by the scope (the engine's
   * default policy decides). Presence means: only these domains.
   */
  allowedDomains?: string[];

  /** How many levels of sub-agent spawning the holder may initiate. 0 = none. */
  maxSubAgentDepth: number;

  /** Tools that require a human approval signal before execution. */
  requireApprovalFor?: string[];

  /** Time-bound scoping. */
  temporalScope?: {
    /** Unix ms — earliest time the scope becomes valid. */
    validFrom?: number;
    /** Unix ms — last instant the scope is valid. */
    validUntil?: number;
    /** Allowed UTC hours-of-day (0–23). Empty array = no temporal hour gate. */
    allowedHours?: number[];
  };

  /** Data classification scoping. */
  dataScope?: {
    /** Labels the agent may read/write (e.g. "public", "internal"). */
    allowedLabels?: string[];
    /** Labels explicitly forbidden (e.g. "secret", "pii"). */
    deniedLabels?: string[];
  };
}

// ─── Agent Identity Certificate (AIC) ────────────────────────────────────────

/**
 * AgentIdentityCertificate — the "passport" for an agent instance.
 *
 * Self-signed at issue time. The holder of `publicKey`'s matching private key
 * is the agent. The signature covers the canonical JSON of every other field
 * (signature itself excluded) using Ed25519.
 */
export interface AgentIdentityCertificate {
  version: AtpVersion;

  /** UUID v4 for this agent instance. */
  agentId: string;

  /** Logical model identifier, e.g. "anthropic/claude-sonnet-4-6". */
  modelId: string;

  /**
   * Optional SHA-256 (hex) of the model weights for local/open-weight models.
   * Hosted models without weight access leave this undefined.
   */
  modelHash?: string;

  /** SHA-256 (hex) of the system prompt at agent initialisation time. */
  systemPromptHash: string;

  /** What this agent is authorised to do. */
  scope: ScopeDeclaration;

  /** Identifier of the human/org responsible for this agent. */
  operatorId: string;

  /** Unix ms — when the certificate was issued. */
  issuedAt: number;

  /** Unix ms — when the certificate expires. */
  expiresAt: number;

  /** Ed25519 public key, base64-standard encoded (32 raw bytes → 44 chars). */
  publicKey: string;

  /** Ed25519 signature over the canonical JSON of all other fields. */
  signature: string;

  /** If this agent was spawned by another agent: parent AIC's certId. */
  parentCertId?: string;
}

/** Stable certificate identifier — SHA-256 (hex) of the canonical signed bytes. */
export type CertId = string;

// ─── Action Receipt ──────────────────────────────────────────────────────────

/**
 * ActionReceipt — tamper-proof record that an agent took an action.
 *
 * Signed by the agent's private key. The optional `receiverSignature` is a
 * counter-signature from the tool/API that received the action, providing
 * mutual non-repudiation when the receiver implements ATP.
 */
export interface ActionReceipt {
  version: AtpVersion;

  /** UUID v4 for this receipt. */
  receiptId: string;

  /** CertId of the AIC under which this action was taken. */
  agentCertId: CertId;

  /** What the agent did. */
  action: {
    /** Tool/action name (e.g. "send_email", "shell_exec"). */
    tool: string;
    /**
     * Action parameters. SHOULD NOT contain secrets — use param hashes
     * (`{ to_hash: "sha256:..." }`) when secrets are unavoidable.
     */
    params: Record<string, unknown>;
    /** Unix ms — when the action was attempted. */
    timestamp: number;
  };

  /** Outcome. */
  result: {
    success: boolean;
    /** Non-sensitive human-readable summary of the result. */
    summary: string;
    /** Unix ms — when the result was observed. */
    timestamp: number;
  };

  /** Ed25519 signature by the agent's private key. */
  agentSignature: string;

  /** Optional Ed25519 signature by the receiver (mutual non-repudiation). */
  receiverSignature?: string;

  /** Optional public key of the receiver (base64). Required if receiverSignature is set. */
  receiverPublicKey?: string;
}

// ─── Trust Chain ─────────────────────────────────────────────────────────────

/**
 * TrustChain — a verified, ordered ancestry of AICs from root → leaf.
 *
 * Cryptographic invariants (enforced by {@link verifyTrustChain}):
 *   1. Each child's `parentCertId` matches its predecessor's CertId.
 *   2. Each AIC's signature is valid over its own contents.
 *   3. Each child's scope is a subset of its parent's scope.
 *   4. Each child's `issuedAt` is within its parent's validity window.
 *   5. `chain.length === depth + 1` (root is depth 0).
 */
export interface TrustChain {
  rootCertId: CertId;
  chain: AgentIdentityCertificate[];
  depth: number;
}

// ─── Breach Attestation ──────────────────────────────────────────────────────

/**
 * BreachAttestation — a signed snapshot of agent state, used to detect tampering.
 *
 * `stateHash` covers (in canonical order): systemPromptHash, memoryHash,
 * toolCallHistoryHash. If the agent has been hijacked since the last
 * attestation, recomputing the state hash will diverge and verification fails.
 *
 * Attestations form a hash chain via `previousHash` for forensic auditability.
 */
export interface BreachAttestation {
  version: AtpVersion;

  /** AgentId from the corresponding AIC. */
  agentId: string;

  /** Unix ms — when the attestation was generated. */
  attestedAt: number;

  /** SHA-256 (hex) of canonical-encoded state inputs. */
  stateHash: string;

  /** Hash of the previous attestation in the chain (hex SHA-256). */
  previousHash?: string;

  /** Ed25519 signature by the agent's private key. */
  signature: string;

  /** Optional third-party attestor identifier (e.g. "lyrie-verification-service"). */
  attestorId?: string;

  /** Optional Ed25519 counter-signature from the attestor. */
  attestorSignature?: string;

  /** Optional attestor public key (base64). Required if attestorSignature is set. */
  attestorPublicKey?: string;
}

/**
 * The state inputs that {@link attestState} hashes together. Ordering is
 * fixed; clients must always supply the same shape so hashes are reproducible.
 */
export interface AgentState {
  systemPromptHash: string;
  /** SHA-256 (hex) over the canonical memory snapshot. */
  memoryHash: string;
  /** SHA-256 (hex) over the canonical tool-call history. */
  toolCallHistoryHash: string;
}

// ─── Verification Results ────────────────────────────────────────────────────

/** Generic validation result used by every ATP verifier. */
export interface VerificationResult {
  valid: boolean;
  /** Machine-readable error code on failure. */
  code?: VerificationErrorCode;
  /** Human-readable reason. */
  reason?: string;
  /** Optional sub-results (e.g. trust-chain link errors). */
  details?: Array<{ code: VerificationErrorCode; reason: string; index?: number }>;
}

/**
 * Stable verification error codes. Treat as part of the public API — adding
 * new ones is non-breaking, renaming existing ones is breaking.
 */
export type VerificationErrorCode =
  | "ATP_VERSION_MISMATCH"
  | "ATP_SIGNATURE_INVALID"
  | "ATP_PUBLIC_KEY_INVALID"
  | "ATP_CERT_EXPIRED"
  | "ATP_CERT_NOT_YET_VALID"
  | "ATP_CERT_REVOKED"
  | "ATP_SCOPE_INVALID"
  | "ATP_SCOPE_WIDENING"
  | "ATP_CHAIN_BROKEN"
  | "ATP_CHAIN_DEPTH_EXCEEDED"
  | "ATP_RECEIPT_AGENT_MISMATCH"
  | "ATP_ATTESTATION_DRIFT"
  | "ATP_ATTESTATION_CHAIN_BROKEN"
  | "ATP_TEMPORAL_OUT_OF_WINDOW"
  | "ATP_TOOL_NOT_ALLOWED"
  | "ATP_DOMAIN_NOT_ALLOWED"
  | "ATP_MALFORMED";

// ─── Key Pairs ───────────────────────────────────────────────────────────────

/** Ed25519 key pair, both halves base64-standard encoded. */
export interface AtpKeyPair {
  publicKey: string;
  privateKey: string;
}

// ─── Compliance Levels ───────────────────────────────────────────────────────

/**
 * ATP compliance levels — see Appendix B of the RFC.
 *
 * BASIC:    AIC + Action Receipts. The minimum.
 * STANDARD: BASIC + SDL + Trust Chain enforcement.
 * FULL:     STANDARD + periodic Breach Attestation.
 */
export type ComplianceLevel = "ATP-Basic" | "ATP-Standard" | "ATP-Full";
