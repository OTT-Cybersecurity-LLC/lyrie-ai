/**
 * breach.ts — Breach Attestation.
 *
 * The fifth ATP primitive. A Breach Attestation is a periodic, signed
 * snapshot of an agent's runtime state. Continuous attestation gives auditors
 * a way to detect post-issuance tampering: if a hijacker mutates the agent's
 * system prompt, memory, or tool-call history, the recomputed state hash
 * will diverge from the last-attested value and verification will fail.
 *
 * Attestations form a hash chain (`previousHash`) so any inserted/removed
 * attestation breaks the chain — analogous to a transparency log entry.
 *
 * The model says nothing about HOW to canonicalise memory and tool history
 * — that is application-specific. ATP only requires SHA-256 hex inputs, so
 * Lyrie (or any other implementer) chooses its own canonicalisation policy.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { canonicalize, isBase64Bytes, sha256Hex, signCanonical, verifyCanonical } from "./crypto";
import type {
  AgentIdentityCertificate,
  AgentState,
  BreachAttestation,
  VerificationResult,
} from "./types";
import { ATP_VERSION } from "./types";

// ─── State hashing ───────────────────────────────────────────────────────────

/**
 * Compute the canonical state hash that goes into the attestation. Inputs
 * are joined deterministically; ordering is fixed by the AgentState type.
 */
export function hashAgentState(state: AgentState): string {
  return sha256Hex(canonicalize({
    systemPromptHash: state.systemPromptHash,
    memoryHash: state.memoryHash,
    toolCallHistoryHash: state.toolCallHistoryHash,
  }));
}

// ─── Issue ───────────────────────────────────────────────────────────────────

export interface AttestStateInput {
  cert: AgentIdentityCertificate;
  /** Agent's private key (base64). */
  privateKey: string;
  state: AgentState;
  /** Hex SHA-256 of the previous attestation in the chain. */
  previousHash?: string;
  /** Override timestamp for testability. */
  attestedAt?: number;
}

/**
 * Generate and sign a fresh Breach Attestation.
 */
export function attestState(input: AttestStateInput): BreachAttestation {
  const stateHash = hashAgentState(input.state);
  const unsigned: Omit<BreachAttestation, "signature"> = {
    version: ATP_VERSION,
    agentId: input.cert.agentId,
    attestedAt: input.attestedAt ?? Date.now(),
    stateHash,
    previousHash: input.previousHash,
  };
  const signature = signCanonical(attestationCorePayload(unsigned), input.privateKey);
  return { ...unsigned, signature };
}

function attestationCorePayload(att: Omit<BreachAttestation, "signature"> | BreachAttestation) {
  return {
    version: att.version,
    agentId: att.agentId,
    attestedAt: att.attestedAt,
    stateHash: att.stateHash,
    previousHash: att.previousHash,
  };
}

// ─── Attestor counter-sign ───────────────────────────────────────────────────

/**
 * Add a third-party attestor counter-signature (e.g. Lyrie verification
 * service vouching for a hosted agent's state).
 */
export function addAttestorSignature(
  attestation: BreachAttestation,
  attestorId: string,
  attestorPrivateKey: string,
  attestorPublicKey: string,
): BreachAttestation {
  if (!isBase64Bytes(attestorPublicKey, 32)) {
    throw new Error("ATP: attestorPublicKey must be 32 raw Ed25519 bytes (base64)");
  }
  const sig = signCanonical(attestationCorePayload(attestation), attestorPrivateKey);
  return { ...attestation, attestorId, attestorSignature: sig, attestorPublicKey };
}

// ─── Verify ──────────────────────────────────────────────────────────────────

export interface VerifyAttestationOptions {
  /** AIC under which the agent signed this attestation. */
  cert: AgentIdentityCertificate;
  /**
   * Expected state hash. If provided and it differs from the attestation's,
   * we return ATP_ATTESTATION_DRIFT — indicating tampering or a stale
   * attestation. If absent, signature is verified but drift is not.
   */
  expectedStateHash?: string;
  /** Expected previousHash (audits the chain). */
  expectedPreviousHash?: string;
  /** Require an attestor counter-signature. */
  requireAttestor?: boolean;
}

/**
 * Verify a BreachAttestation:
 *   1. structural well-formedness
 *   2. agentId matches the supplied cert
 *   3. agent signature is valid against the cert's public key
 *   4. (optional) stateHash equals expectedStateHash
 *   5. (optional) previousHash equals expectedPreviousHash
 *   6. (optional) attestor signature verifies
 */
export function verifyAttestation(
  att: BreachAttestation,
  opts: VerifyAttestationOptions,
): VerificationResult {
  if (!att || typeof att !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "attestation must be object" };
  }
  if (att.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  if (att.agentId !== opts.cert.agentId) {
    return {
      valid: false,
      code: "ATP_MALFORMED",
      reason: `agentId ${att.agentId} != cert.agentId ${opts.cert.agentId}`,
    };
  }
  if (typeof att.stateHash !== "string" || !/^[0-9a-f]{64}$/.test(att.stateHash)) {
    return { valid: false, code: "ATP_MALFORMED", reason: "stateHash must be 64-char lowercase hex" };
  }
  if (typeof att.attestedAt !== "number") {
    return { valid: false, code: "ATP_MALFORMED", reason: "attestedAt must be number" };
  }
  if (!isBase64Bytes(att.signature, 64)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "signature not 64 bytes" };
  }

  if (!verifyCanonical(attestationCorePayload(att), opts.cert.publicKey, att.signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "agent signature did not verify" };
  }

  if (opts.expectedStateHash !== undefined && opts.expectedStateHash !== att.stateHash) {
    return {
      valid: false,
      code: "ATP_ATTESTATION_DRIFT",
      reason: `state hash drift: expected ${opts.expectedStateHash}, got ${att.stateHash}`,
    };
  }
  if (
    opts.expectedPreviousHash !== undefined &&
    opts.expectedPreviousHash !== (att.previousHash ?? "")
  ) {
    return {
      valid: false,
      code: "ATP_ATTESTATION_CHAIN_BROKEN",
      reason: `previousHash mismatch`,
    };
  }

  if (opts.requireAttestor || att.attestorSignature !== undefined) {
    if (!att.attestorSignature || !att.attestorPublicKey) {
      return {
        valid: false,
        code: "ATP_SIGNATURE_INVALID",
        reason: "attestor signature required but missing",
      };
    }
    if (!isBase64Bytes(att.attestorPublicKey, 32) || !isBase64Bytes(att.attestorSignature, 64)) {
      return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "malformed attestor key/sig" };
    }
    if (
      !verifyCanonical(attestationCorePayload(att), att.attestorPublicKey, att.attestorSignature)
    ) {
      return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "attestor signature did not verify" };
    }
  }

  return { valid: true };
}

// ─── Chain helpers ───────────────────────────────────────────────────────────

/** Hex SHA-256 of an attestation's canonical signed form — the value the next attestation should put in `previousHash`. */
export function attestationHash(att: BreachAttestation): string {
  return sha256Hex(canonicalize(att));
}

/**
 * Verify a temporally-ordered list of attestations from the same agent.
 * Each attestation must reference the previous one's hash via `previousHash`,
 * and `attestedAt` must be non-decreasing.
 */
export function verifyAttestationChain(
  chain: BreachAttestation[],
  cert: AgentIdentityCertificate,
): VerificationResult {
  if (chain.length === 0) {
    return { valid: false, code: "ATP_MALFORMED", reason: "empty attestation chain" };
  }
  let prevHash: string | undefined;
  let prevTime = -Infinity;
  for (let i = 0; i < chain.length; i++) {
    const att = chain[i]!;
    const single = verifyAttestation(att, {
      cert,
      expectedPreviousHash: prevHash,
    });
    if (!single.valid) {
      return { ...single, details: [{ code: single.code!, reason: single.reason!, index: i }] };
    }
    if (att.attestedAt < prevTime) {
      return {
        valid: false,
        code: "ATP_ATTESTATION_CHAIN_BROKEN",
        reason: `attestation[${i}].attestedAt went backwards`,
      };
    }
    prevTime = att.attestedAt;
    prevHash = attestationHash(att);
  }
  return { valid: true };
}
