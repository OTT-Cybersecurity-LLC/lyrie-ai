/**
 * receipt.ts — Action Receipts.
 *
 * The second ATP primitive. Every consequential action an agent takes
 * (tool invocation, API call, file write, payment, message send) emits a
 * signed receipt that:
 *
 *   - identifies the AIC under which the action was taken,
 *   - records the action and its result with timestamps,
 *   - is cryptographically tamper-evident.
 *
 * Receipts are append-only by convention. They form the audit substrate for
 * "did agent X actually do Y?" — a question that, before ATP, no AI system
 * could answer with cryptographic certainty.
 *
 * Optional receiver counter-signatures provide mutual non-repudiation when
 * the receiving system also implements ATP (e.g. Lyrie talking to another
 * Lyrie agent, or to an ATP-aware tool registry).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  isBase64Bytes,
  newUuid,
  signCanonical,
  verifyCanonical,
} from "./crypto";
import type {
  ActionReceipt,
  AgentIdentityCertificate,
  CertId,
  VerificationResult,
} from "./types";
import { ATP_VERSION } from "./types";
import { certIdOf } from "./aic";

// ─── Issue ───────────────────────────────────────────────────────────────────

export interface SignReceiptInput {
  /** AIC of the agent taking the action (used to bind agentCertId + verify caller holds the key). */
  cert: AgentIdentityCertificate;
  /** The agent's private key (base64). */
  privateKey: string;
  action: ActionReceipt["action"];
  result: ActionReceipt["result"];
  /** Optional pre-assigned receiptId. */
  receiptId?: string;
}

/**
 * Sign a fresh Action Receipt under `cert`. The signature covers the canonical
 * JSON of every field except `agentSignature`, `receiverSignature`, and
 * `receiverPublicKey` (counter-sigs are added later, see {@link addReceiverSignature}).
 */
export function signReceipt(input: SignReceiptInput): ActionReceipt {
  const unsigned: Omit<ActionReceipt, "agentSignature"> = {
    version: ATP_VERSION,
    receiptId: input.receiptId ?? newUuid(),
    agentCertId: certIdOf(input.cert),
    action: input.action,
    result: input.result,
  };
  const agentSignature = signCanonical(receiptCorePayload(unsigned), input.privateKey);
  return { ...unsigned, agentSignature };
}

/**
 * The bytes signed by the agent. We strip both signatures and the
 * receiver-public-key from the canonical payload so receiver counter-signing
 * does not invalidate the agent's signature, and vice versa.
 */
function receiptCorePayload(receipt: Omit<ActionReceipt, "agentSignature"> | ActionReceipt) {
  const r = receipt as ActionReceipt;
  return {
    version: r.version,
    receiptId: r.receiptId,
    agentCertId: r.agentCertId,
    action: r.action,
    result: r.result,
  };
}

// ─── Receiver counter-sign ───────────────────────────────────────────────────

/**
 * Add a receiver's counter-signature to an existing receipt. The receiver
 * signs the same core payload as the agent (so signatures are independent
 * but bound to identical content) and embeds its public key for verification.
 */
export function addReceiverSignature(
  receipt: ActionReceipt,
  receiverPrivateKey: string,
  receiverPublicKey: string,
): ActionReceipt {
  if (!isBase64Bytes(receiverPublicKey, 32)) {
    throw new Error("ATP: receiverPublicKey must be 32 raw Ed25519 bytes (base64)");
  }
  const sig = signCanonical(receiptCorePayload(receipt), receiverPrivateKey);
  return { ...receipt, receiverSignature: sig, receiverPublicKey };
}

// ─── Verify ──────────────────────────────────────────────────────────────────

export interface VerifyReceiptOptions {
  /** AIC bound to this receipt; required for signature verification. */
  cert: AgentIdentityCertificate;
  /** If true, also verify the receiver's counter-signature (must be present). */
  requireReceiverSignature?: boolean;
}

/**
 * Verify an Action Receipt:
 *   1. structural well-formedness
 *   2. agentCertId matches the supplied cert's CertId
 *   3. agent signature is valid against the cert's public key
 *   4. (optional) receiver signature is valid against its embedded public key
 */
export function verifyReceipt(receipt: ActionReceipt, opts: VerifyReceiptOptions): VerificationResult {
  if (!receipt || typeof receipt !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "receipt must be object" };
  }
  if (receipt.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  if (typeof receipt.receiptId !== "string" || !receipt.receiptId) {
    return { valid: false, code: "ATP_MALFORMED", reason: "receiptId required" };
  }
  if (typeof receipt.agentCertId !== "string" || !receipt.agentCertId) {
    return { valid: false, code: "ATP_MALFORMED", reason: "agentCertId required" };
  }
  if (!receipt.action || typeof receipt.action !== "object" || typeof receipt.action.tool !== "string") {
    return { valid: false, code: "ATP_MALFORMED", reason: "action.tool required" };
  }
  if (typeof receipt.action.timestamp !== "number" || typeof receipt.result?.timestamp !== "number") {
    return { valid: false, code: "ATP_MALFORMED", reason: "timestamps required" };
  }
  if (typeof receipt.result.success !== "boolean") {
    return { valid: false, code: "ATP_MALFORMED", reason: "result.success required" };
  }
  if (!isBase64Bytes(receipt.agentSignature, 64)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "agentSignature not 64 bytes" };
  }

  const expectedCertId = certIdOf(opts.cert);
  if (receipt.agentCertId !== expectedCertId) {
    return {
      valid: false,
      code: "ATP_RECEIPT_AGENT_MISMATCH",
      reason: `agentCertId ${receipt.agentCertId} != cert ${expectedCertId}`,
    };
  }

  const payload = receiptCorePayload(receipt);
  if (!verifyCanonical(payload, opts.cert.publicKey, receipt.agentSignature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "agent signature did not verify" };
  }

  if (opts.requireReceiverSignature || receipt.receiverSignature !== undefined) {
    if (!receipt.receiverSignature || !receipt.receiverPublicKey) {
      return {
        valid: false,
        code: "ATP_SIGNATURE_INVALID",
        reason: "receiver signature required but missing",
      };
    }
    if (!isBase64Bytes(receipt.receiverPublicKey, 32) || !isBase64Bytes(receipt.receiverSignature, 64)) {
      return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "malformed receiver key/sig" };
    }
    if (!verifyCanonical(payload, receipt.receiverPublicKey, receipt.receiverSignature)) {
      return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "receiver signature did not verify" };
    }
  }

  return { valid: true };
}

// ─── Receipt log helpers ─────────────────────────────────────────────────────

/**
 * Filter a list of receipts to those issued by a specific AIC.
 * Useful for audit queries: "what did agent X do during incident Y?"
 */
export function receiptsForCert(receipts: ActionReceipt[], certId: CertId): ActionReceipt[] {
  return receipts.filter((r) => r.agentCertId === certId);
}
