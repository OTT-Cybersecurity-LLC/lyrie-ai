/**
 * finding-attestation.ts — Signed Findings (ATP chain of custody).
 *
 * A finding (pentest result, secret-scan hit, or any other structured
 * observation an agent produces) is only as trustworthy as the agent that
 * produced it. Without cryptographic binding, a finding is just JSON —
 * anyone can edit severity, drop context, or fabricate a result after the
 * fact, and no downstream consumer (a human reviewer, a ticketing system, a
 * compliance audit) can tell the difference between "the agent found this"
 * and "someone hand-edited the report."
 *
 * `signFinding` closes that gap by wrapping an arbitrary payload `T` in an
 * Ed25519 signature bound to the issuing agent's AIC. The signature covers
 * the exact payload plus the signer's CertId and the signing timestamp, so
 * any post-hoc mutation of the payload — or any attempt to re-attribute the
 * finding to a different agent — is detectable by `verifySignedFinding`.
 *
 * This module is intentionally generic over `T` and has zero knowledge of
 * any specific finding shape (pentest, secrets, or otherwise) — that keeps
 * `@lyrie/atp` dependency-free and reusable by any consumer, matching the
 * dependency direction declared across the workspace (concrete packages
 * depend on `@lyrie/atp`; `@lyrie/atp` never depends on them).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { isBase64Bytes, signCanonical, verifyCanonical } from "./crypto";
import type {
  AgentIdentityCertificate,
  AtpVersion,
  CertId,
  VerificationResult,
} from "./types";
import { ATP_VERSION } from "./types";
import { certIdOf } from "./aic";

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * SignedFinding — an arbitrary payload `T` wrapped in an ATP Ed25519
 * signature that binds it to the issuing agent's certificate.
 *
 * The signature covers the canonical JSON of every field except
 * `signature` itself, following the same "build unsigned, sign, spread
 * back in" pattern as {@link signReceipt} in `receipt.ts`.
 */
export interface SignedFinding<T> {
  version: AtpVersion;
  /** The finding payload, untouched. */
  payload: T;
  /** CertId of the AIC under which this finding was signed. */
  agentCertId: CertId;
  /** ISO-8601 timestamp of when the signature was created. */
  signedAt: string;
  /** Ed25519 signature (base64) by the agent's private key. */
  signature: string;
}

// ─── Sign ────────────────────────────────────────────────────────────────────

export interface SignFindingInput<T> {
  /** The finding payload to sign. Any JSON-serialisable value. */
  payload: T;
  /** AIC of the agent that produced this finding. */
  cert: AgentIdentityCertificate;
  /** The agent's private key (base64), matching `cert.publicKey`. */
  privateKey: string;
  /** Override the signing timestamp (ISO-8601). Default `new Date().toISOString()` — useful for testability. */
  signedAt?: string;
}

/**
 * The bytes signed by the agent — every field of the wrapper except
 * `signature`. Exposed only for symmetry with `verifySignedFinding`'s
 * rebuild step.
 */
function signedFindingCorePayload<T>(
  wrapper: Omit<SignedFinding<T>, "signature"> | SignedFinding<T>,
): Omit<SignedFinding<T>, "signature"> {
  const w = wrapper as SignedFinding<T>;
  return {
    version: w.version,
    payload: w.payload,
    agentCertId: w.agentCertId,
    signedAt: w.signedAt,
  };
}

/**
 * Sign an arbitrary finding payload under `cert`, producing a
 * tamper-evident `SignedFinding<T>`. Any later mutation of `payload`,
 * `agentCertId`, or `signedAt` invalidates the signature (see
 * {@link verifySignedFinding}).
 */
export function signFinding<T>(input: SignFindingInput<T>): SignedFinding<T> {
  const unsigned: Omit<SignedFinding<T>, "signature"> = {
    version: ATP_VERSION,
    payload: input.payload,
    agentCertId: certIdOf(input.cert),
    signedAt: input.signedAt ?? new Date().toISOString(),
  };
  const signature = signCanonical(signedFindingCorePayload(unsigned), input.privateKey);
  return { ...unsigned, signature };
}

// ─── Verify ──────────────────────────────────────────────────────────────────

/**
 * Verify a `SignedFinding<T>`:
 *   1. structural well-formedness
 *   2. `signed.agentCertId` matches the CertId of the supplied `cert`
 *      (rejects a signature that claims a different signer than the cert
 *      actually presented — checked before the signature itself, same as
 *      other ATP verifiers do for cert binding)
 *   3. the Ed25519 signature is valid against `cert.publicKey` over the
 *      canonical core payload (rejects any tampering with payload,
 *      agentCertId, or signedAt post-signing)
 */
export function verifySignedFinding<T>(
  signed: SignedFinding<T>,
  cert: AgentIdentityCertificate,
): VerificationResult {
  if (!signed || typeof signed !== "object") {
    return { valid: false, code: "ATP_MALFORMED", reason: "signed finding must be object" };
  }
  if (signed.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  if (typeof signed.agentCertId !== "string" || !signed.agentCertId) {
    return { valid: false, code: "ATP_MALFORMED", reason: "agentCertId required" };
  }
  if (typeof signed.signedAt !== "string" || !signed.signedAt) {
    return { valid: false, code: "ATP_MALFORMED", reason: "signedAt required" };
  }
  if (typeof signed.payload === "undefined") {
    return { valid: false, code: "ATP_MALFORMED", reason: "payload required" };
  }
  if (!isBase64Bytes(signed.signature, 64)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "signature not 64 raw bytes" };
  }

  const expectedCertId = certIdOf(cert);
  if (signed.agentCertId !== expectedCertId) {
    return {
      valid: false,
      code: "ATP_RECEIPT_AGENT_MISMATCH",
      reason: `agentCertId ${signed.agentCertId} != cert ${expectedCertId}`,
    };
  }

  const payload = signedFindingCorePayload(signed);
  if (!verifyCanonical(payload, cert.publicKey, signed.signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "finding signature did not verify" };
  }

  return { valid: true };
}
