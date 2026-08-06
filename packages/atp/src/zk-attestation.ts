/**
 * zk-attestation.ts — Privacy-preserving pentest trust-score attestations.
 *
 * NAMING PRECISION (per the build brief: "if not real ZK, name it
 * correctly"): this module does NOT implement a general-purpose zero-
 * knowledge proof system (no SNARK/STARK circuit, no arithmetic-circuit
 * satisfiability proof). What it implements is a **commitment-based
 * threshold attestation**, sometimes called a "proof of threshold" or
 * "range disclosure via commitment": the attester commits to the full,
 * private finding set with a salted hash, and separately signs a public
 * *claim* ("trust score >= X") that a verifier can check was produced by
 * a trusted attester over a specific committed dataset — without the
 * verifier ever seeing the findings, their count, their severities, or
 * anything else about them beyond the pass/fail claim.
 *
 * This is precisely the property zero-knowledge proofs are colloquially
 * invoked for in a pentest-reporting context ("prove security posture
 * without revealing vulnerabilities"), and it is a real, sound
 * cryptographic construction — just not the "ZK" family of proof systems
 * in the strict theoretical sense (no simulator/extractor argument, no
 * interactive or non-interactive ZK proof of knowledge of the committed
 * preimage). We call it a **Threshold Trust Attestation (TTA)**
 * throughout the API and docs to avoid overclaiming "zero-knowledge."
 *
 * What a verifier CAN learn:
 *   - The claim: "trust score for commitment C is >= threshold T."
 *   - That the claim is signed by an Ed25519 key the verifier chooses to
 *     trust (the attester — e.g. Lyrie's own scanning pipeline, or a
 *     third-party auditor).
 *   - The commitment hash `findingsCommitment` (a SHA-256 digest) — useful
 *     for the ORIGINAL finding set's owner to later prove, if they choose,
 *     that a specific finding set was the one attested (by revealing the
 *     salt + findings and recomputing the hash) — a classic commit/reveal
 *     scheme layered under the signed claim.
 *
 * What a verifier CANNOT learn from the attestation alone:
 *   - The actual trust score value (only that it clears the threshold).
 *   - Any finding, its severity, category, file path, or count.
 *   - The salt (kept by the attester/prover; never distributed).
 *
 * Built entirely on ATP's existing Ed25519 + canonical-JSON + SHA-256
 * primitives (`crypto.ts`) — no new crypto dependency.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { randomBytes } from "node:crypto";
import { canonicalize, sha256Hex, signCanonical, verifyCanonical } from "./crypto";
import type { VerificationResult } from "./types";
import { ATP_VERSION } from "./types";

export const ZK_ATTESTATION_VERSION = "lyrie-tta-1.0.0";

// ─── Commitment ──────────────────────────────────────────────────────────────

/**
 * Commit to an arbitrary private findings payload with a random salt.
 * `sha256(salt || canonicalize(findings))`. The salt MUST be kept secret
 * by the prover — without it, the commitment cannot be opened, and without
 * opening it, a verifier learns nothing about `findings` from the hash.
 */
export function commitFindings(findings: unknown, salt?: string): { commitment: string; salt: string } {
  const s = salt ?? randomBytes(32).toString("base64");
  const commitment = sha256Hex(`${s}::${canonicalize(findings)}`);
  return { commitment, salt: s };
}

/** Re-open a commitment to verify it matches a revealed (findings, salt) pair. Used only if the prover chooses to later disclose findings out-of-band — never required for the trust-score claim itself. */
export function verifyCommitment(commitment: string, findings: unknown, salt: string): boolean {
  return sha256Hex(`${salt}::${canonicalize(findings)}`) === commitment;
}

// ─── Threshold Trust Attestation ─────────────────────────────────────────────

export interface TrustScoreAttestationBody {
  /** SHA-256 commitment over the private findings set (see `commitFindings`). */
  findingsCommitment: string;
  /** The threshold being claimed as met, e.g. 70 (0-100 scale, matches `lyrie hack --trust-score`). */
  threshold: number;
  /** True iff the attester confirms actualScore >= threshold. Always true for a validly-issued attestation — the attester simply does not ISSUE one when the claim is false. */
  meetsThreshold: true;
  /** Opaque subject identifier the attestation is about (e.g. a repo/commit hash, a domain, an agent id) — never the findings themselves. */
  subject: string;
  /** Unix ms — when the attestation was issued. */
  issuedAt: number;
  /** Unix ms — optional expiry (trust scores go stale as code/threat-intel changes). */
  expiresAt?: number;
  /** Free-form non-sensitive metadata (scanner version, scan scope label). No findings, no counts, no file paths. */
  metadata?: Record<string, string | number | boolean>;
}

export interface TrustScoreAttestation {
  version: typeof ATP_VERSION;
  body: TrustScoreAttestationBody;
  /** Human-readable attester id (e.g. "lyrie-hack-pipeline"). */
  attesterId: string;
  /** Ed25519 public key (base64) of the attester. */
  attesterPublicKey: string;
  /** Ed25519 signature (base64) over canonicalize(body). */
  signature: string;
}

export interface CreateTrustScoreAttestationInput {
  /** The private findings payload driving the real score (never embedded in the output). */
  findings: unknown;
  /** The actual computed trust score (0-100). Compared against `threshold` locally; never included in the output. */
  actualScore: number;
  threshold: number;
  subject: string;
  attesterId: string;
  attesterPrivateKey: string;
  attesterPublicKey: string;
  /** Override issuedAt for testability. */
  issuedAt?: number;
  expiresAt?: number;
  metadata?: Record<string, string | number | boolean>;
  /** Override the random commitment salt for reproducible tests. */
  salt?: string;
}

export type CreateTrustScoreAttestationResult =
  | { ok: true; attestation: TrustScoreAttestation; salt: string }
  | { ok: false; reason: string };

/**
 * Create a Threshold Trust Attestation. Refuses to issue one when
 * `actualScore < threshold` — an attester cannot be tricked into signing a
 * false claim through this API; the caller must lower `threshold` to
 * something actually met, or not issue an attestation at all.
 *
 * Returns the `salt` used for the commitment (input.salt if provided, else
 * freshly generated) so the CALLER can retain it — this module never
 * persists it. If the salt is lost, the commitment can never be opened,
 * which is fine: the attestation itself does not need the salt to verify.
 */
export function createTrustScoreAttestation(
  input: CreateTrustScoreAttestationInput,
): CreateTrustScoreAttestationResult {
  if (input.actualScore < input.threshold) {
    return {
      ok: false,
      reason: `actualScore (${input.actualScore}) does not meet threshold (${input.threshold}) — refusing to issue a false attestation`,
    };
  }
  if (input.threshold < 0 || input.threshold > 100) {
    return { ok: false, reason: "threshold must be within [0, 100]" };
  }

  const { commitment, salt } = commitFindings(input.findings, input.salt);

  const body: TrustScoreAttestationBody = {
    findingsCommitment: commitment,
    threshold: input.threshold,
    meetsThreshold: true,
    subject: input.subject,
    issuedAt: input.issuedAt ?? Date.now(),
    expiresAt: input.expiresAt,
    metadata: input.metadata,
  };

  const signature = signCanonical(body, input.attesterPrivateKey);
  const attestation: TrustScoreAttestation = {
    version: ATP_VERSION,
    body,
    attesterId: input.attesterId,
    attesterPublicKey: input.attesterPublicKey,
    signature,
  };
  return { ok: true, attestation, salt };
}

export interface VerifyTrustScoreAttestationOptions {
  /** Only accept attestations signed by one of these attester public keys. Required — no implicit trust. */
  trustedAttesterPublicKeys: string[];
  /** Reject an attestation whose claimed threshold is below this — lets a verifier require ">= 70" even if a weaker ">= 40" attestation exists for the same subject. */
  minimumThreshold?: number;
  now?: number;
}

export interface TrustScoreAttestationVerification extends VerificationResult {
  /** Convenience echo of the verified claim, only present when valid. */
  claim?: { subject: string; threshold: number };
}

/**
 * Verify a Threshold Trust Attestation WITHOUT any access to the original
 * findings — this is the entire point. A verifier learns only:
 *   "subject S's trust score was attested by a trusted key as >= threshold T,
 *    as of issuedAt, not yet expired."
 */
export function verifyTrustScoreAttestation(
  attestation: TrustScoreAttestation,
  opts: VerifyTrustScoreAttestationOptions,
): TrustScoreAttestationVerification {
  if (!attestation || typeof attestation !== "object" || !attestation.body) {
    return { valid: false, code: "ATP_MALFORMED", reason: "attestation/body must be objects" };
  }
  if (attestation.version !== ATP_VERSION) {
    return { valid: false, code: "ATP_VERSION_MISMATCH", reason: `expected ${ATP_VERSION}` };
  }
  const b = attestation.body;
  if (typeof b.findingsCommitment !== "string" || !b.findingsCommitment) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.findingsCommitment required" };
  }
  if (typeof b.threshold !== "number" || b.threshold < 0 || b.threshold > 100) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.threshold must be within [0,100]" };
  }
  if (b.meetsThreshold !== true) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.meetsThreshold must be true" };
  }
  if (typeof b.subject !== "string" || !b.subject) {
    return { valid: false, code: "ATP_MALFORMED", reason: "body.subject required" };
  }

  if (!opts.trustedAttesterPublicKeys || opts.trustedAttesterPublicKeys.length === 0) {
    return {
      valid: false,
      code: "ATP_PUBLIC_KEY_INVALID",
      reason: "verifyTrustScoreAttestation requires a non-empty trustedAttesterPublicKeys list",
    };
  }
  if (!opts.trustedAttesterPublicKeys.includes(attestation.attesterPublicKey)) {
    return {
      valid: false,
      code: "ATP_PUBLIC_KEY_INVALID",
      reason: `attester public key ${attestation.attesterPublicKey} is not trusted`,
    };
  }

  if (!verifyCanonical(attestation.body, attestation.attesterPublicKey, attestation.signature)) {
    return { valid: false, code: "ATP_SIGNATURE_INVALID", reason: "attestation signature did not verify" };
  }

  const now = opts.now ?? Date.now();
  if (typeof b.expiresAt === "number" && now > b.expiresAt) {
    return { valid: false, code: "ATP_CERT_EXPIRED", reason: `attestation expired at ${b.expiresAt}` };
  }

  if (typeof opts.minimumThreshold === "number" && b.threshold < opts.minimumThreshold) {
    return {
      valid: false,
      code: "ATP_SCOPE_INVALID",
      reason: `attested threshold (${b.threshold}) is below the required minimum (${opts.minimumThreshold})`,
    };
  }

  return { valid: true, claim: { subject: b.subject, threshold: b.threshold } };
}
