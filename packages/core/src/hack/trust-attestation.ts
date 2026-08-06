/**
 * Lyrie Hack — Trust Attestation (integration layer).
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * NAMING PRECISION (inherited from `@lyrie/atp`'s zk-attestation.ts — see
 * that file's header for the full rationale): this module does NOT wire up
 * a general-purpose zero-knowledge proof system. It is a thin integration
 * layer over ATP's **Threshold Trust Attestation (TTA)** primitive — a
 * commitment-based "prove security posture without revealing findings"
 * construction (salted-hash commitment + Ed25519-signed threshold claim).
 * It is a real, sound cryptographic construction, but it is not the "ZK"
 * family of proof systems in the strict theoretical sense (no
 * simulator/extractor argument, no SNARK/STARK circuit). This layer must
 * not, and does not, describe itself as "zero-knowledge" anywhere in its
 * docs or output — only as a Threshold Trust Attestation.
 *
 * PURPOSE: connects the already-complete `@lyrie/atp` TTA primitives
 * (`commitFindings`, `createTrustScoreAttestation`,
 * `verifyTrustScoreAttestation`, `verifyCommitment`) to Lyrie Hack's actual
 * pentest trust-score pipeline (`HackReport` + `TrustScoreBreakdown`), so a
 * scan's private findings can be committed to and a public "trust score >=
 * threshold" claim can be signed and later verified — without ever
 * publishing the findings themselves.
 *
 * What gets committed: `report.validatedFindings` (the confirmed/unconfirmed
 * pentest findings from Stages A-F) plus `report.secretFindings` (hardcoded
 * secrets) — i.e. exactly the two finding sets `computeTrustScore` draws its
 * deductions from. This keeps the commitment's scope aligned 1:1 with what
 * the attested claim is actually about.
 *
 * SAFETY: this module refuses to help produce a signed false claim. Even
 * though `createTrustScoreAttestation` (the underlying ATP primitive)
 * already guards against `actualScore < threshold` internally, this layer
 * adds its own explicit, redundant pre-check with a clear thrown error —
 * belt-and-suspenders, and it fails fast with a Lyrie-domain-specific
 * message (mentioning the report/subject) before ever touching the crypto
 * layer.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  commitFindings,
  createTrustScoreAttestation,
  verifyCommitment,
  verifyTrustScoreAttestation,
  type AgentIdentityCertificate,
  type CreateTrustScoreAttestationResult,
  type TrustScoreAttestation,
  type TrustScoreAttestationVerification,
  type VerifyTrustScoreAttestationOptions,
} from "@lyrie/atp";
import type { HackReport } from "./report-engine";
import type { TrustScoreBreakdown } from "./trust-score";

export const TRUST_ATTESTATION_VERSION = "lyrie-trust-attestation-1.0.0";

/** The private finding payload a `HackReport` commits to when attesting a threshold claim. */
export interface TrustAttestationFindings {
  validatedFindings: HackReport["validatedFindings"];
  secretFindings: HackReport["secretFindings"];
}

/** Build the exact findings payload committed by `attestTrustThreshold`, for reuse by `revealTrustCommitment`. */
function findingsPayloadOf(report: HackReport): TrustAttestationFindings {
  return {
    validatedFindings: report.validatedFindings,
    secretFindings: report.secretFindings,
  };
}

export interface AttestTrustThresholdInput {
  /** The full pentest report — its findings drive the commitment; they are never embedded in the output. */
  report: HackReport;
  /** The pre-computed breakdown for `report` (caller must pass the matching one — not recomputed here to keep this a pure wiring layer, not a scoring engine). */
  breakdown: TrustScoreBreakdown;
  /** The threshold being claimed as met, 0-100 (matches `lyrie hack --trust-score`). */
  threshold: number;
  /** Attester's Agent Identity Certificate — supplies `attesterId` (agentId) and `attesterPublicKey`. */
  cert: AgentIdentityCertificate;
  /** Attester's Ed25519 private key (base64), used to sign the threshold claim. Never included in the output. */
  privateKey: string;
  /** Override issuedAt for testability. */
  issuedAt?: number;
  /** Optional expiry — trust scores go stale as code/threat-intel changes. */
  expiresAt?: number;
  /** Non-sensitive metadata (scanner version, scan scope label). No findings, no counts, no file paths. */
  metadata?: Record<string, string | number | boolean>;
  /** Override the random commitment salt for reproducible tests. */
  salt?: string;
}

export type AttestTrustThresholdResult =
  | { ok: true; attestation: TrustScoreAttestation; salt: string }
  | { ok: false; reason: string };

/**
 * Attest that `report`'s trust score clears `threshold`, without revealing
 * any finding. Commits to `report.validatedFindings` + `report.secretFindings`
 * with a fresh (or caller-supplied) salt, then signs the public claim via
 * `@lyrie/atp`'s `createTrustScoreAttestation`.
 *
 * Refuses to issue an attestation when `breakdown.score < threshold`: this
 * check is enforced BOTH here (fast, Lyrie-domain error message, before any
 * crypto work) AND inside `createTrustScoreAttestation` itself (ATP's own
 * guard) — so a caller cannot bypass the refusal by calling the ATP
 * primitive directly instead of this wrapper, and cannot trick this wrapper
 * into signing a false claim even if the ATP-level guard were ever removed.
 *
 * `report.target` is used as the attestation's `subject` and `cert.agentId`
 * as its `attesterId` — this ties the claim to both "what was scanned" and
 * "which certified agent scanned it."
 */
export function attestTrustThreshold(input: AttestTrustThresholdInput): AttestTrustThresholdResult {
  if (input.breakdown.score < input.threshold) {
    return {
      ok: false,
      reason:
        `refusing to attest: report "${input.report.target}" trust score ` +
        `(${input.breakdown.score}) does not meet threshold (${input.threshold})`,
    };
  }

  const result: CreateTrustScoreAttestationResult = createTrustScoreAttestation({
    findings: findingsPayloadOf(input.report),
    actualScore: input.breakdown.score,
    threshold: input.threshold,
    subject: input.report.target,
    attesterId: input.cert.agentId,
    attesterPrivateKey: input.privateKey,
    attesterPublicKey: input.cert.publicKey,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    metadata: input.metadata,
    salt: input.salt,
  });

  if (!result.ok) {
    // Only reachable if ATP's own guard rejects for a reason other than the
    // one already checked above (e.g. an out-of-range threshold).
    return { ok: false, reason: result.reason };
  }

  return { ok: true, attestation: result.attestation, salt: result.salt };
}

/**
 * Verify a Threshold Trust Attestation produced by `attestTrustThreshold`.
 * Thin wrapper over `@lyrie/atp`'s `verifyTrustScoreAttestation` — a
 * verifier learns only "subject's trust score was attested by a trusted key
 * as >= threshold," never the findings or the actual score.
 */
export function verifyTrustAttestation(
  attestation: TrustScoreAttestation,
  expectedAttesterPublicKey: string,
  opts: Omit<VerifyTrustScoreAttestationOptions, "trustedAttesterPublicKeys"> = {},
): TrustScoreAttestationVerification {
  return verifyTrustScoreAttestation(attestation, {
    ...opts,
    trustedAttesterPublicKeys: [expectedAttesterPublicKey],
  });
}

export interface RevealTrustCommitmentInput {
  /** The report whose findings are being revealed to match against a previously published commitment. */
  report: HackReport;
  /** The commitment hash to check against (typically `attestation.body.findingsCommitment`). */
  commitment: string;
  /** The salt used at commit time (from `attestTrustThreshold`'s returned `salt`). */
  salt: string;
}

/**
 * Reveal half of the commit/reveal scheme: proves, after the fact, that a
 * specific `HackReport`'s findings are exactly the ones a previously
 * published `commitment` hash was committed to. Thin wrapper over
 * `@lyrie/atp`'s `verifyCommitment` — does not reimplement the hash
 * comparison. Returns `false` for any tampering (added/removed/modified
 * finding) since the committed payload's canonical form changes.
 */
export function revealTrustCommitment(input: RevealTrustCommitmentInput): boolean {
  return verifyCommitment(input.commitment, findingsPayloadOf(input.report), input.salt);
}
