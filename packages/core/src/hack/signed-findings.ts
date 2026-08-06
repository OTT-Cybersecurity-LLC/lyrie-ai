/**
 * Lyrie Hack — Signed Findings (integration layer).
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Thin integration layer over `@lyrie/atp`'s generic `signFinding` /
 * `verifySignedFinding` primitives (see `packages/atp/src/finding-attestation.ts`),
 * wired to Lyrie Hack's actual pentest finding types (`ValidatedFinding`,
 * `SecretFinding`) so a full `HackReport` can be signed under a single AIC
 * in one call.
 *
 * This module deliberately contains zero cryptography of its own — all
 * signing/verification is delegated to `@lyrie/atp`'s public surface. It
 * exists purely to give `signFinding` type-specific ergonomics for the
 * shapes Lyrie Hack actually produces, without `@lyrie/atp` ever needing to
 * know what a `ValidatedFinding` or `SecretFinding` looks like.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  signFinding,
  type AgentIdentityCertificate,
  type SignedFinding,
} from "@lyrie/atp";

import type { ValidatedFinding } from "../pentest/stages-validator";
import type { SecretFinding } from "./secret-detector";
import type { HackReport } from "./report-engine";

export const SIGNED_FINDINGS_VERSION = "lyrie-signed-findings-1.0.0";

export interface SignHackReportResult {
  /** The original report, unmodified. */
  report: HackReport;
  /** Every `validatedFindings` entry, individually signed. */
  signedFindings: SignedFinding<ValidatedFinding>[];
  /** Every `secretFindings` entry, individually signed. */
  signedSecrets: SignedFinding<SecretFinding>[];
}

/**
 * Sign every finding in a `HackReport` under a single AIC in one call.
 * Convenience wrapper over `@lyrie/atp`'s `signFinding` — does not mutate
 * `report`. Each entry can later be independently verified via
 * `verifySignedFinding` from `@lyrie/atp`.
 */
export function signHackReport(
  report: HackReport,
  cert: AgentIdentityCertificate,
  privateKey: string,
): SignHackReportResult {
  // Use one shared timestamp for the whole batch so every finding produced
  // by this run carries an identical, auditable signedAt.
  const signedAt = new Date().toISOString();

  const signedFindings = report.validatedFindings.map((finding) =>
    signFinding<ValidatedFinding>({ payload: finding, cert, privateKey, signedAt }),
  );
  const signedSecrets = report.secretFindings.map((finding) =>
    signFinding<SecretFinding>({ payload: finding, cert, privateKey, signedAt }),
  );

  return { report, signedFindings, signedSecrets };
}
