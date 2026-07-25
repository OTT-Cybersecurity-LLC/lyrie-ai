/**
 * Lyrie Hack — Trust Score.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Aggregates a `HackReport`'s findings into a single, deterministic 0-100
 * trust score, plus a transparent `TrustScoreBreakdown` showing exactly how
 * the number was derived (per-severity deductions, not a black box).
 *
 * Formula (documented, not a black box):
 *   score = 100 - sum(deduction[severity] * count[severity]) , floored at 0
 *
 * Deduction weights per finding, applied to CONFIRMED validated findings
 * (`ValidatedFinding.confirmed === true`) and ALL secret findings (secrets
 * are treated as always-confirmed — SecretDetector doesn't carry a
 * confirmation stage the way pentest findings do via Stages A-F):
 *
 *   critical: 25   high: 12   medium: 5   low: 2   info: 0.5
 *
 * Rationale for the weights: a single critical finding (e.g. confirmed
 * RCE) should be enough to drag a "trustworthy" score into failing
 * territory on its own (100 - 25*1 = 75, and two criticals already put you
 * under 50). Info-level findings barely move the needle — they're mostly
 * hygiene notes, not real risk. This mirrors the same severity ordering
 * used everywhere else in the report engine (`toSarif`'s
 * SEVERITY_TO_SARIF, `toMarkdown`'s `order` array) for consistency.
 *
 * Determinism: the score is a pure function of `report.validatedFindings`
 * and `report.secretFindings` (specifically their `.confirmed`/`.severity`
 * fields) — same findings always produce the same score, independent of
 * scan duration, target, or any other report metadata. No randomness, no
 * network calls, fully offline.
 *
 * Unconfirmed findings (Stages A-F ran but couldn't confirm exploitability)
 * are intentionally excluded from the deduction — an unconfirmed finding is
 * a *lead*, not a verified risk, and scoring it the same as a confirmed one
 * would make the score noisy/unstable across runs with different Stage
 * confirmation luck. This is the more conservative choice: it means the
 * score can only be as harsh as what Lyrie could actually prove.
 */

import type { HackReport, Severity } from "./report-engine";

export const TRUST_SCORE_VERSION = "lyrie-trust-score-1.0.0";

/** Deduction points per finding, by severity. Documented, not a black box. */
export const TRUST_SCORE_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0.5,
};

export interface TrustScoreDeduction {
  severity: Severity;
  count: number;
  weight: number;
  /** count * weight, before the 100-point ceiling/0 floor is applied. */
  subtotal: number;
}

export interface TrustScoreBreakdown {
  /** Final 0-100 score, floored at 0, rounded to the nearest integer. */
  score: number;
  /** Raw (unfloored, unrounded) 100 - totalDeduction, for auditability. */
  rawScore: number;
  /** Sum of all deduction subtotals. */
  totalDeduction: number;
  /** Per-severity breakdown, in critical -> info order. */
  deductions: TrustScoreDeduction[];
  /** How many findings counted toward the score (confirmed only + all secrets). */
  countedFindings: number;
  /** How many confirmed-pentest findings were excluded for being unconfirmed. */
  excludedUnconfirmed: number;
  version: typeof TRUST_SCORE_VERSION;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Compute the aggregate 0-100 trust score for a HackReport. Deterministic —
 * calling this twice on the same report always returns the same result.
 */
export function computeTrustScore(report: HackReport): TrustScoreBreakdown {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let excludedUnconfirmed = 0;

  for (const v of report.validatedFindings) {
    if (!v.confirmed) {
      excludedUnconfirmed++;
      continue;
    }
    counts[v.finding.severity]++;
  }
  for (const s of report.secretFindings) {
    counts[s.severity]++;
  }

  const deductions: TrustScoreDeduction[] = SEVERITY_ORDER.map((severity) => {
    const count = counts[severity];
    const weight = TRUST_SCORE_WEIGHTS[severity];
    return { severity, count, weight, subtotal: count * weight };
  });

  const totalDeduction = deductions.reduce((sum, d) => sum + d.subtotal, 0);
  const rawScore = 100 - totalDeduction;
  const score = Math.max(0, Math.round(rawScore));
  const countedFindings = SEVERITY_ORDER.reduce((sum, s) => sum + counts[s], 0);

  return {
    score,
    rawScore,
    totalDeduction,
    deductions,
    countedFindings,
    excludedUnconfirmed,
    version: TRUST_SCORE_VERSION,
  };
}

/** One-line human summary, e.g. "82/100 (2 high, 1 medium)". */
export function formatTrustScoreSummary(breakdown: TrustScoreBreakdown): string {
  const parts = breakdown.deductions
    .filter((d) => d.count > 0)
    .map((d) => `${d.count} ${d.severity}`);
  const detail = parts.length > 0 ? ` (${parts.join(", ")})` : " (no counted findings)";
  return `${breakdown.score}/100${detail}`;
}
