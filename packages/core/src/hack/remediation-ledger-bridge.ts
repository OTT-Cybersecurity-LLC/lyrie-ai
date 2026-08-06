/**
 * Lyrie Hack — Remediation → Trust Ledger bridge.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * ─── WHAT THIS FILE IS ──────────────────────────────────────────────────────
 *
 * This is GLUE CODE between two already-complete, independently-tested
 * systems. It contains no scoring logic and no re-validation logic — both of
 * those already exist and are NOT modified here:
 *
 *   - `remediation-pr/revalidate.ts` proves (or disproves) that an
 *     auto-remediation PR actually fixed the vulnerability, by re-running
 *     verification against the patched tree in a sandboxed backend. It
 *     returns a `RevalidationResult` with a `status` of `"verified-fixed"`,
 *     `"still-vulnerable"`, or `"inconclusive"`.
 *   - `hack/trust-ledger.ts`'s `TrustLedger` persists `computeTrustScore()`
 *     results (from `hack/trust-score.ts`) as an append-only history per
 *     target, and can diff the two most recent entries.
 *
 * This module is the missing wire between them: given a `RevalidationResult`
 * for a specific finding, decide whether — and how — to record a new,
 * improved trust-score entry in the ledger.
 *
 * ─── THE CORRECTNESS GUARANTEE (READ THIS BEFORE TOUCHING THIS FILE) ───────
 *
 * **A trust-score improvement is NEVER recorded unless
 * `revalidation.status === "verified-fixed"`.**
 *
 * This is the single most important property of this module. The whole
 * point of the sandboxed re-validation step is to make Lyrie's self-healing
 * loop trustworthy: a PR that merely *claims* to fix something, or one whose
 * re-check errored out / couldn't reach a verdict, must NEVER be allowed to
 * improve a target's recorded security posture. If this guarantee had a bug,
 * an attacker (or just a broken CI run) could fake a better trust score by
 * opening a no-op PR and letting revalidation silently pass or error out in
 * the "successful" direction. `still-vulnerable` and `inconclusive` both
 * short-circuit to `{ skipped: true, reason }` before any ledger write is
 * attempted — see `recordVerifiedRemediation()` below, and the
 * `remediation-ledger-bridge.test.ts` cases asserting ledger history length
 * is UNCHANGED for both of those statuses.
 *
 * ─── DESIGN DECISION: how a fixed finding is removed from the report ───────
 *
 * Neither `ValidatedFinding` (pentest/stages-validator.ts) nor
 * `SecretFinding` (hack/secret-detector.ts) carries any "resolved" / "fixed"
 * / "closed" field today — `ValidatedFinding` only has `confirmed: boolean`
 * (did Stages A–F confirm exploitability, not "is it still open"), and
 * `SecretFinding` has no status field at all. Rather than inventing a new
 * field on either (which would require touching two already-complete,
 * tested modules), this bridge takes the simplest correct approach:
 * **filter the matched finding OUT of the cloned report's arrays** before
 * recomputing the trust score. `computeTrustScore()` is a pure function of
 * `validatedFindings`/`secretFindings` (see trust-score.ts's own docs), so a
 * finding that no longer appears in either array cannot contribute a
 * deduction — functionally identical to marking it resolved, with zero
 * changes to any other module.
 *
 * ─── MATCHING `fixedFindingId` ─────────────────────────────────────────────
 *
 * Both candidate finding shapes already carry a stable unique id:
 *   - `ValidatedFinding.finding.id` (`RawFinding.id`, pentest/stages-validator.ts)
 *   - `SecretFinding.id` (hack/secret-detector.ts)
 * `fixedFindingId` is matched against both; whichever collection contains a
 * match has that entry filtered out. See `EDGE CASE` below for the no-match
 * behavior.
 *
 * ─── EDGE CASE: `fixedFindingId` matches nothing ───────────────────────────
 *
 * If `fixedFindingId` doesn't match any `validatedFindings[].finding.id` or
 * `secretFindings[].id`, this is treated as a **no-op recompute, not an
 * error**: the cloned report is unchanged, `computeTrustScore` runs on an
 * identical set of findings, and the resulting (unchanged) score is still
 * recorded to the ledger as a new entry. Rationale: `revalidation.status`
 * already proved a real fix landed and was sandboxed-verified — refusing to
 * record *anything* just because the caller passed a stale/mistyped id
 * would silently drop a legitimate verified-fix event from history. A wrong
 * id here is a caller bug worth normal logging/observability, not a reason
 * to make the ledger blind to a proven remediation. (This still can never
 * *fake an improvement* — if nothing is removed, the score cannot go down or
 * be inflated; at worst it stays exactly the same, which is the honest
 * reflection of "the id given didn't match a known finding.")
 */

import type { HackReport } from "./report-engine";
import { computeTrustScore, type TrustScoreBreakdown } from "./trust-score";
import type { TrustLedger, TrustLedgerEntry } from "./trust-ledger";
import type { RevalidationResult } from "../remediation-pr/revalidate";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface RecordVerifiedRemediationInput {
  /** The report the fixed finding originally appeared in. Not mutated — cloned internally. */
  originalReport: HackReport;
  /**
   * Unique id of the finding that was fixed — matched against
   * `validatedFindings[].finding.id` (RawFinding.id) and `secretFindings[].id`.
   */
  fixedFindingId: string;
  /** Outcome of `revalidateRemediation()` (remediation-pr/revalidate.ts) for this fix. */
  revalidation: RevalidationResult;
  /** Ledger to record the new (recomputed) trust-score entry into, when the fix is verified. */
  ledger: TrustLedger;
}

export type RecordVerifiedRemediationResult =
  | {
      updatedReport: HackReport;
      breakdown: TrustScoreBreakdown;
      entry: TrustLedgerEntry;
    }
  | { skipped: true; reason: string };

// ─── recordVerifiedRemediation ──────────────────────────────────────────────

/**
 * Given a proven-or-not `RevalidationResult` for one finding, either:
 *   - skip recording anything (fix not verified — see the correctness
 *     guarantee in the file header), or
 *   - clone `originalReport` with the fixed finding filtered out, recompute
 *     its trust score, persist the new entry to `ledger`, and return all
 *     three artifacts.
 *
 * NEVER throws for a normal `RevalidationResult` — the only failure mode is
 * the explicit `{ skipped: true, reason }` return for anything other than
 * `"verified-fixed"`.
 */
export function recordVerifiedRemediation(
  input: RecordVerifiedRemediationInput,
): RecordVerifiedRemediationResult {
  const { originalReport, fixedFindingId, revalidation, ledger } = input;

  // ── The correctness guarantee ─────────────────────────────────────────────
  // Never record an improved trust score unless the fix was actually proven
  // by sandboxed re-validation. "still-vulnerable" and "inconclusive" both
  // stop here, before any ledger write.
  if (revalidation.status !== "verified-fixed") {
    return {
      skipped: true,
      reason: `revalidation status is "${revalidation.status}", not "verified-fixed" — refusing to record a trust-score improvement for an unproven fix. Summary: ${revalidation.summary}`,
    };
  }

  const updatedReport: HackReport = {
    ...originalReport,
    validatedFindings: originalReport.validatedFindings.filter(
      (v) => v.finding.id !== fixedFindingId,
    ),
    secretFindings: originalReport.secretFindings.filter((s) => s.id !== fixedFindingId),
  };

  const breakdown = computeTrustScore(updatedReport);
  const entry = ledger.record(updatedReport, breakdown);

  return { updatedReport, breakdown, entry };
}

// ─── describeRemediationImpact ──────────────────────────────────────────────

/**
 * Human-readable one-liner comparing two SPECIFIC ledger entries — the
 * entry recorded immediately before a fix, and the entry recorded by
 * `recordVerifiedRemediation()` immediately after. Unlike
 * `TrustLedger.delta()` (which always compares a target's latest two
 * history rows, whatever they happen to be), this takes explicit `before`/
 * `after` entries so callers get a correct comparison even if other runs
 * have been recorded for the same target in between — a standalone diff,
 * not a call-through to `delta()`.
 *
 * Example: "Verified fix for f-critical-1 raised trust score 73 → 98 (+25)."
 */
export function describeRemediationImpact(
  before: TrustLedgerEntry,
  after: TrustLedgerEntry,
  fixedFindingId?: string,
): string {
  const scoreDelta = after.score - before.score;
  const sign = scoreDelta > 0 ? "+" : "";
  const subject = fixedFindingId ? `Verified fix for ${fixedFindingId}` : "Verified fix";
  const direction =
    scoreDelta > 0
      ? "raised"
      : scoreDelta < 0
        ? "lowered"
        : "left unchanged";
  return `${subject} ${direction} trust score ${before.score} → ${after.score} (${sign}${scoreDelta}).`;
}
