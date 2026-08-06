/**
 * watch/drift-severity.ts — Aggregate drift-severity classification over a
 * single tick's `AdapterFinding[]` (the output of `diffPostureSnapshots()`).
 *
 * `diff.ts` already assigns a per-finding `severity` (see its module doc —
 * e.g. newly-exposed path = critical, removed hardening header = high,
 * added header = info). That per-finding severity is real and is reused
 * here verbatim, NOT re-derived — this module's job is strictly to roll a
 * whole tick's findings up into ONE actionable overall verdict (the worst
 * severity present, plus human-readable reasons) so a cron job or CLI can
 * make a single go/no-go decision ("exit 1 and page someone" vs "log and
 * move on") without re-implementing per-finding logic.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { AdapterFinding } from "../engine/daemon";

export type DriftSeverityLevel = "info" | "low" | "medium" | "high" | "critical";

export interface DriftSeverityResult {
  /** Highest severity present across all findings this tick ("info" when there are none). */
  severity: DriftSeverityLevel;
  /** One human-readable line per finding that contributed, worst-first. */
  reasons: string[];
}

/** Ordering used to find the "worst" severity across a set of findings. */
const SEVERITY_RANK: Record<DriftSeverityLevel, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function isDriftSeverityLevel(v: string): v is DriftSeverityLevel {
  return v in SEVERITY_RANK;
}

/**
 * Roll a tick's diff findings up into one overall `DriftSeverityResult`.
 *
 * Rules (all already encoded as per-finding severities in `diff.ts` —
 * restated here for reviewers, not re-implemented):
 *   - TLS cert expired or expiring in <7 days   → critical (diff.ts emits
 *     "critical" once `msUntilExpiry <= 0`; the <30-day warning window is
 *     "medium" per diff.ts's 14-day default warning threshold — see below).
 *   - Newly-exposed path (COMMON_EXPOSED_PATHS) → critical
 *   - CSP/HSTS/other hardening header REMOVED   → high
 *   - Hardening header ADDED                    → info (improvement)
 *   - Server/X-Powered-By header changed        → info/low (fingerprinting only)
 *   - New subdomain discovered                  → medium
 *
 * `findings` with no elements (idle tick, or first-ever run with nothing to
 * diff against) yields `{ severity: "info", reasons: [] }`.
 */
export function classifyDriftSeverity(findings: AdapterFinding[]): DriftSeverityResult {
  if (findings.length === 0) {
    return { severity: "info", reasons: [] };
  }

  const sorted = [...findings].sort((a, b) => {
    const rankA = isDriftSeverityLevel(a.severity) ? SEVERITY_RANK[a.severity] : 0;
    const rankB = isDriftSeverityLevel(b.severity) ? SEVERITY_RANK[b.severity] : 0;
    return rankB - rankA;
  });

  let worst: DriftSeverityLevel = "info";
  for (const f of sorted) {
    if (isDriftSeverityLevel(f.severity) && SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst]) {
      worst = f.severity;
    }
  }

  const reasons = sorted.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`);

  return { severity: worst, reasons };
}
