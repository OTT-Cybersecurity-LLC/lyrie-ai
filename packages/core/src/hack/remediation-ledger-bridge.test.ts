/**
 * Lyrie Hack — Remediation → Trust Ledger bridge tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";

import { TrustLedger } from "./trust-ledger";
import { computeTrustScore } from "./trust-score";
import { REPORT_ENGINE_VERSION, type HackReport, type Severity } from "./report-engine";
import type { RevalidationResult } from "../remediation-pr/revalidate";
import { describeRemediationImpact, recordVerifiedRemediation } from "./remediation-ledger-bridge";

// ─── Fixtures (mirrors trust-ledger.test.ts / trust-score.test.ts style) ────

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function baseReport(over: Partial<HackReport> = {}): HackReport {
  return {
    target: "/tmp/x",
    runId: "hack-test",
    mode: "standard",
    startedAt: "2026-07-25T00:00:00.000Z",
    finishedAt: "2026-07-25T00:00:01.000Z",
    durationMs: 1000,
    threatMatches: [],
    validatedFindings: [],
    secretFindings: [],
    remediations: [],
    counts: emptyCounts(),
    totalFindings: 0,
    aavRan: false,
    selfScanRan: false,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
    reporterVersion: REPORT_ENGINE_VERSION,
    ...over,
  };
}

function validatedFinding(id: string, severity: Severity, confirmed = true) {
  return {
    finding: {
      id,
      title: `${severity} test finding`,
      severity,
      description: "test",
      category: "other" as const,
      evidence: "",
    },
    confirmed,
    stages: [],
    confidence: confirmed ? 0.9 : 0.2,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

function secretFinding(id: string, severity: Severity) {
  return {
    id,
    type: "google-api-key" as const,
    severity,
    file: "src/config.ts",
    line: 3,
    redactedSample: "abcd..ef",
    length: 32,
    confidence: 1,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

function revalidation(status: RevalidationResult["status"], summary = "test summary"): RevalidationResult {
  return {
    status,
    backend: "local",
    summary,
    durationMs: 42,
  };
}

let ledger: TrustLedger;

afterEach(() => {
  ledger?.close();
});

// ─── skip paths — never fake an unverified fix ──────────────────────────────

describe("recordVerifiedRemediation — never records an unverified fix", () => {
  it("skips and does NOT write to the ledger when status is 'still-vulnerable'", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "still-vuln.com";

    const report = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("f-critical-1", "critical")],
    });
    // seed one entry so we can assert history length is unchanged, not just "still 0"
    ledger.record(report, computeTrustScore(report));
    expect(ledger.history(target).length).toBe(1);

    const result = recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "f-critical-1",
      revalidation: revalidation("still-vulnerable", "backend still saw the vuln"),
      ledger,
    });

    expect(result).toEqual({
      skipped: true,
      reason: expect.stringContaining('status is "still-vulnerable"'),
    });
    expect(ledger.history(target).length).toBe(1); // UNCHANGED — no write happened
  });

  it("skips and does NOT write to the ledger when status is 'inconclusive'", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "inconclusive.com";

    const report = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("f-critical-1", "critical")],
    });
    ledger.record(report, computeTrustScore(report));
    expect(ledger.history(target).length).toBe(1);

    const result = recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "f-critical-1",
      revalidation: revalidation("inconclusive", "sandbox backend was not ready"),
      ledger,
    });

    expect(result).toEqual({
      skipped: true,
      reason: expect.stringContaining('status is "inconclusive"'),
    });
    expect(ledger.history(target).length).toBe(1); // UNCHANGED — no write happened
  });
});

// ─── verified-fixed happy path ───────────────────────────────────────────────

describe("recordVerifiedRemediation — verified-fixed happy path", () => {
  it("removes the fixed finding, recomputes a strictly higher score, and records +1 ledger entry", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "verified.com";

    // 1 critical (25) + 1 low (2) => 100 - 27 = 73
    const report = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [
        validatedFinding("f-critical-1", "critical"),
        validatedFinding("f-low-1", "low"),
      ],
    });
    const beforeBreakdown = computeTrustScore(report);
    expect(beforeBreakdown.score).toBe(73);
    const before = ledger.record(report, beforeBreakdown);
    expect(ledger.history(target).length).toBe(1);

    const result = recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "f-critical-1",
      revalidation: revalidation("verified-fixed", "sandboxed re-scan found 0 qualifying findings"),
      ledger,
    });

    expect("skipped" in result).toBe(false);
    if ("skipped" in result) throw new Error("unreachable"); // narrow for TS

    // critical removed, low remains => 100 - 2 = 98
    expect(result.breakdown.score).toBe(98);
    expect(result.breakdown.score).toBeGreaterThan(beforeBreakdown.score);
    expect(result.updatedReport.validatedFindings.map((v) => v.finding.id)).toEqual(["f-low-1"]);
    expect(result.updatedReport.secretFindings).toEqual(report.secretFindings);

    // ledger has +1 entry
    const history = ledger.history(target);
    expect(history.length).toBe(2);
    expect(history[0]!.id).toBe(result.entry.id);
    expect(result.entry.score).toBe(98);

    const impact = describeRemediationImpact(before, result.entry, "f-critical-1");
    expect(impact.length).toBeGreaterThan(0);
    expect(impact).toContain("73");
    expect(impact).toContain("98");
    expect(impact).toContain("+25");
  });

  it("also matches and filters a fixed SecretFinding by id", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "secret-fix.com";

    // 1 high secret (12) => 100 - 12 = 88
    const report = baseReport({
      target,
      runId: "run-1",
      secretFindings: [secretFinding("s-high-1", "high")],
    });
    expect(computeTrustScore(report).score).toBe(88);
    ledger.record(report, computeTrustScore(report));

    const result = recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "s-high-1",
      revalidation: revalidation("verified-fixed"),
      ledger,
    });

    expect("skipped" in result).toBe(false);
    if ("skipped" in result) throw new Error("unreachable");
    expect(result.breakdown.score).toBe(100);
    expect(result.updatedReport.secretFindings).toEqual([]);
  });

  it("does not mutate the originalReport passed in", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "no-mutate.com";

    const report = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("f-critical-1", "critical")],
    });
    const originalFindingsRef = report.validatedFindings;

    recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "f-critical-1",
      revalidation: revalidation("verified-fixed"),
      ledger,
    });

    expect(report.validatedFindings).toBe(originalFindingsRef);
    expect(report.validatedFindings.length).toBe(1);
  });
});

// ─── edge case: fixedFindingId matches nothing ──────────────────────────────

describe("recordVerifiedRemediation — fixedFindingId with no match", () => {
  it("is treated as a no-op recompute (same score still recorded), not an error", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "no-match.com";

    const report = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("f-critical-1", "critical")],
    });
    const beforeScore = computeTrustScore(report).score; // 75
    ledger.record(report, computeTrustScore(report));

    const result = recordVerifiedRemediation({
      originalReport: report,
      fixedFindingId: "f-does-not-exist",
      revalidation: revalidation("verified-fixed"),
      ledger,
    });

    expect("skipped" in result).toBe(false);
    if ("skipped" in result) throw new Error("unreachable");
    // nothing removed -> score unchanged, but still a new recorded entry
    expect(result.breakdown.score).toBe(beforeScore);
    expect(result.updatedReport.validatedFindings.length).toBe(1);
    expect(ledger.history(target).length).toBe(2);
  });
});

// ─── describeRemediationImpact ───────────────────────────────────────────────

describe("describeRemediationImpact", () => {
  it("produces a non-empty human-readable string mentioning both scores for an improvement", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "describe.com";

    const r1 = baseReport({ target, runId: "run-1", validatedFindings: [validatedFinding("f-1", "high")] });
    const before = ledger.record(r1, computeTrustScore(r1)); // 88

    const r2 = baseReport({ target, runId: "run-2" });
    const after = ledger.record(r2, computeTrustScore(r2)); // 100

    const impact = describeRemediationImpact(before, after);
    expect(typeof impact).toBe("string");
    expect(impact.length).toBeGreaterThan(0);
    expect(impact).toContain("88");
    expect(impact).toContain("100");
    expect(impact).toContain("raised");
  });

  it("describes a zero-delta comparison as 'left unchanged' without throwing", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();
    const target = "flat.com";

    const r1 = baseReport({ target, runId: "run-1" });
    const before = ledger.record(r1, computeTrustScore(r1));
    const r2 = baseReport({ target, runId: "run-2" });
    const after = ledger.record(r2, computeTrustScore(r2));

    const impact = describeRemediationImpact(before, after);
    expect(impact).toContain("left unchanged");
    expect(impact).toContain("(0)");
  });
});
