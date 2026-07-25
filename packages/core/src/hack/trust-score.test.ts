/**
 * Lyrie Hack — Trust Score tests.
 *
 * Hand-verified test cases against the documented formula:
 *   score = 100 - (critical*25 + high*12 + medium*5 + low*2 + info*0.5), floor 0
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, expect, it } from "bun:test";
import { computeTrustScore, formatTrustScoreSummary, TRUST_SCORE_WEIGHTS } from "./trust-score";
import { REPORT_ENGINE_VERSION, type HackReport, type Severity } from "./report-engine";

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

function validatedFinding(severity: Severity, confirmed = true) {
  return {
    finding: {
      id: `f-${severity}-${Math.random()}`,
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

function secretFinding(severity: Severity) {
  return {
    id: `s-${severity}-${Math.random()}`,
    type: "generic-secret" as const,
    severity,
    file: "config.js",
    line: 1,
    redactedSample: "AAAA***ZZ",
    length: 20,
    confidence: 0.9,
    signature: "Lyrie.ai by OTT Cybersecurity LLC" as const,
  };
}

describe("computeTrustScore — documented formula, hand-verified cases", () => {
  it("case 1: zero findings scores exactly 100", () => {
    const report = baseReport();
    const bd = computeTrustScore(report);
    expect(bd.score).toBe(100);
    expect(bd.rawScore).toBe(100);
    expect(bd.totalDeduction).toBe(0);
    expect(bd.countedFindings).toBe(0);
  });

  it("case 2: 1 critical + 1 high = 100 - (25 + 12) = 63", () => {
    const report = baseReport({
      validatedFindings: [validatedFinding("critical"), validatedFinding("high")],
    });
    const bd = computeTrustScore(report);
    // Hand-verified: 100 - (1*25 + 1*12) = 100 - 37 = 63
    expect(bd.totalDeduction).toBe(37);
    expect(bd.rawScore).toBe(63);
    expect(bd.score).toBe(63);
  });

  it("case 3: 2 medium + 3 low + 4 info = 100 - (10 + 6 + 2) = 82", () => {
    const report = baseReport({
      validatedFindings: [
        validatedFinding("medium"),
        validatedFinding("medium"),
        validatedFinding("low"),
        validatedFinding("low"),
        validatedFinding("low"),
        validatedFinding("info"),
        validatedFinding("info"),
        validatedFinding("info"),
        validatedFinding("info"),
      ],
    });
    const bd = computeTrustScore(report);
    // Hand-verified: 2*5 + 3*2 + 4*0.5 = 10 + 6 + 2 = 18 -> 100 - 18 = 82
    expect(bd.totalDeduction).toBe(18);
    expect(bd.rawScore).toBe(82);
    expect(bd.score).toBe(82);
  });

  it("case 4: overwhelming criticals floor at 0, never negative", () => {
    const report = baseReport({
      validatedFindings: Array.from({ length: 10 }, () => validatedFinding("critical")),
    });
    const bd = computeTrustScore(report);
    // Hand-verified: 10*25 = 250 -> rawScore -150 -> floored to 0
    expect(bd.totalDeduction).toBe(250);
    expect(bd.rawScore).toBe(-150);
    expect(bd.score).toBe(0);
  });

  it("case 5: secret findings count toward the score same as confirmed pentest findings", () => {
    const report = baseReport({
      secretFindings: [secretFinding("critical")],
    });
    const bd = computeTrustScore(report);
    // Hand-verified: 100 - 25 = 75
    expect(bd.totalDeduction).toBe(25);
    expect(bd.score).toBe(75);
  });

  it("unconfirmed findings are excluded from the deduction (leads, not verified risk)", () => {
    const report = baseReport({
      validatedFindings: [validatedFinding("critical", false), validatedFinding("critical", false)],
    });
    const bd = computeTrustScore(report);
    expect(bd.score).toBe(100);
    expect(bd.totalDeduction).toBe(0);
    expect(bd.excludedUnconfirmed).toBe(2);
    expect(bd.countedFindings).toBe(0);
  });

  it("mix of confirmed and unconfirmed: only confirmed counts", () => {
    const report = baseReport({
      validatedFindings: [validatedFinding("high", true), validatedFinding("high", false)],
    });
    const bd = computeTrustScore(report);
    // Only the confirmed high counts: 100 - 12 = 88
    expect(bd.score).toBe(88);
    expect(bd.excludedUnconfirmed).toBe(1);
    expect(bd.countedFindings).toBe(1);
  });

  it("is deterministic — repeated calls on the same input produce the same score", () => {
    const report = baseReport({
      validatedFindings: [validatedFinding("critical"), validatedFinding("medium")],
      secretFindings: [secretFinding("low")],
    });
    const results = Array.from({ length: 25 }, () => computeTrustScore(report));
    const scores = new Set(results.map((r) => r.score));
    const raws = new Set(results.map((r) => r.rawScore));
    expect(scores.size).toBe(1);
    expect(raws.size).toBe(1);
    // Hand-verified: 1 critical (25) + 1 medium (5) + 1 low secret (2) = 32 -> 100 - 32 = 68
    expect(results[0]!.score).toBe(68);
  });

  it("deductions array is in critical -> info order and matches weights", () => {
    const report = baseReport();
    const bd = computeTrustScore(report);
    expect(bd.deductions.map((d) => d.severity)).toEqual(["critical", "high", "medium", "low", "info"]);
    for (const d of bd.deductions) {
      expect(d.weight).toBe(TRUST_SCORE_WEIGHTS[d.severity]);
    }
  });

  it("score never exceeds 100 and never goes below 0 across random-ish combos", () => {
    for (let i = 0; i < 20; i++) {
      const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
      const findings = Array.from({ length: i }, (_, j) => validatedFinding(severities[j % 5]!));
      const bd = computeTrustScore(baseReport({ validatedFindings: findings }));
      expect(bd.score).toBeGreaterThanOrEqual(0);
      expect(bd.score).toBeLessThanOrEqual(100);
    }
  });
});

describe("formatTrustScoreSummary", () => {
  it("formats a clean report", () => {
    const bd = computeTrustScore(baseReport());
    expect(formatTrustScoreSummary(bd)).toBe("100/100 (no counted findings)");
  });

  it("formats a report with mixed findings", () => {
    const bd = computeTrustScore(
      baseReport({ validatedFindings: [validatedFinding("critical"), validatedFinding("high")] }),
    );
    expect(formatTrustScoreSummary(bd)).toBe("63/100 (1 critical, 1 high)");
  });
});
