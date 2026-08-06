/**
 * Lyrie Hack — Continuous Trust Ledger tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { afterEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";

import { TrustLedger } from "./trust-ledger";
import { computeTrustScore, type TrustScoreBreakdown } from "./trust-score";
import { REPORT_ENGINE_VERSION, type HackReport, type Severity } from "./report-engine";

// ─── Fixtures (mirrors trust-score.test.ts's fixture style) ─────────────────

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

function breakdownFor(report: HackReport): TrustScoreBreakdown {
  return computeTrustScore(report);
}

let ledger: TrustLedger;

afterEach(() => {
  ledger?.close();
});

// ─── record + retrieve round trip ───────────────────────────────────────────

describe("TrustLedger — record + retrieve round trip", () => {
  it("records an entry and reads it back via latest()", () => {
    ledger = new TrustLedger(new Database(":memory:"));
    ledger.initialize();

    const report = baseReport({ target: "example.com", runId: "run-1" });
    const breakdown = breakdownFor(report);
    const recorded = ledger.record(report, breakdown);

    expect(recorded.target).toBe("example.com");
    expect(recorded.runId).toBe("run-1");
    expect(recorded.score).toBe(100);
    expect(recorded.mode).toBe("standard");
    expect(recorded.breakdown).toEqual(breakdown);
    expect(typeof recorded.id).toBe("string");
    expect(recorded.id.length).toBeGreaterThan(0);
    expect(() => new Date(recorded.recordedAt).toISOString()).not.toThrow();

    const latest = ledger.latest("example.com");
    expect(latest).toBeDefined();
    expect(latest).toEqual(recorded);
  });

  it("returns undefined from latest() when no entries exist for the target", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    expect(ledger.latest("nothing-here.com")).toBeUndefined();
  });

  it("auto-initializes lazily if initialize() was never called explicitly", () => {
    ledger = new TrustLedger(":memory:");
    const report = baseReport({ target: "lazy.com" });
    const entry = ledger.record(report, breakdownFor(report));
    expect(entry.target).toBe("lazy.com");
    expect(ledger.latest("lazy.com")?.id).toBe(entry.id);
  });

  it("accepts a plain db path string as well as a Database instance", () => {
    ledger = new TrustLedger(); // defaults to :memory:
    ledger.initialize();
    const report = baseReport({ target: "default-path.com" });
    const entry = ledger.record(report, breakdownFor(report));
    expect(entry.target).toBe("default-path.com");
  });
});

// ─── history ordering ────────────────────────────────────────────────────────

describe("TrustLedger — history ordering", () => {
  it("returns entries most-recent-first", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();

    const target = "history.com";
    const r1 = baseReport({ target, runId: "run-1" });
    const e1 = ledger.record(r1, breakdownFor(r1));

    const r2 = baseReport({ target, runId: "run-2", validatedFindings: [validatedFinding("high")] });
    const e2 = ledger.record(r2, breakdownFor(r2));

    const r3 = baseReport({ target, runId: "run-3", validatedFindings: [validatedFinding("critical")] });
    const e3 = ledger.record(r3, breakdownFor(r3));

    const hist = ledger.history(target);
    expect(hist.map((e) => e.runId)).toEqual(["run-3", "run-2", "run-1"]);
    expect(hist[0]!.id).toBe(e3.id);
    expect(hist[2]!.id).toBe(e1.id);
  });

  it("respects the limit parameter", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();

    const target = "limited.com";
    for (let i = 0; i < 5; i++) {
      const r = baseReport({ target, runId: `run-${i}` });
      ledger.record(r, breakdownFor(r));
    }

    const hist = ledger.history(target, 2);
    expect(hist.length).toBe(2);
    expect(hist.map((e) => e.runId)).toEqual(["run-4", "run-3"]);
  });

  it("keeps histories separate per target", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();

    const rA = baseReport({ target: "a.com", runId: "a-1" });
    ledger.record(rA, breakdownFor(rA));
    const rB = baseReport({ target: "b.com", runId: "b-1" });
    ledger.record(rB, breakdownFor(rB));

    expect(ledger.history("a.com").map((e) => e.runId)).toEqual(["a-1"]);
    expect(ledger.history("b.com").map((e) => e.runId)).toEqual(["b-1"]);
  });
});

// ─── delta with 0/1/2+ entries ───────────────────────────────────────────────

describe("TrustLedger — delta()", () => {
  it("returns undefined with 0 entries", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    expect(ledger.delta("none.com")).toBeUndefined();
  });

  it("returns undefined with exactly 1 entry", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "one-entry.com";
    const r = baseReport({ target });
    ledger.record(r, breakdownFor(r));
    expect(ledger.delta(target)).toBeUndefined();
  });

  it("computes delta correctly with 2 entries — regression case", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "regressed.com";

    const r1 = baseReport({ target, runId: "run-1" }); // score 100
    ledger.record(r1, breakdownFor(r1));

    const r2 = baseReport({
      target,
      runId: "run-2",
      validatedFindings: [validatedFinding("critical")],
    }); // score 75
    ledger.record(r2, breakdownFor(r2));

    const d = ledger.delta(target);
    expect(d).toBeDefined();
    expect(d!.current.runId).toBe("run-2");
    expect(d!.previous.runId).toBe("run-1");
    expect(d!.scoreDelta).toBe(-25);
    expect(d!.regressions.map((x) => x.severity)).toEqual(["critical"]);
    expect(d!.improvements).toEqual([]);
  });

  it("computes delta correctly with 2 entries — improvement case", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "improved.com";

    const r1 = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("high"), validatedFinding("high")],
    }); // 2 high -> 100 - 24 = 76
    ledger.record(r1, breakdownFor(r1));

    const r2 = baseReport({
      target,
      runId: "run-2",
      validatedFindings: [validatedFinding("high")],
    }); // 1 high -> 88
    ledger.record(r2, breakdownFor(r2));

    const d = ledger.delta(target);
    expect(d).toBeDefined();
    expect(d!.scoreDelta).toBe(12);
    expect(d!.improvements.map((x) => x.severity)).toEqual(["high"]);
    expect(d!.regressions).toEqual([]);
  });

  it("uses only the 2 most recent entries when 3+ exist", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "three-plus.com";

    const r1 = baseReport({ target, runId: "run-1", validatedFindings: [validatedFinding("critical")] });
    ledger.record(r1, breakdownFor(r1)); // 75

    const r2 = baseReport({ target, runId: "run-2" });
    ledger.record(r2, breakdownFor(r2)); // 100 (fully recovered)

    const r3 = baseReport({ target, runId: "run-3", validatedFindings: [validatedFinding("low")] });
    ledger.record(r3, breakdownFor(r3)); // 98

    const d = ledger.delta(target);
    expect(d).toBeDefined();
    expect(d!.current.runId).toBe("run-3");
    expect(d!.previous.runId).toBe("run-2");
    expect(d!.scoreDelta).toBe(-2);
    expect(d!.regressions.map((x) => x.severity)).toEqual(["low"]);
  });

  it("mixed regressions and improvements across different severities", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "mixed.com";

    const r1 = baseReport({
      target,
      runId: "run-1",
      validatedFindings: [validatedFinding("high"), validatedFinding("high"), validatedFinding("low")],
    });
    ledger.record(r1, breakdownFor(r1));

    const r2 = baseReport({
      target,
      runId: "run-2",
      validatedFindings: [validatedFinding("high"), validatedFinding("critical")],
    });
    ledger.record(r2, breakdownFor(r2));

    const d = ledger.delta(target);
    expect(d).toBeDefined();
    // high went 2 -> 1 (improvement), low went 1 -> 0 (improvement), critical went 0 -> 1 (regression)
    const regSeverities = d!.regressions.map((x) => x.severity).sort();
    const impSeverities = d!.improvements.map((x) => x.severity).sort();
    expect(regSeverities).toEqual(["critical"]);
    expect(impSeverities).toEqual(["high", "low"]);
  });

  it("no findings change between two identical entries yields no regressions/improvements", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "stable.com";

    const r1 = baseReport({ target, runId: "run-1", validatedFindings: [validatedFinding("medium")] });
    ledger.record(r1, breakdownFor(r1));
    const r2 = baseReport({ target, runId: "run-2", validatedFindings: [validatedFinding("medium")] });
    ledger.record(r2, breakdownFor(r2));

    const d = ledger.delta(target);
    expect(d).toBeDefined();
    expect(d!.scoreDelta).toBe(0);
    expect(d!.regressions).toEqual([]);
    expect(d!.improvements).toEqual([]);
  });
});

// ─── formatDeltaSummary ───────────────────────────────────────────────────────

describe("TrustLedger — formatDeltaSummary()", () => {
  it("formats a regression summary with score arrow and delta", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "fmt-regress.com";

    const r1 = baseReport({ target, runId: "run-1" }); // 100
    ledger.record(r1, breakdownFor(r1));
    const r2 = baseReport({ target, runId: "run-2", validatedFindings: [validatedFinding("critical")] }); // 75
    ledger.record(r2, breakdownFor(r2));

    const summary = ledger.formatDeltaSummary(ledger.delta(target)!);
    expect(summary).toBe("Trust score: 100 → 75 (-25). Regression: +1 critical in latest scan.");
  });

  it("formats an improvement summary", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "fmt-improve.com";

    const r1 = baseReport({ target, runId: "run-1", validatedFindings: [validatedFinding("high")] }); // 88
    ledger.record(r1, breakdownFor(r1));
    const r2 = baseReport({ target, runId: "run-2" }); // 100
    ledger.record(r2, breakdownFor(r2));

    const summary = ledger.formatDeltaSummary(ledger.delta(target)!);
    expect(summary).toBe("Trust score: 88 → 100 (+12). Improvement: -1 high resolved.");
  });

  it("formats a no-change summary", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "fmt-stable.com";

    const r1 = baseReport({ target, runId: "run-1" });
    ledger.record(r1, breakdownFor(r1));
    const r2 = baseReport({ target, runId: "run-2" });
    ledger.record(r2, breakdownFor(r2));

    const summary = ledger.formatDeltaSummary(ledger.delta(target)!);
    expect(summary).toBe("Trust score: 100 → 100 (0). No change in finding counts.");
  });

  it("formats a mixed regression + improvement summary", () => {
    ledger = new TrustLedger(":memory:");
    ledger.initialize();
    const target = "fmt-mixed.com";

    const r1 = baseReport({ target, runId: "run-1", validatedFindings: [validatedFinding("high")] }); // 88
    ledger.record(r1, breakdownFor(r1));
    const r2 = baseReport({
      target,
      runId: "run-2",
      validatedFindings: [validatedFinding("critical")],
    }); // 75
    ledger.record(r2, breakdownFor(r2));

    const summary = ledger.formatDeltaSummary(ledger.delta(target)!);
    expect(summary).toContain("Regression: +1 critical in latest scan.");
    expect(summary).toContain("Improvement: -1 high resolved.");
    expect(summary.startsWith("Trust score: 88 → 75 (-13).")).toBe(true);
  });
});
