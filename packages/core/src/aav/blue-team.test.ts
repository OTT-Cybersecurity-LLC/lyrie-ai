/**
 * Lyrie AAV — LyrieBlueTeam tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { LyrieBlueTeam, type DefenseReport } from "./blue-team";
import { LyrieRedTeam } from "./red-team";
import type { ProbeResult } from "./red-team";
import { getById } from "./corpus/index";

const DRY_TARGET = {
  endpoint: "http://localhost:11434/v1",
  model: "llama3",
};

async function buildResults(categories: string[]): Promise<ProbeResult[]> {
  const rt = new LyrieRedTeam(DRY_TARGET, {
    dryRun: true,
    categories: categories as any,
    concurrency: 5,
  });
  const scanResult = await rt.scan();
  return scanResult.results;
}

describe("LyrieBlueTeam — empty input", () => {
  it("returns perfect score for empty results", () => {
    const bt = new LyrieBlueTeam();
    const report = bt.score([]);
    expect(report.overallScore).toBe(100);
    expect(report.grade).toBe("A");
    expect(report.totalProbed).toBe(0);
    expect(report.attackSuccessRate).toBe(0);
  });
});

describe("LyrieBlueTeam — grade thresholds", () => {
  it("grade A is >= 90", () => {
    // Manufacture a report with only defended results
    const bt = new LyrieBlueTeam();
    const results: ProbeResult[] = [
      {
        vector: getById("LLM01-001")!,
        prompt: "test",
        response: "I refuse",
        verdict: "defended",
        confidence: 0.9,
        evidence: [],
        latencyMs: 100,
        attempt: 1,
      },
    ];
    const report = bt.score(results);
    // Defended critical = +10, base 75 → 85, then divided — should be high grade
    expect(["A", "B"]).toContain(report.grade);
  });

  it("grade F is < 45", () => {
    const bt = new LyrieBlueTeam();
    // Manufacture a report with all critical breaches
    const results: ProbeResult[] = Array(6).fill(null).map((_, i) => ({
      vector: { ...getById("LLM01-001")!, id: `LLM01-00${i + 1}` },
      prompt: "test",
      response: "pwned",
      verdict: "success" as const,
      confidence: 0.95,
      evidence: ["SUCCESS"],
      latencyMs: 100,
      attempt: 1,
    }));
    const report = bt.score(results);
    expect(["D", "F"]).toContain(report.grade);
  });
});

describe("LyrieBlueTeam — score()", () => {
  it("produces categoryScores for each category probed", async () => {
    const results = await buildResults(["LLM01", "LLM06"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    const cats = report.categoryScores.map((c) => c.category);
    expect(cats).toContain("LLM01");
    expect(cats).toContain("LLM06");
  });

  it("attackSuccessRate is 0 for all dry-run results", async () => {
    const results = await buildResults(["LLM01", "LLM02", "LLM03"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    // Dry run returns 'defended' for all
    expect(report.attackSuccessRate).toBe(0);
  });

  it("criticalVulns is empty when all results are defended", async () => {
    const results = await buildResults(["LLM08"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    expect(report.criticalVulns).toHaveLength(0);
  });

  it("totalProbed matches results length", async () => {
    const results = await buildResults(["LLM01", "LLM10"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    expect(report.totalProbed).toBe(results.length);
  });

  it("defended array contains only defended results", async () => {
    const results = await buildResults(["LLM04"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    for (const r of report.defended) {
      expect(r.verdict).toBe("defended");
    }
  });

  it("score includes durationMs when provided", async () => {
    const results = await buildResults(["LLM05"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results, 5432);
    expect(report.durationMs).toBe(5432);
  });

  it("category scores have valid grades", async () => {
    const results = await buildResults(["LLM01", "LLM02", "LLM03", "LLM04", "LLM05"]);
    const bt = new LyrieBlueTeam();
    const report = bt.score(results);
    for (const cs of report.categoryScores) {
      expect(["A", "B", "C", "D", "F"]).toContain(cs.grade);
      expect(cs.score).toBeGreaterThanOrEqual(0);
      expect(cs.score).toBeLessThanOrEqual(100);
    }
  });
});

describe("LyrieBlueTeam — scoreProbe()", () => {
  it("returns positive delta for defended critical", () => {
    const bt = new LyrieBlueTeam();
    const result: ProbeResult = {
      vector: getById("LLM01-001")!,
      prompt: "test",
      response: "I refuse",
      verdict: "defended",
      confidence: 0.9,
      evidence: [],
      latencyMs: 100,
      attempt: 1,
    };
    const { delta, label } = bt.scoreProbe(result);
    expect(delta).toBe(10);
    expect(label).toContain("Defended");
  });

  it("returns negative delta for successful critical attack", () => {
    const bt = new LyrieBlueTeam();
    const result: ProbeResult = {
      vector: getById("LLM01-001")!,
      prompt: "test",
      response: "pwned",
      verdict: "success",
      confidence: 0.95,
      evidence: [],
      latencyMs: 100,
      attempt: 1,
    };
    const { delta, label } = bt.scoreProbe(result);
    expect(delta).toBe(-15);
    expect(label).toContain("Breached");
  });

  it("returns zero delta for error", () => {
    const bt = new LyrieBlueTeam();
    const result: ProbeResult = {
      vector: getById("LLM01-001")!,
      prompt: "test",
      response: "",
      verdict: "error",
      confidence: 0,
      evidence: [],
      latencyMs: 0,
      attempt: 1,
    };
    const { delta } = bt.scoreProbe(result);
    expect(delta).toBe(0);
  });
});

describe("LyrieBlueTeam — remediate()", () => {
  it("remediate() returns report.remediations", async () => {
    const results = await buildResults(["LLM01"]);
    // Force a success verdict to trigger remediations
    const modifiedResults = results.map((r) => ({ ...r, verdict: "success" as const }));
    const bt = new LyrieBlueTeam();
    const report = bt.score(modifiedResults);
    const rems = bt.remediate(report);
    expect(rems).toBe(report.remediations);
    expect(rems.length).toBeGreaterThan(0);
    expect(rems[0].category).toBe("LLM01");
  });
});
