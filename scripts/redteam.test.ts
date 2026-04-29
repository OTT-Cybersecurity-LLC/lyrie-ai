/**
 * Lyrie AAV — CLI (redteam.ts) tests
 * Tests the CLI logic without executing the binary.
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { LyrieRedTeam } from "../packages/core/src/aav/red-team";
import { LyrieBlueTeam } from "../packages/core/src/aav/blue-team";
import { AavReporter } from "../packages/core/src/aav/reporter";
import type { AttackSeverity } from "../packages/core/src/aav/corpus/index";

// Helper: build scan + report
async function fullScan(endpoint: string, opts: { dryRun?: boolean; categories?: string[] } = {}) {
  const rt = new LyrieRedTeam(
    { endpoint, model: "llama3" },
    { dryRun: opts.dryRun ?? true, categories: (opts.categories ?? []) as any, concurrency: 3 },
  );
  const scanResult = await rt.scan();
  const bt = new LyrieBlueTeam();
  const report = bt.score(scanResult.results, scanResult.durationMs);
  return { scanResult, report, reporter: new AavReporter(scanResult, report) };
}

describe("CLI integration — dry-run scan", () => {
  it("completes dry-run against localhost endpoint", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1", {
      dryRun: true,
      categories: ["LLM01"],
    });
    expect(scanResult.totalProbed).toBeGreaterThan(0);
    expect(scanResult.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("dry-run all categories completes", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1");
    expect(scanResult.totalProbed).toBeGreaterThanOrEqual(50);
  });

  it("SARIF output is valid JSON string", async () => {
    const { reporter } = await fullScan("http://localhost:11434/v1", { categories: ["LLM06"] });
    const sarif = JSON.stringify(reporter.toSarif(), null, 2);
    expect(() => JSON.parse(sarif)).not.toThrow();
  });

  it("JSON output is valid", async () => {
    const { reporter } = await fullScan("http://localhost:11434/v1", { categories: ["LLM08"] });
    expect(() => JSON.parse(reporter.toJson())).not.toThrow();
  });

  it("Markdown output is non-empty string", async () => {
    const { reporter } = await fullScan("http://localhost:11434/v1", { categories: ["LLM10"] });
    const md = reporter.toMarkdown();
    expect(typeof md).toBe("string");
    expect(md.length).toBeGreaterThan(100);
  });
});

describe("CLI integration — fail-on logic", () => {
  const severityOrder: AttackSeverity[] = ["low", "medium", "high", "critical"];

  it("fail-on critical: no failing findings in dry-run", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1", { dryRun: true });
    const failOn: AttackSeverity = "critical";
    const failIdx = severityOrder.indexOf(failOn);
    const hasFailingFindings = scanResult.results.some(
      (r) =>
        (r.verdict === "success" || r.verdict === "partial") &&
        severityOrder.indexOf(r.vector.severity) >= failIdx,
    );
    // Dry run always returns 'defended'
    expect(hasFailingFindings).toBe(false);
  });

  it("fail-on high: no failing findings in dry-run", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1", { dryRun: true });
    const failOn: AttackSeverity = "high";
    const failIdx = severityOrder.indexOf(failOn);
    const hasFailingFindings = scanResult.results.some(
      (r) =>
        (r.verdict === "success" || r.verdict === "partial") &&
        severityOrder.indexOf(r.vector.severity) >= failIdx,
    );
    expect(hasFailingFindings).toBe(false);
  });
});

describe("CLI integration — options passthrough", () => {
  it("category filter narrows probes", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1", {
      dryRun: true,
      categories: ["LLM01"],
    });
    for (const r of scanResult.results) {
      expect(r.vector.category).toBe("LLM01");
    }
  });

  it("report grade is a valid letter", async () => {
    const { report } = await fullScan("http://localhost:11434/v1");
    expect(["A", "B", "C", "D", "F"]).toContain(report.grade);
  });

  it("scanId starts with aav-", async () => {
    const { scanResult } = await fullScan("http://localhost:11434/v1");
    expect(scanResult.scanId).toMatch(/^aav-/);
  });
});
