/**
 * Lyrie AAV — AavReporter tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { AavReporter } from "./reporter";
import { LyrieRedTeam } from "./red-team";
import { LyrieBlueTeam } from "./blue-team";

async function buildReporter(categories: string[]) {
  const rt = new LyrieRedTeam(
    { endpoint: "http://localhost:11434/v1", model: "llama3" },
    { dryRun: true, categories: categories as any, concurrency: 3 },
  );
  const scanResult = await rt.scan();
  const bt = new LyrieBlueTeam();
  const report = bt.score(scanResult.results, scanResult.durationMs);
  return new AavReporter(scanResult, report);
}

describe("AavReporter — SARIF", () => {
  it("produces valid SARIF 2.1.0 structure", async () => {
    const reporter = await buildReporter(["LLM01", "LLM06"]);
    const sarif = reporter.toSarif();
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif");
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs.length).toBe(1);
  });

  it("SARIF run has tool.driver with LyrieAAV name", async () => {
    const reporter = await buildReporter(["LLM01"]);
    const sarif = reporter.toSarif();
    expect(sarif.runs[0].tool.driver.name).toBe("LyrieAAV");
    expect(sarif.runs[0].tool.driver.version).toBe("0.6.0");
    expect(sarif.runs[0].tool.driver.informationUri).toBe("https://lyrie.ai");
  });

  it("SARIF results array exists (may be empty for dry-run)", async () => {
    const reporter = await buildReporter(["LLM01"]);
    const sarif = reporter.toSarif();
    expect(Array.isArray(sarif.runs[0].results)).toBe(true);
    // Dry run returns defended, so no results
    expect(sarif.runs[0].results.length).toBe(0);
  });

  it("SARIF with success probes has results with ruleId", async () => {
    // Manually build a scan result with a success verdict
    const rt = new LyrieRedTeam(
      { endpoint: "http://localhost:11434/v1", model: "llama3" },
      { dryRun: true, categories: ["LLM01"] },
    );
    const scanResult = await rt.scan();
    // Inject a success result
    const successResult = {
      ...scanResult.results[0],
      verdict: "success" as const,
      confidence: 0.9,
      evidence: ["SUCCESS_MATCH: as DAN"],
    };
    const modifiedScan = { ...scanResult, results: [successResult] };
    const bt = new LyrieBlueTeam();
    const report = bt.score([successResult]);
    const reporter = new AavReporter(modifiedScan, report);
    const sarif = reporter.toSarif();
    expect(sarif.runs[0].results.length).toBe(1);
    expect(sarif.runs[0].results[0].ruleId).toMatch(/^LLM\d{2}-\d{3}$/);
    expect(sarif.runs[0].tool.driver.rules.length).toBe(1);
  });

  it("SARIF severity maps correctly", async () => {
    const rt = new LyrieRedTeam(
      { endpoint: "http://localhost:11434/v1", model: "llama3" },
      { dryRun: true, categories: ["LLM01"] },
    );
    const scanResult = await rt.scan();
    const successResult = {
      ...scanResult.results[0], // LLM01-001 is critical
      verdict: "success" as const,
    };
    const modifiedScan = { ...scanResult, results: [successResult] };
    const bt = new LyrieBlueTeam();
    const report = bt.score([successResult]);
    const reporter = new AavReporter(modifiedScan, report);
    const sarif = reporter.toSarif();
    expect(sarif.runs[0].results[0].level).toBe("error"); // critical → error
  });
});

describe("AavReporter — Markdown", () => {
  it("produces Markdown with grade header", async () => {
    const reporter = await buildReporter(["LLM01", "LLM08"]);
    const md = reporter.toMarkdown();
    expect(md).toContain("Grade");
    expect(md).toContain("LyrieAAV");
  });

  it("Markdown includes OWASP coverage table", async () => {
    const reporter = await buildReporter(["LLM01", "LLM02"]);
    const md = reporter.toMarkdown();
    expect(md).toContain("OWASP LLM Top 10 Coverage");
    expect(md).toContain("LLM01");
    expect(md).toContain("LLM02");
  });

  it("Markdown includes endpoint", async () => {
    const reporter = await buildReporter(["LLM06"]);
    const md = reporter.toMarkdown();
    expect(md).toContain("http://localhost:11434/v1");
  });

  it("Markdown includes scan ID", async () => {
    const reporter = await buildReporter(["LLM03"]);
    const md = reporter.toMarkdown();
    expect(md).toContain("aav-");
  });
});

describe("AavReporter — JSON", () => {
  it("toJson returns valid JSON", async () => {
    const reporter = await buildReporter(["LLM01"]);
    const json = reporter.toJson();
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("JSON has version 0.6.0", async () => {
    const reporter = await buildReporter(["LLM01"]);
    const obj = JSON.parse(reporter.toJson());
    expect(obj.version).toBe("0.6.0");
    expect(obj.generator).toBe("LyrieAAV");
  });

  it("JSON includes target endpoint", async () => {
    const reporter = await buildReporter(["LLM04"]);
    const obj = JSON.parse(reporter.toJson());
    expect(obj.target.endpoint).toBe("http://localhost:11434/v1");
  });

  it("JSON includes probeResults array", async () => {
    const reporter = await buildReporter(["LLM05"]);
    const obj = JSON.parse(reporter.toJson());
    expect(Array.isArray(obj.probeResults)).toBe(true);
    expect(obj.probeResults.length).toBeGreaterThan(0);
    expect(obj.probeResults[0].id).toBeDefined();
    expect(obj.probeResults[0].verdict).toBeDefined();
  });
});
