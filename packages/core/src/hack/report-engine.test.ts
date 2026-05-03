/**
 * Lyrie Hack — Report Engine tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, expect, it } from "bun:test";

import {
  REPORT_ENGINE_VERSION,
  toJson,
  toMarkdown,
  toSarif,
  type HackReport,
  type Severity,
} from "./report-engine";

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function makeReport(over: Partial<HackReport> = {}): HackReport {
  const c = emptyCounts();
  c.high = 1;
  c.critical = 1;
  return {
    target: "/tmp/x",
    runId: "hack-test",
    mode: "standard",
    startedAt: "2026-05-04T00:00:00.000Z",
    finishedAt: "2026-05-04T00:00:01.000Z",
    durationMs: 1000,
    threatMatches: [],
    validatedFindings: [
      {
        finding: {
          id: "f-1",
          title: "SQL injection in user lookup",
          severity: "critical",
          description: "User id concatenated into SQL.",
          file: "server.js",
          line: 17,
          cwe: "CWE-89",
          category: "sql-injection",
          evidence: "db.query(`SELECT * FROM users WHERE id = ${id}`)",
        },
        confirmed: true,
        stages: [
          { stage: "A", passed: true, reason: "ok" },
          { stage: "B", passed: true, reason: "ok" },
          { stage: "C", passed: true, reason: "ok" },
          { stage: "D", passed: true, reason: "ok" },
        ],
        confidence: 0.92,
        signature: "Lyrie.ai by OTT Cybersecurity LLC",
      },
    ],
    secretFindings: [
      {
        id: "lyrie-secret-aws-1",
        type: "aws-access-key-id",
        severity: "high",
        file: "config.js",
        line: 3,
        redactedSample: "AKIA***LE",
        length: 20,
        confidence: 0.99,
        signature: "Lyrie.ai by OTT Cybersecurity LLC",
      },
    ],
    remediations: [],
    counts: c,
    totalFindings: 2,
    aavRan: false,
    selfScanRan: true,
    selfScanVerdict: "clean",
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
    reporterVersion: REPORT_ENGINE_VERSION,
    ...over,
  };
}

describe("toSarif", () => {
  it("emits SARIF 2.1.0 with the Lyrie driver", () => {
    const sarif = toSarif(makeReport());
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].tool.driver.name).toBe("Lyrie Hack");
    expect(sarif.runs[0].tool.driver.informationUri).toBe("https://lyrie.ai");
  });

  it("maps severity to SARIF level", () => {
    const sarif = toSarif(makeReport());
    const result = sarif.runs[0].results.find((r) => r.ruleId === "CWE-89");
    expect(result?.level).toBe("error");
    const secretResult = sarif.runs[0].results.find((r) => r.ruleId.startsWith("lyrie-secret-"));
    expect(secretResult?.level).toBe("error");
  });

  it("includes a security-severity property", () => {
    const sarif = toSarif(makeReport());
    const rule = sarif.runs[0].tool.driver.rules.find((r) => r.id === "CWE-89");
    expect(rule?.properties["security-severity"]).toBe("9.5");
  });

  it("attaches partial fingerprints for stable diffing", () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs[0].results[0].partialFingerprints?.lyrie).toBeDefined();
  });

  it("never emits an empty results array on a non-empty report", () => {
    const sarif = toSarif(makeReport());
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });
});

describe("toMarkdown", () => {
  it("starts with the Lyrie Hack Report header", () => {
    const md = toMarkdown(makeReport());
    expect(md.startsWith("# 🛡️")).toBe(true);
  });

  it("includes the executive summary line", () => {
    const md = toMarkdown(makeReport());
    expect(md).toContain("## Executive Summary");
  });

  it("groups findings by severity", () => {
    const md = toMarkdown(makeReport());
    expect(md).toContain("CRITICAL");
    expect(md).toContain("HIGH");
  });

  it("includes the Lyrie signature footer", () => {
    const md = toMarkdown(makeReport());
    expect(md).toContain("Lyrie.ai by OTT Cybersecurity LLC");
  });

  it("renders a remediation block when remediations are present", () => {
    const r = makeReport({
      remediations: [
        {
          findingId: "f-1",
          suggestion: {
            description: "Use parameterized queries.",
            diffHint: { before: "x", after: "y" },
            testCommand: "bun test",
            referenceCwe: "CWE-89",
            confidence: 0.9,
            signature: "Lyrie.ai by OTT Cybersecurity LLC",
          },
        },
      ],
    });
    const md = toMarkdown(r);
    expect(md).toContain("## Remediation Plan");
    expect(md).toContain("CWE-89");
  });

  it("notes when no findings were produced", () => {
    const md = toMarkdown({
      ...makeReport(),
      validatedFindings: [],
      secretFindings: [],
      counts: emptyCounts(),
      totalFindings: 0,
    });
    expect(md).toContain("No findings");
  });
});

describe("toJson", () => {
  it("round-trips a report via JSON.parse", () => {
    const json = toJson(makeReport());
    const parsed = JSON.parse(json);
    expect(parsed.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
    expect(parsed.totalFindings).toBe(2);
  });
});
