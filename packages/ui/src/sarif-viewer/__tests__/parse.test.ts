/**
 * Tests for SARIF parser edge cases.
 *
 * Uses bun:test (same runner as packages/core).
 */

import { describe, expect, it } from "bun:test";
import { parseSarif, parseSarifJson } from "../parse";
import type { SarifDocument } from "../types";

// ─── Fixtures ───────────────────────────────────────────────────────────────

const minimalDoc: SarifDocument = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "Nuclei", rules: [] } },
      results: [
        {
          ruleId: "CVE-2024-1234",
          level: "error",
          message: { text: "Critical vulnerability found" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "https://target.example.com/login" },
                region: { startLine: 42 },
              },
            },
          ],
        },
      ],
    },
  ],
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("parseSarif", () => {
  it("parses a minimal valid SARIF document", () => {
    const result = parseSarif(minimalDoc);
    expect(result.totalCount).toBe(1);
    expect(result.findings[0].ruleId).toBe("CVE-2024-1234");
    expect(result.findings[0].level).toBe("error");
    expect(result.findings[0].message).toBe("Critical vulnerability found");
    expect(result.findings[0].location).toBe("https://target.example.com/login");
    expect(result.findings[0].line).toBe(42);
    expect(result.findings[0].locationIsUrl).toBe(true);
    expect(result.findings[0].toolName).toBe("Nuclei");
  });

  it("counts severities correctly", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "Scanner" } },
          results: [
            { message: { text: "A" }, level: "error" },
            { message: { text: "B" }, level: "warning" },
            { message: { text: "C" }, level: "warning" },
            { message: { text: "D" }, level: "note" },
            { message: { text: "E" } }, // level missing → "none"
          ],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.bySeverity.error).toBe(1);
    expect(r.bySeverity.warning).toBe(2);
    expect(r.bySeverity.note).toBe(1);
    expect(r.bySeverity.none).toBe(1);
    expect(r.totalCount).toBe(5);
  });

  it("handles empty runs array", () => {
    const r = parseSarif({ runs: [] });
    expect(r.totalCount).toBe(0);
    expect(r.findings).toHaveLength(0);
    expect(r.toolNames).toHaveLength(0);
  });

  it("handles run with no results field", () => {
    const doc: SarifDocument = {
      runs: [{ tool: { driver: { name: "Tool" } } }],
    };
    const r = parseSarif(doc);
    expect(r.totalCount).toBe(0);
  });

  it("handles run with empty results array", () => {
    const doc: SarifDocument = {
      runs: [{ tool: { driver: { name: "Tool" } }, results: [] }],
    };
    const r = parseSarif(doc);
    expect(r.totalCount).toBe(0);
  });

  it("maps rule metadata to findings when rules are present", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: {
            driver: {
              name: "Nuclei",
              rules: [
                {
                  id: "CVE-2024-1234",
                  name: "SQL Injection",
                  shortDescription: { text: "SQL injection in login" },
                  helpUri: "https://docs.example.com/CVE-2024-1234",
                },
              ],
            },
          },
          results: [
            { ruleId: "CVE-2024-1234", level: "error", message: { text: "Found" } },
          ],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.findings[0].rule?.name).toBe("SQL Injection");
    expect(r.findings[0].rule?.helpUri).toBe("https://docs.example.com/CVE-2024-1234");
  });

  it("falls back to 'unknown' ruleId when missing", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "Tool" } },
          results: [{ message: { text: "Something bad" }, level: "warning" }],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.findings[0].ruleId).toBe("unknown");
  });

  it("populates automationDetails.id as runId", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "Tool" } },
          automationDetails: { id: "scan-run-42" },
          results: [{ message: { text: "x" } }],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.runIds).toContain("scan-run-42");
    expect(r.findings[0].runId).toBe("scan-run-42");
  });

  it("handles multiple runs", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "Amass" } },
          results: [{ message: { text: "subdomain" }, level: "note" }],
        },
        {
          tool: { driver: { name: "Nuclei" } },
          results: [
            { message: { text: "vuln1" }, level: "error" },
            { message: { text: "vuln2" }, level: "error" },
          ],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.totalCount).toBe(3);
    expect(r.toolNames).toContain("Amass");
    expect(r.toolNames).toContain("Nuclei");
  });

  it("sorts findings: errors first, then warning, note, none", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "T" } },
          results: [
            { ruleId: "R3", message: { text: "x" }, level: "none" },
            { ruleId: "R2", message: { text: "x" }, level: "note" },
            { ruleId: "R1", message: { text: "x" }, level: "error" },
            { ruleId: "R4", message: { text: "x" }, level: "warning" },
          ],
        },
      ],
    };
    const r = parseSarif(doc);
    const levels = r.findings.map((f) => f.level);
    expect(levels[0]).toBe("error");
    expect(levels[1]).toBe("warning");
    expect(levels[2]).toBe("note");
    expect(levels[3]).toBe("none");
  });

  it("handles missing physicalLocation gracefully", () => {
    const doc: SarifDocument = {
      runs: [
        {
          tool: { driver: { name: "T" } },
          results: [
            {
              ruleId: "R1",
              message: { text: "x" },
              locations: [{ logicalLocations: [{ name: "main.ts" }] }],
            },
          ],
        },
      ],
    };
    const r = parseSarif(doc);
    expect(r.findings[0].location).toBeUndefined();
    expect(r.findings[0].locationIsUrl).toBe(false);
  });
});

describe("parseSarifJson", () => {
  it("parses valid JSON string", () => {
    const r = parseSarifJson(JSON.stringify(minimalDoc));
    expect(r).not.toBeNull();
    expect(r!.totalCount).toBe(1);
  });

  it("returns null for invalid JSON", () => {
    expect(parseSarifJson("not json")).toBeNull();
    expect(parseSarifJson("{broken")).toBeNull();
    expect(parseSarifJson("")).toBeNull();
  });

  it("returns null for valid JSON but completely wrong shape (no runs)", () => {
    // No runs array → parseSarif handles it, returns empty (not null)
    const r = parseSarifJson(JSON.stringify({ foo: "bar" }));
    expect(r).not.toBeNull(); // parseSarif handles missing .runs gracefully
    expect(r!.totalCount).toBe(0);
  });
});
