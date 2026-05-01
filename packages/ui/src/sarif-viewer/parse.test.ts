/**
 * Tests for SARIF parser utilities.
 * Uses bun:test (built-in).
 */

import { describe, it, expect } from "bun:test";
import { parseSarifRaw as parseSarif, groupByRule } from "./parse";
import type { SarifLog, SarifRun } from "./types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MINIMAL_SARIF: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: { driver: { name: "TestScanner", version: "1.0.0", rules: [] } },
      results: [],
    },
  ],
};

const RICH_SARIF: SarifLog = {
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Lyrie",
          version: "0.1.0",
          rules: [
            {
              id: "SQL001",
              name: "SqlInjection",
              shortDescription: { text: "Possible SQL injection" },
              defaultConfiguration: { level: "error" },
              helpUri: "https://lyrie.ai/rules/SQL001",
            },
            {
              id: "XSS002",
              name: "CrossSiteScripting",
              shortDescription: { text: "Reflected XSS" },
              defaultConfiguration: { level: "warning" },
            },
            {
              id: "INFO001",
              name: "InfoLeak",
              shortDescription: { text: "Sensitive info in response" },
              defaultConfiguration: { level: "note" },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "SQL001",
          level: "error",
          message: { text: "SQL injection in login form" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/auth/login.ts" },
                region: { startLine: 42 },
              },
            },
          ],
        },
        {
          ruleId: "SQL001",
          level: "error",
          message: { text: "SQL injection in search endpoint" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/search/query.ts" },
                region: { startLine: 17 },
              },
            },
          ],
        },
        {
          ruleId: "XSS002",
          level: "warning",
          message: { text: "Unsanitised user input in template" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/views/profile.ts" },
                region: { startLine: 88 },
              },
            },
          ],
        },
        {
          ruleId: "INFO001",
          level: "note",
          message: { text: "Stack trace exposed in error response" },
        },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------
// parseSarif
// ---------------------------------------------------------------------------

describe("parseSarif", () => {
  it("parses a valid SARIF JSON string", () => {
    const result = parseSarif(JSON.stringify(MINIMAL_SARIF));
    expect(result.version).toBe("2.1.0");
    expect(result.runs).toHaveLength(1);
  });

  it("accepts a pre-parsed object", () => {
    const result = parseSarif(MINIMAL_SARIF);
    expect(result.version).toBe("2.1.0");
  });

  it("throws on unsupported version string", () => {
    expect(() =>
      parseSarif(JSON.stringify({ version: "1.0.0", runs: [] }))
    ).toThrow("Unsupported SARIF version");
  });

  it("throws when version is missing", () => {
    expect(() => parseSarif(JSON.stringify({ runs: [] }))).toThrow(
      "Unsupported SARIF version"
    );
  });

  it("throws on null input", () => {
    expect(() => parseSarif("null")).toThrow();
  });

  it("throws on invalid JSON string", () => {
    expect(() => parseSarif("{bad json")).toThrow();
  });

  it("preserves runs array", () => {
    const result = parseSarif(RICH_SARIF);
    expect(result.runs).toHaveLength(1);
    expect(result.runs[0].tool.driver.name).toBe("Lyrie");
  });
});

// ---------------------------------------------------------------------------
// groupByRule
// ---------------------------------------------------------------------------

describe("groupByRule", () => {
  it("returns empty array for a run with no results", () => {
    const groups = groupByRule(MINIMAL_SARIF.runs[0]);
    expect(groups).toHaveLength(0);
  });

  it("groups results by ruleId", () => {
    const run = RICH_SARIF.runs[0];
    const groups = groupByRule(run);
    const sql = groups.find((g) => g.ruleId === "SQL001");
    expect(sql).toBeDefined();
    expect(sql!.results).toHaveLength(2);
  });

  it("sorts by severity — error first, then warning, note, none", () => {
    const groups = groupByRule(RICH_SARIF.runs[0]);
    expect(groups[0].level).toBe("error");
    expect(groups[1].level).toBe("warning");
    expect(groups[2].level).toBe("note");
  });

  it("resolves ruleName from rules array", () => {
    const groups = groupByRule(RICH_SARIF.runs[0]);
    const sql = groups.find((g) => g.ruleId === "SQL001");
    expect(sql!.ruleName).toBe("SqlInjection");
  });

  it("resolves ruleDescription from shortDescription", () => {
    const groups = groupByRule(RICH_SARIF.runs[0]);
    const sql = groups.find((g) => g.ruleId === "SQL001");
    expect(sql!.ruleDescription).toBe("Possible SQL injection");
  });

  it("resolves helpUri when present", () => {
    const groups = groupByRule(RICH_SARIF.runs[0]);
    const sql = groups.find((g) => g.ruleId === "SQL001");
    expect(sql!.helpUri).toBe("https://lyrie.ai/rules/SQL001");
  });

  it("falls back to ruleId as ruleName when rule not in rules array", () => {
    const run: SarifRun = {
      tool: { driver: { name: "Unknown", rules: [] } },
      results: [
        {
          ruleId: "ORPHAN",
          level: "warning",
          message: { text: "orphaned result" },
        },
      ],
    };
    const groups = groupByRule(run);
    expect(groups[0].ruleName).toBe("ORPHAN");
  });

  it("uses result.level when rule defaultConfiguration is absent", () => {
    const run: SarifRun = {
      tool: { driver: { name: "X", rules: [{ id: "R1", name: "Rule1" }] } },
      results: [{ ruleId: "R1", level: "note", message: { text: "msg" } }],
    };
    const groups = groupByRule(run);
    expect(groups[0].level).toBe("note");
  });

  it("defaults level to warning when neither result nor rule specifies one", () => {
    const run: SarifRun = {
      tool: { driver: { name: "X", rules: [] } },
      results: [{ ruleId: "R1", message: { text: "msg" } }],
    };
    const groups = groupByRule(run);
    expect(groups[0].level).toBe("warning");
  });

  it("handles run.results being undefined", () => {
    const run: SarifRun = {
      tool: { driver: { name: "X" } },
    };
    const groups = groupByRule(run);
    expect(groups).toHaveLength(0);
  });
});
