/**
 * Lyrie Governance — Agent Permission Analyzer Tests
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { describe, it, expect } from "bun:test";
import { AgentPermissionAnalyzer, parseToolManifest } from "./permissions";
import type { ToolManifest } from "./permissions";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeManifest(tools: Array<{ name: string; [k: string]: unknown }>): ToolManifest {
  return { tools: tools.map((t) => ({ ...t })), agentId: "test-agent" };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("AgentPermissionAnalyzer — minimal risk", () => {
  it("empty manifest produces riskScore 0", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const report = analyzer.analyze({ tools: [], agentId: "empty" });
    expect(report.riskScore).toBe(0);
    expect(report.riskLevel).toBe("MINIMAL");
  });

  it("benign read-only tools produce low risk", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([
      { name: "get_weather", auditLog: true },
      { name: "search_web", auditLog: true },
    ]);
    const report = analyzer.analyze(manifest);
    // No risky patterns matched — only the global audit-log check matters
    expect(report.riskScore).toBeLessThan(50);
  });
});

describe("AgentPermissionAnalyzer — critical tools", () => {
  it("execute_code without controls produces critical finding", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([{ name: "execute_code" }]);
    const report = analyzer.analyze(manifest);
    const critical = report.findings.filter((f) => f.severity === "critical");
    expect(critical.length).toBeGreaterThan(0);
    expect(report.riskLevel).toMatch(/CRITICAL|HIGH/);
  });

  it("payment tool without approval produces critical finding", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([{ name: "process_payment" }]);
    const report = analyzer.analyze(manifest);
    const paymentFinding = report.findings.find((f) => f.tool === "process_payment");
    expect(paymentFinding).toBeDefined();
    expect(paymentFinding?.severity).toBe("critical");
  });

  it("database_write without human approval escalates to critical", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([{ name: "execute_sql", requiresApproval: false }]);
    const report = analyzer.analyze(manifest);
    const sqlFinding = report.findings.find((f) => f.tool === "execute_sql");
    expect(sqlFinding).toBeDefined();
    expect(["critical", "high"]).toContain(sqlFinding?.severity);
  });

  it("identity management tools without controls produce critical findings", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([{ name: "assign_role" }]);
    const report = analyzer.analyze(manifest);
    const finding = report.findings.find((f) => f.tool === "assign_role");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
  });
});

describe("AgentPermissionAnalyzer — missing audit log detection", () => {
  it("tools without auditLog flag trigger global audit-log gap", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([{ name: "get_weather", auditLog: false }]);
    const report = analyzer.analyze(manifest);
    expect(report.missingControls).toContain("auditLog");
  });

  it("all tools with auditLog=true do not trigger audit gap", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const manifest = makeManifest([
      { name: "get_weather", auditLog: true },
      { name: "list_files", auditLog: true },
    ]);
    const report = analyzer.analyze(manifest);
    // Audit log finding for wildcard only if auditLog is false
    const auditFinding = report.findings.find(
      (f) => f.tool === "*" && f.nistRef === "MEASURE-2.5",
    );
    expect(auditFinding).toBeUndefined();
  });
});

describe("AgentPermissionAnalyzer — report structure", () => {
  it("report has all required fields", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const report = analyzer.analyze(makeManifest([{ name: "send_email" }]));
    expect(typeof report.riskScore).toBe("number");
    expect(report.riskScore).toBeGreaterThanOrEqual(0);
    expect(report.riskScore).toBeLessThanOrEqual(100);
    expect(typeof report.riskLevel).toBe("string");
    expect(Array.isArray(report.excessivePermissions)).toBe(true);
    expect(Array.isArray(report.missingControls)).toBe(true);
    expect(Array.isArray(report.recommendations)).toBe(true);
    expect(Array.isArray(report.complianceFlags)).toBe(true);
    expect(Array.isArray(report.findings)).toBe(true);
    expect(typeof report.toolCount).toBe("number");
    expect(report.analyzedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("email tool flags NIST GOVERN-2.2 compliance", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const report = analyzer.analyze(makeManifest([{ name: "send_email" }]));
    const hasNist = report.complianceFlags.some((f) => f.includes("GOVERN-2.2"));
    expect(hasNist).toBe(true);
  });

  it("findings are sorted critical first", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const report = analyzer.analyze(makeManifest([
      { name: "send_email" },
      { name: "execute_code" },
    ]));
    if (report.findings.length > 1) {
      const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      for (let i = 1; i < report.findings.length; i++) {
        expect(
          severityOrder[report.findings[i]!.severity] >= severityOrder[report.findings[i - 1]!.severity],
        ).toBe(true);
      }
    }
  });
});

describe("AgentPermissionAnalyzer — formatReport", () => {
  it("produces non-empty markdown", () => {
    const analyzer = new AgentPermissionAnalyzer();
    const report = analyzer.analyze(makeManifest([{ name: "execute_code" }]));
    const md = AgentPermissionAnalyzer.formatReport(report, "test-agent");
    expect(md).toContain("# 🔐 Agent Permission Analysis Report");
    expect(md).toContain("Risk Score");
    expect(md.length).toBeGreaterThan(200);
  });
});

describe("parseToolManifest — JSON format", () => {
  it("parses OpenAI-style tool manifest from JSON file", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "lyrie-test-"));
    const manifest = {
      agentId: "my-agent",
      tools: [
        { name: "send_email", description: "Sends emails" },
        { name: "read_file", auditLog: true, scopes: ["/data"] },
      ],
    };
    const filePath = path.join(tmpDir, "manifest.json");
    fs.writeFileSync(filePath, JSON.stringify(manifest));
    const parsed = parseToolManifest(filePath);
    expect(parsed.agentId).toBe("my-agent");
    expect(parsed.tools.length).toBe(2);
    expect(parsed.tools[0]!.name).toBe("send_email");
    expect(parsed.tools[1]!.auditLog).toBe(true);
    fs.rmSync(tmpDir, { recursive: true });
  });
});
