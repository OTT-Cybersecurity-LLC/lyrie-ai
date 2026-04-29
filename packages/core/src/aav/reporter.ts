/**
 * Lyrie AAV — AavReporter
 *
 * Converts a DefenseReport + ProbeResult[] into SARIF 2.1.0, Markdown, or JSON.
 * SARIF output is compatible with GitHub Code Scanning.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import type { DefenseReport } from "./blue-team";
import type { ProbeResult, RedTeamScanResult } from "./red-team";
import type { OwaspLlmCategory } from "./corpus/index";

// ─── SARIF 2.1.0 types (minimal) ─────────────────────────────────────────────

interface SarifResult {
  ruleId: string;
  message: { text: string };
  level: "error" | "warning" | "note" | "none";
  locations: SarifLocation[];
  properties?: Record<string, unknown>;
}

interface SarifLocation {
  physicalLocation?: {
    artifactLocation: { uri: string };
    region?: { startLine: number };
  };
  logicalLocations?: Array<{ name: string; kind: string }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    tags: string[];
    "security-severity": string;
    owaspCategory: string;
  };
}

interface SarifOutput {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    properties?: Record<string, unknown>;
  }>;
}

// ─── Severity mappers ─────────────────────────────────────────────────────────

function toSarifLevel(severity: string): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    default:
      return "none";
  }
}

// SARIF "security-severity" uses CVSS-like numeric (0-10)
function toSecuritySeverity(severity: string): string {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.5";
    case "medium":
      return "5.0";
    case "low":
      return "2.5";
    default:
      return "0.0";
  }
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

const OWASP_NAMES: Record<OwaspLlmCategory, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Insecure Output Handling",
  LLM03: "Training Data Poisoning",
  LLM04: "Model Denial of Service",
  LLM05: "Supply Chain Vulnerabilities",
  LLM06: "Sensitive Information Disclosure",
  LLM07: "Insecure Plugin Design",
  LLM08: "Excessive Agency",
  LLM09: "Overreliance",
  LLM10: "Model Theft",
};

// ─── AavReporter ──────────────────────────────────────────────────────────────

export class AavReporter {
  private scanResult: RedTeamScanResult;
  private report: DefenseReport;

  constructor(scanResult: RedTeamScanResult, report: DefenseReport) {
    this.scanResult = scanResult;
    this.report = report;
  }

  // ─── SARIF 2.1.0 ──────────────────────────────────────────────────────────

  toSarif(): SarifOutput {
    const successfulProbes = this.scanResult.results.filter(
      (r) => r.verdict === "success" || r.verdict === "partial",
    );

    // Deduplicate rules by vector ID
    const ruleMap = new Map<string, SarifRule>();
    for (const probe of successfulProbes) {
      const v = probe.vector;
      if (!ruleMap.has(v.id)) {
        ruleMap.set(v.id, {
          id: v.id,
          name: v.name.replace(/\s+/g, ""),
          shortDescription: { text: `${v.category}: ${v.name}` },
          fullDescription: { text: v.description },
          helpUri: `https://owasp.org/www-project-top-10-for-large-language-model-applications/#${v.category.toLowerCase()}`,
          properties: {
            tags: ["security", "ai", "llm", v.category, ...v.mitreTactics.map((t) => t.split(" ")[0])],
            "security-severity": toSecuritySeverity(v.severity),
            owaspCategory: v.category,
          },
        });
      }
    }

    const sarifResults: SarifResult[] = successfulProbes.map((probe) => {
      const v = probe.vector;
      return {
        ruleId: v.id,
        message: {
          text: `[${v.severity.toUpperCase()}] ${v.name}: Attack succeeded against target. Confidence: ${(probe.confidence * 100).toFixed(0)}%. Evidence: ${probe.evidence.slice(0, 2).join("; ")}`,
        },
        level: toSarifLevel(v.severity),
        locations: [
          {
            logicalLocations: [
              {
                name: this.scanResult.target.endpoint,
                kind: "aiEndpoint",
              },
            ],
          },
        ],
        properties: {
          verdict: probe.verdict,
          confidence: probe.confidence,
          latencyMs: probe.latencyMs,
          mitreTactics: v.mitreTactics,
          nistAiRmfRef: v.nistAiRmfRef,
          euAiActRef: v.euAiActRef,
          attempt: probe.attempt,
        },
      };
    });

    return {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "LyrieAAV",
              version: "0.6.0",
              informationUri: "https://lyrie.ai",
              rules: [...ruleMap.values()],
            },
          },
          results: sarifResults,
          properties: {
            scanId: this.scanResult.scanId,
            endpoint: this.scanResult.target.endpoint,
            overallGrade: this.report.grade,
            overallScore: this.report.overallScore,
            durationMs: this.scanResult.durationMs,
          },
        },
      ],
    };
  }

  // ─── Markdown ──────────────────────────────────────────────────────────────

  toMarkdown(): string {
    const r = this.report;
    const s = this.scanResult;
    const gradeEmoji: Record<string, string> = {
      A: "🟢",
      B: "🟡",
      C: "🟠",
      D: "🔴",
      F: "💀",
    };

    const lines: string[] = [
      `# ${gradeEmoji[r.grade] ?? "⚪"} LyrieAAV Red Team Report — Grade ${r.grade}`,
      "",
      `> **Endpoint:** \`${s.target.endpoint}\`  `,
      `> **Score:** ${r.overallScore}/100  `,
      `> **Vectors probed:** ${r.totalProbed}  `,
      `> **Attack success rate:** ${(r.attackSuccessRate * 100).toFixed(1)}%  `,
      `> **Duration:** ${((s.durationMs ?? 0) / 1000).toFixed(1)}s  `,
      `> **Scan ID:** \`${s.scanId}\`  `,
      "",
    ];

    // Critical vulns table
    if (r.criticalVulns.length > 0) {
      lines.push("## 🔴 Critical Vulnerabilities");
      lines.push("");
      lines.push("| ID | Name | Confidence | Evidence |");
      lines.push("|---|---|---|---|");
      for (const v of r.criticalVulns) {
        const ev = v.evidence.slice(0, 1).join("; ").replace(/\|/g, "\\|").slice(0, 80);
        lines.push(
          `| \`${v.vector.id}\` | ${v.vector.name} | ${(v.confidence * 100).toFixed(0)}% | ${ev} |`,
        );
      }
      lines.push("");
    }

    // High vulns
    if (r.highVulns.length > 0) {
      lines.push("## 🟠 High Vulnerabilities");
      lines.push("");
      lines.push("| ID | Name | Confidence | Evidence |");
      lines.push("|---|---|---|---|");
      for (const v of r.highVulns) {
        const ev = v.evidence.slice(0, 1).join("; ").replace(/\|/g, "\\|").slice(0, 80);
        lines.push(
          `| \`${v.vector.id}\` | ${v.vector.name} | ${(v.confidence * 100).toFixed(0)}% | ${ev} |`,
        );
      }
      lines.push("");
    }

    // OWASP coverage table
    lines.push("## 📊 OWASP LLM Top 10 Coverage");
    lines.push("");
    lines.push("| Category | Name | Grade | Score | Probed | Breached | Defended |");
    lines.push("|---|---|---|---|---|---|---|");
    for (const cat of r.categoryScores.sort((a, b) => a.category.localeCompare(b.category))) {
      const gradeE = gradeEmoji[cat.grade] ?? "⚪";
      lines.push(
        `| ${cat.category} | ${cat.categoryName} | ${gradeE} ${cat.grade} | ${cat.score} | ${cat.probeCount} | ${cat.successCount + cat.partialCount} | ${cat.defendedCount} |`,
      );
    }
    lines.push("");

    // Remediations
    if (r.remediations.length > 0) {
      lines.push("## 🔧 Recommended Actions");
      lines.push("");
      for (const rem of r.remediations) {
        const sevEmoji = rem.priority === "immediate" ? "🚨" : rem.priority === "high" ? "🔴" : rem.priority === "medium" ? "🟡" : "🔵";
        lines.push(`### ${sevEmoji} ${rem.title} \`[${rem.category}]\``);
        lines.push("");
        lines.push(rem.description);
        lines.push("");
        lines.push("**Implementation steps:**");
        for (const step of rem.implementation) {
          lines.push(`- ${step}`);
        }
        lines.push("");
        lines.push(`*NIST AI RMF: ${rem.nistAiRmfRef} | EU AI Act: ${rem.euAiActRef}*`);
        lines.push("");
      }
    }

    // Footer
    lines.push("---");
    lines.push(`*Generated by [LyrieAAV](https://lyrie.ai) v0.6.0 — OTT Cybersecurity LLC*`);
    lines.push("");

    return lines.join("\n");
  }

  // ─── JSON ──────────────────────────────────────────────────────────────────

  toJson(): string {
    return JSON.stringify(
      {
        version: "0.6.0",
        generator: "LyrieAAV",
        generatedAt: new Date().toISOString(),
        scanId: this.scanResult.scanId,
        target: this.scanResult.target,
        report: this.report,
        probeResults: this.scanResult.results.map((r) => ({
          id: r.vector.id,
          category: r.vector.category,
          name: r.vector.name,
          severity: r.vector.severity,
          verdict: r.verdict,
          confidence: r.confidence,
          evidence: r.evidence,
          latencyMs: r.latencyMs,
          attempt: r.attempt,
          error: r.error,
        })),
      },
      null,
      2,
    );
  }
}
