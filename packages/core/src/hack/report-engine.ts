/**
 * Lyrie Hack — Report Engine.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Assembles every phase output of `lyrie hack <target>` into:
 *   - SARIF 2.1.0 (machine, GitHub Code Scanning ingestible)
 *   - Markdown (human, executive-summary first)
 *   - JSON     (full raw, for downstream tooling)
 *
 * © OTT Cybersecurity LLC.
 */

import type { ValidatedFinding } from "../pentest/stages-validator";
import type { AttackSurface } from "../pentest/attack-surface";
import type { ThreatIntelMatch } from "../pentest/threat-intel";
import type { DependencyGraph } from "./dependency-graph";
import type { SecretFinding } from "./secret-detector";
import type { RemediationSuggestion } from "./auto-remediation";

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface HackReport {
  /** Which target the run hit. */
  target: string;
  /** Run id (UUID-ish). */
  runId: string;
  /** Run mode. */
  mode: "quick" | "standard" | "deep" | "paranoid";
  /** Wall-clock timing. */
  startedAt: string;
  finishedAt: string;
  durationMs: number;

  /** Phase outputs. */
  surface?: AttackSurface;
  dependencyGraph?: DependencyGraph;
  threatMatches: ThreatIntelMatch[];
  validatedFindings: ValidatedFinding[];
  secretFindings: SecretFinding[];
  remediations: Array<{
    findingId: string;
    suggestion: RemediationSuggestion;
  }>;

  /** Severity rollup. */
  counts: Record<Severity, number>;
  totalFindings: number;

  /** Whether the AAV phase ran. */
  aavRan: boolean;
  /** Whether the self-scan phase ran. */
  selfScanRan: boolean;
  selfScanVerdict?: "clean" | "suspicious" | "blocked";

  /** Lyrie signature. */
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
  reporterVersion: string;
}

export const REPORT_ENGINE_VERSION = "lyrie-report-1.0.0";

// ─── SARIF 2.1.0 ─────────────────────────────────────────────────────────────

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}
interface SarifRun {
  tool: { driver: { name: string; version: string; informationUri: string; rules: SarifRule[] } };
  results: SarifResult[];
  invocations: Array<{ executionSuccessful: boolean; endTimeUtc: string }>;
}
interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: "note" | "warning" | "error" };
  properties: Record<string, unknown>;
}
interface SarifResult {
  ruleId: string;
  level: "note" | "warning" | "error";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
}

const SEVERITY_TO_SARIF: Record<Severity, "note" | "warning" | "error"> = {
  info: "note",
  low: "note",
  medium: "warning",
  high: "error",
  critical: "error",
};

export function toSarif(report: HackReport): SarifLog {
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const v of report.validatedFindings) {
    const f = v.finding;
    const ruleId = f.cwe ?? `lyrie-${f.category ?? "other"}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: f.category ?? "vulnerability",
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        defaultConfiguration: { level: SEVERITY_TO_SARIF[f.severity] },
        properties: { "security-severity": severityScore(f.severity) },
      });
    }
    results.push({
      ruleId,
      level: SEVERITY_TO_SARIF[f.severity],
      message: { text: f.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file ?? "unknown" },
            region: f.line ? { startLine: f.line } : undefined,
          },
        },
      ],
      partialFingerprints: { lyrie: f.id },
      properties: {
        confirmed: v.confirmed,
        confidence: v.confidence,
        stages: v.stages.map((s) => `${s.stage}:${s.passed ? "pass" : "fail"}`).join(","),
      },
    });
  }

  for (const s of report.secretFindings) {
    const ruleId = `lyrie-secret-${s.type}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: s.type,
        shortDescription: { text: `Hardcoded ${s.type}` },
        fullDescription: {
          text: `Lyrie SecretDetector identified a hardcoded ${s.type}. Hardcoded credentials in source must be rotated and replaced with env vars or a secret manager.`,
        },
        defaultConfiguration: { level: SEVERITY_TO_SARIF[s.severity] },
        properties: { "security-severity": severityScore(s.severity) },
      });
    }
    results.push({
      ruleId,
      level: SEVERITY_TO_SARIF[s.severity],
      message: { text: `Hardcoded ${s.type} detected (${s.redactedSample})` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: s.file },
            region: { startLine: s.line },
          },
        },
      ],
      partialFingerprints: { lyrie: s.id },
      properties: { confidence: s.confidence },
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Lyrie Hack",
            version: REPORT_ENGINE_VERSION,
            informationUri: "https://lyrie.ai",
            rules: Array.from(rules.values()),
          },
        },
        results,
        invocations: [
          { executionSuccessful: true, endTimeUtc: report.finishedAt },
        ],
      },
    ],
  };
}

function severityScore(s: Severity): string {
  switch (s) {
    case "critical":
      return "9.5";
    case "high":
      return "7.5";
    case "medium":
      return "5.0";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

// ─── Markdown ────────────────────────────────────────────────────────────────

export function toMarkdown(report: HackReport): string {
  const lines: string[] = [];
  lines.push(`# 🛡️  Lyrie Hack Report`);
  lines.push("");
  lines.push(`**Target:** \`${report.target}\``);
  lines.push(`**Mode:** ${report.mode}`);
  lines.push(`**Run ID:** \`${report.runId}\``);
  lines.push(`**Started:** ${report.startedAt}`);
  lines.push(`**Duration:** ${(report.durationMs / 1000).toFixed(2)}s`);
  lines.push(`**Signature:** _Lyrie.ai by OTT Cybersecurity LLC_`);
  lines.push("");

  // ── Executive summary ───────────────────────────────────────────────────
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(
    `Lyrie scanned **${report.target}** in **${report.mode}** mode and surfaced ` +
      `**${report.totalFindings}** finding${report.totalFindings === 1 ? "" : "s"} ` +
      `(${formatCounts(report.counts)}).`,
  );
  if (report.surface) {
    lines.push(
      `Attack surface: ${report.surface.entryPoints.length} entry points · ` +
        `${report.surface.trustBoundaries.length} boundaries · ` +
        `${report.surface.dataFlows.length} flows · ` +
        `${report.surface.dependencies.length} dependencies (mapper).`,
    );
  }
  if (report.dependencyGraph) {
    lines.push(
      `Dependency graph: ${report.dependencyGraph.packages.length} packages across ` +
        `${report.dependencyGraph.ecosystems.join(", ") || "no detected ecosystem"}.`,
    );
  }
  if (report.threatMatches.length > 0) {
    const kev = report.threatMatches.filter((m) => m.advisory.kev?.inKev).length;
    lines.push(
      `Threat-intel correlation: ${report.threatMatches.length} advisor${report.threatMatches.length === 1 ? "y" : "ies"} matched ` +
        `(${kev} on CISA KEV).`,
    );
  }
  if (report.aavRan) lines.push("AAV phase: ✅ executed against deployed instance.");
  if (report.selfScanRan)
    lines.push(`Self-scan: **${report.selfScanVerdict ?? "unknown"}** (run-log integrity).`);
  lines.push("");

  // ── Findings by severity ───────────────────────────────────────────────
  lines.push("## Findings by Severity");
  lines.push("");

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    const findings = report.validatedFindings.filter((f) => f.finding.severity === sev);
    const secrets = report.secretFindings.filter((s) => s.severity === sev);
    if (findings.length === 0 && secrets.length === 0) continue;
    lines.push(`### ${badgeFor(sev)} ${sev.toUpperCase()} (${findings.length + secrets.length})`);
    lines.push("");

    for (const v of findings) {
      const f = v.finding;
      lines.push(`- **[${ruleLabel(f.cwe, f.category)}]** ${f.title}`);
      if (f.file) lines.push(`  - 📍 \`${f.file}${f.line ? `:${f.line}` : ""}\``);
      lines.push(`  - 🎯 confidence ${(v.confidence * 100).toFixed(0)}% · stages: ${v.stages.map((s) => `${s.stage}${s.passed ? "✓" : "✗"}`).join(" ")}`);
      if (f.description) lines.push(`  - 💬 ${f.description}`);
      if (v.poc) {
        lines.push(`  - 🔬 PoC (${v.poc.kind}):`);
        lines.push("    ```");
        lines.push(...v.poc.payload.split("\n").slice(0, 6).map((l) => "    " + l));
        lines.push("    ```");
      }
    }
    for (const s of secrets) {
      lines.push(`- **[${s.type}]** Hardcoded ${s.type} \`${s.redactedSample}\``);
      lines.push(`  - 📍 \`${s.file}:${s.line}\``);
      lines.push(`  - 🎯 confidence ${(s.confidence * 100).toFixed(0)}%`);
    }
    lines.push("");
  }

  if (report.totalFindings === 0) {
    lines.push("✅ No findings.");
    lines.push("");
  }

  // ── Remediation plan ───────────────────────────────────────────────────
  if (report.remediations.length > 0) {
    lines.push("## Remediation Plan");
    lines.push("");
    let i = 1;
    for (const r of report.remediations.slice(0, 25)) {
      lines.push(`### ${i++}. \`${r.findingId}\``);
      lines.push("");
      lines.push(r.suggestion.description);
      lines.push("");
      if (r.suggestion.diffHint) {
        lines.push("**Before:**");
        lines.push("```");
        lines.push(r.suggestion.diffHint.before);
        lines.push("```");
        lines.push("**After:**");
        lines.push("```");
        lines.push(r.suggestion.diffHint.after);
        lines.push("```");
      }
      if (r.suggestion.testCommand) {
        lines.push(`**Verify:** \`${r.suggestion.testCommand}\``);
      }
      if (r.suggestion.referenceCwe) {
        lines.push(`**Reference:** ${r.suggestion.referenceCwe}` +
          (r.suggestion.referenceUrl ? ` — ${r.suggestion.referenceUrl}` : ""));
      }
      lines.push("");
    }
  }

  // ── Threat-intel matches ───────────────────────────────────────────────
  if (report.threatMatches.length > 0) {
    lines.push("## Threat-Intel Matches");
    lines.push("");
    for (const m of report.threatMatches.slice(0, 25)) {
      const a = m.advisory;
      const kev = a.kev?.inKev ? " 🚨 **KEV**" : "";
      lines.push(`- \`${a.cve}\` ${a.title}${kev}`);
      lines.push(`  - matched: ${m.reason}`);
      if (a.verdict) lines.push(`  - verdict: ${a.verdict}`);
    }
    lines.push("");
  }

  // ── Scan metadata ──────────────────────────────────────────────────────
  lines.push("## Scan Metadata");
  lines.push("");
  lines.push(`- Reporter: \`${REPORT_ENGINE_VERSION}\``);
  lines.push(`- Started: ${report.startedAt}`);
  lines.push(`- Finished: ${report.finishedAt}`);
  lines.push(`- Duration: ${report.durationMs} ms`);
  lines.push(`- Mode: ${report.mode}`);
  lines.push("");
  lines.push(`---`);
  lines.push(`_Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai_`);

  return lines.join("\n");
}

// ─── JSON (canonical) ────────────────────────────────────────────────────────

export function toJson(report: HackReport): string {
  return JSON.stringify(report, null, 2);
}

// ─── helpers ────────────────────────────────────────────────────────────────

function formatCounts(c: Record<Severity, number>): string {
  return (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => `${c[s]} ${s}`)
    .join(" · ");
}

function badgeFor(s: Severity): string {
  switch (s) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}

function ruleLabel(cwe?: string, category?: string): string {
  if (cwe) return cwe;
  if (category) return category;
  return "finding";
}
