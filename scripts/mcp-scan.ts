#!/usr/bin/env bun
/**
 * `lyrie mcp-scan <manifest.json>` — MCP Security Scanner CLI
 *
 * Scans MCP server manifests for tool poisoning, typosquatting,
 * hidden unicode injections, and CVE-2026-30615 class vulnerabilities.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Usage:
 *   bun run scripts/mcp-scan.ts <manifest.json> [options]
 *
 * Examples:
 *   bun run scripts/mcp-scan.ts ~/.cursor/mcp.json
 *   bun run scripts/mcp-scan.ts ./mcp.json --output json
 *   bun run scripts/mcp-scan.ts ./mcp.json --fail-on high
 */

import { scanMcpManifest } from "../packages/core/src/mcp/security-scanner";
import type { McpFinding } from "../packages/core/src/mcp/security-scanner";

// ─── Arg parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function hasFlag(flag: string): boolean {
  return args.includes(flag);
}

const manifestPath = args.find((a) => !a.startsWith("--"));

if (!manifestPath || hasFlag("--help") || hasFlag("-h")) {
  console.log(`
🔍 Lyrie MCP Security Scanner
Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai

Usage:
  lyrie mcp-scan <manifest.json> [options]

Arguments:
  manifest.json         Path to the MCP manifest file to scan

Options:
  --output <fmt>        Output format: text|json (default: text)
  --fail-on <sev>       Exit 1 if findings at or above severity: critical|high|medium|low
  --help, -h            Show this help

Detection Rules:
  TOOL_NAME_TYPOSQUATTING       Edit distance < 2 to popular tools (bash, python, git, ...)
  HIDDEN_UNICODE                Zero-width chars, RTL override, homoglyphs in name/description
  DESCRIPTION_PROMPT_INJECTION  "ignore previous", "system:", "IGNORE ALL" patterns
  EXCESSIVE_PERMISSIONS         write+exec+network+filesystem all at once
  SCHEMA_MISMATCH               Declared type doesn't match parameter semantics
  SUSPICIOUS_DESCRIPTION_LENGTH Description > 2000 chars (injection padding)
  MISSING_SCOPE                 No scope declaration (violates ATP)
  KNOWN_BAD_PATTERN             CVE-2026-30615 MCP RCE fingerprints

Examples:
  lyrie mcp-scan ~/.cursor/mcp.json
  lyrie mcp-scan ./mcp.json --output json
  lyrie mcp-scan ./mcp.json --fail-on high
`);
  process.exit(0);
}

const outputFormat = getFlag("--output") ?? "text";
const failOn = getFlag("--fail-on");

// ─── Run scan ─────────────────────────────────────────────────────────────────

const SEVERITY_ORDER = ["low", "medium", "high", "critical"];

const SEVERITY_ICONS: Record<string, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

console.error("🔍 Lyrie MCP Security Scanner");
console.error(`   Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai`);
console.error("─────────────────────────────────────────────────────────────────");
console.error(`   Manifest: ${manifestPath}`);
console.error("");

let result;
try {
  result = await scanMcpManifest({ manifestPath });
} catch (err) {
  console.error(`❌ Scan failed: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(2);
}

if (outputFormat === "json") {
  console.log(JSON.stringify(result, null, 2));
} else {
  console.log(`\n📊 MCP Security Scan Report`);
  console.log(`   Target:    ${result.target}`);
  console.log(`   Tools:     ${result.toolCount}`);
  console.log(`   Duration:  ${result.scanDurationMs}ms`);
  console.log(`   Status:    ${result.ok ? "✅ CLEAN" : "⚠️  FINDINGS DETECTED"}`);
  console.log(`   Findings:  ${result.findings.length}`);

  if (result.findings.length > 0) {
    console.log("\n─── Findings ───────────────────────────────────────────────────────");

    const grouped: Record<string, McpFinding[]> = {};
    for (const finding of result.findings) {
      if (!grouped[finding.severity]) grouped[finding.severity] = [];
      grouped[finding.severity].push(finding);
    }

    for (const sev of [...SEVERITY_ORDER].reverse()) {
      if (!grouped[sev]) continue;
      for (const f of grouped[sev]) {
        const icon = SEVERITY_ICONS[f.severity] ?? "⚪";
        console.log(`\n${icon} [${f.severity.toUpperCase()}] ${f.rule}`);
        if (f.tool) console.log(`   Tool:        ${f.tool}`);
        console.log(`   Description: ${f.description}`);
        console.log(`   Evidence:    ${f.evidence}`);
        console.log(`   Remediation: ${f.remediation}`);
      }
    }

    console.log("\n────────────────────────────────────────────────────────────────────");
    const critCount = result.findings.filter((f) => f.severity === "critical").length;
    const highCount = result.findings.filter((f) => f.severity === "high").length;
    if (critCount > 0) console.log(`⛔  ${critCount} CRITICAL finding(s) — reject this manifest.`);
    if (highCount > 0) console.log(`⚠️   ${highCount} HIGH finding(s) — review before use.`);
  } else {
    console.log("\n✅ No security findings — manifest appears clean.");
  }
}

// ─── Fail-on logic ────────────────────────────────────────────────────────────

if (failOn) {
  const failIdx = SEVERITY_ORDER.indexOf(failOn);
  const hasFailingFindings = result.findings.some(
    (f) => SEVERITY_ORDER.indexOf(f.severity) >= failIdx,
  );
  if (hasFailingFindings) {
    console.error(`\n⛔  Exiting with code 1: findings at or above '${failOn}' severity detected.`);
    process.exit(1);
  }
}
