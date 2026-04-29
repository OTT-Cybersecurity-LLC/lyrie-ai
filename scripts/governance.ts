#!/usr/bin/env bun
/**
 * `lyrie governance` — AI Governance CLI
 *
 * Subcommands:
 *   lyrie governance assess [--config <path>] [--interactive] [--out report.json]
 *   lyrie governance permissions <path-to-agent-config>
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { AiGovernanceScorecard } from "../packages/core/src/governance/scorecard";
import { AgentPermissionAnalyzer, parseToolManifest } from "../packages/core/src/governance/permissions";

// ─── Arg parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function hasFlag(flag: string): boolean {
  return args.includes(flag);
}

const subCommand = args[0];

// ─── Help ─────────────────────────────────────────────────────────────────────

if (!subCommand || hasFlag("--help") || hasFlag("-h") || subCommand === "help") {
  console.log(`
🏛️  Lyrie Governance — AI Risk & Compliance CLI
Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai

Usage:
  lyrie governance <subcommand> [options]

Subcommands:
  assess       Score an AI deployment against NIST AI RMF + EU AI Act
  permissions  Analyze an AI agent's tool permissions for risk

lyrie governance assess:
  --config <path>    Path to agent config file or directory (auto-infers answers)
  --interactive      Run interactive questionnaire (overrides --config answers)
  --out <path>       Write JSON report to file (default: stdout as markdown)

lyrie governance permissions:
  <config-path>      Path to agent tool manifest or config file
  --out <path>       Write report to file (default: stdout as markdown)
  --json             Output as JSON instead of markdown

Examples:
  lyrie governance assess --interactive
  lyrie governance assess --config ./agent-config.json --out report.json
  lyrie governance permissions ./tools-manifest.json
  lyrie governance permissions ./agent.config.ts --json --out perms-report.json
`);
  process.exit(0);
}

// ─── assess ──────────────────────────────────────────────────────────────────

if (subCommand === "assess") {
  const configPath = getFlag("--config");
  const outPath = getFlag("--out");
  const isInteractive = hasFlag("--interactive");

  console.error("");
  console.error("🏛️  Lyrie AI Governance Assessment");
  console.error("   Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai");
  console.error("─────────────────────────────────────────────────────────────────");

  let answers = {};

  if (isInteractive) {
    answers = await AiGovernanceScorecard.runInteractive();
  }

  const scorecard = new AiGovernanceScorecard();
  const report = await scorecard.assess({
    configPath,
    answers: isInteractive ? answers : undefined,
  });

  if (outPath) {
    mkdirSync(dirname(outPath === "." ? "./" : outPath) || ".", { recursive: true });
    writeFileSync(outPath, JSON.stringify(report, null, 2), "utf-8");
    console.error(`\n   Report saved: ${outPath}`);
    console.error(`   Overall Score: ${report.overallScore}/100 (${report.maturityLevel})`);
    console.error(`   EU AI Act: ${report.euAiActCompliance}`);
    console.error(`   Critical Gaps: ${report.gaps.filter((g) => g.severity === "critical").length}`);
  } else {
    console.error(`\n   Overall Score: ${report.overallScore}/100 (${report.maturityLevel})`);
    console.error(`   EU AI Act: ${report.euAiActCompliance}`);
    console.error(`   Critical Gaps: ${report.gaps.filter((g) => g.severity === "critical").length}\n`);
    process.stdout.write(AiGovernanceScorecard.formatReport(report) + "\n");
  }

  process.exit(0);
}

// ─── permissions ─────────────────────────────────────────────────────────────

if (subCommand === "permissions") {
  const configPath = args[1];
  const outPath = getFlag("--out");
  const asJson = hasFlag("--json");

  if (!configPath) {
    console.error("❌ Usage: lyrie governance permissions <path-to-agent-config>");
    process.exit(1);
  }

  console.error("");
  console.error("🔐 Lyrie Agent Permission Analyzer");
  console.error("   Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai");
  console.error("─────────────────────────────────────────────────────────────────");
  console.error(`   Config: ${configPath}`);
  console.error("");

  let manifest;
  try {
    manifest = parseToolManifest(configPath);
  } catch (err) {
    console.error(`❌ Failed to parse config: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }

  console.error(`   Tools found: ${manifest.tools.length}`);
  console.error(`   Agent ID: ${manifest.agentId ?? "unknown"}`);

  const analyzer = new AgentPermissionAnalyzer();
  const report = analyzer.analyze(manifest);

  console.error(`   Risk Score: ${report.riskScore}/100 (${report.riskLevel})`);
  console.error(`   Critical findings: ${report.findings.filter((f) => f.severity === "critical").length}`);
  console.error(`   High findings: ${report.findings.filter((f) => f.severity === "high").length}`);
  console.error("");

  const output = asJson
    ? JSON.stringify(report, null, 2)
    : AgentPermissionAnalyzer.formatReport(report, manifest.agentId);

  if (outPath) {
    mkdirSync(dirname(outPath === "." ? "./" : outPath) || ".", { recursive: true });
    writeFileSync(outPath, output, "utf-8");
    console.error(`   Report saved: ${outPath}`);
  } else {
    process.stdout.write(output + "\n");
  }

  process.exit(0);
}

// ─── Unknown subcommand ───────────────────────────────────────────────────────

console.error(`❌ Unknown subcommand: ${subCommand}`);
console.error("   Run 'lyrie governance --help' for usage.");
process.exit(1);
