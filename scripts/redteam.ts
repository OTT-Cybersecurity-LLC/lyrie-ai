#!/usr/bin/env bun
/**
 * `lyrie redteam <endpoint>` — AI Red Team CLI
 *
 * Attacks deployed AI agents to find vulnerabilities.
 * Compatible with any OpenAI-compatible endpoint.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Usage:
 *   bun run scripts/redteam.ts <endpoint> [options]
 *
 * Examples:
 *   bun run scripts/redteam.ts http://localhost:11434/v1 --model llama3 --dry-run
 *   bun run scripts/redteam.ts https://api.openai.com/v1 --api-key $OPENAI_API_KEY --model gpt-4o
 *   bun run scripts/redteam.ts http://localhost:11434/v1 --categories LLM01,LLM06 --severity high
 *   bun run scripts/redteam.ts http://myapp.com/v1 --output sarif --out report.sarif --fail-on high
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { LyrieRedTeam } from "../packages/core/src/aav/red-team";
import { LyrieBlueTeam } from "../packages/core/src/aav/blue-team";
import { AavReporter } from "../packages/core/src/aav/reporter";
import type { OwaspLlmCategory, AttackSeverity } from "../packages/core/src/aav/corpus/index";

// ─── Arg parsing ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function hasFlag(flag: string): boolean {
  return args.includes(flag);
}

const endpoint = args.find((a) => !a.startsWith("--"));

if (!endpoint || hasFlag("--help") || hasFlag("-h")) {
  console.log(`
🔴 LyrieAAV — AI Red Team Scanner
Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai

Usage:
  lyrie redteam <endpoint> [options]

Arguments:
  endpoint              OpenAI-compatible base URL (e.g. http://localhost:11434/v1)

Options:
  --api-key <key>       API key for the target endpoint
  --model <model>       Model name to test (default: gpt-3.5-turbo)
  --categories <cats>   Comma-separated OWASP categories (e.g. LLM01,LLM06)
  --severity <level>    Minimum severity: critical|high|medium|low (default: low)
  --mode <mode>         Test mode: blackbox|greybox|whitebox (default: blackbox)
  --system-prompt <sp>  System prompt to inject into target
  --concurrency <n>     Parallel probes (default: 3)
  --output <fmt>        Output format: markdown|sarif|json (default: markdown)
  --out <path>          Write report to file (default: stdout)
  --fail-on <sev>       Exit 1 if any finding >= this severity (default: none)
  --dry-run             Simulate probes without making HTTP requests
  --help                Show this help

Examples:
  lyrie redteam http://localhost:11434/v1 --model llama3 --dry-run
  lyrie redteam https://api.openai.com/v1 --api-key $KEY --categories LLM01,LLM06
  lyrie redteam http://myapp.com/v1 --output sarif --out scan.sarif --fail-on high
`);
  process.exit(0);
}

const apiKey = getFlag("--api-key") ?? process.env["OPENAI_API_KEY"] ?? process.env["API_KEY"];
const model = getFlag("--model") ?? "gpt-3.5-turbo";
const systemPrompt = getFlag("--system-prompt");
const mode = (getFlag("--mode") ?? "blackbox") as "blackbox" | "greybox" | "whitebox";
const concurrency = parseInt(getFlag("--concurrency") ?? "3", 10);
const outputFormat = (getFlag("--output") ?? "markdown") as "markdown" | "sarif" | "json";
const outPath = getFlag("--out");
const failOn = getFlag("--fail-on") as AttackSeverity | undefined;
const isDryRun = hasFlag("--dry-run");
const minSeverity = (getFlag("--severity") ?? "low") as AttackSeverity;

const categoriesRaw = getFlag("--categories");
const categories = categoriesRaw
  ? (categoriesRaw.split(",").map((c) => c.trim()) as OwaspLlmCategory[])
  : [];

// ─── Run scan ─────────────────────────────────────────────────────────────────

console.error(""); // stderr separator
console.error("🔴 LyrieAAV — AI Red Team Scanner");
console.error(`   Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai`);
console.error("─────────────────────────────────────────────────────────────────");
console.error(`   Endpoint:     ${endpoint}`);
console.error(`   Model:        ${model}`);
console.error(`   Mode:         ${mode}`);
console.error(`   Min severity: ${minSeverity}`);
console.error(`   Categories:   ${categories.length > 0 ? categories.join(", ") : "all"}`);
console.error(`   Concurrency:  ${concurrency}`);
console.error(`   Dry run:      ${isDryRun}`);
console.error(`   Output:       ${outputFormat}${outPath ? ` → ${outPath}` : " (stdout)"}`);
console.error("");

const rt = new LyrieRedTeam(
  {
    endpoint,
    apiKey,
    model,
    mode,
    systemPrompt,
  },
  {
    categories,
    minSeverity,
    concurrency,
    dryRun: isDryRun,
  },
);

let probeCount = 0;
process.stderr.write("   Scanning");

const scanResult = await rt.scan();
process.stderr.write(` done (${scanResult.totalProbed} probes, ${(scanResult.durationMs / 1000).toFixed(1)}s)\n\n`);

// ─── Score + report ───────────────────────────────────────────────────────────

const bt = new LyrieBlueTeam();
const report = bt.score(scanResult.results, scanResult.durationMs);
const reporter = new AavReporter(scanResult, report);

// Progress summary to stderr
console.error(`   Grade:        ${report.grade} (${report.overallScore}/100)`);
console.error(`   Success rate: ${(report.attackSuccessRate * 100).toFixed(1)}%`);
console.error(`   Critical:     ${scanResult.results.filter((r) => r.vector.severity === "critical" && r.verdict === "success").length} breached`);
console.error(`   High:         ${scanResult.results.filter((r) => r.vector.severity === "high" && r.verdict === "success").length} breached`);
console.error("");

// Build output
let output: string;
switch (outputFormat) {
  case "sarif":
    output = JSON.stringify(reporter.toSarif(), null, 2);
    break;
  case "json":
    output = reporter.toJson();
    break;
  default:
    output = reporter.toMarkdown();
}

// Write or print
if (outPath) {
  mkdirSync(dirname(outPath === "." ? "./" : outPath) || ".", { recursive: true });
  writeFileSync(outPath, output, "utf-8");
  console.error(`   Report saved: ${outPath}`);
} else {
  process.stdout.write(output + "\n");
}

// ─── Fail-on logic ────────────────────────────────────────────────────────────

if (failOn) {
  const severityOrder: AttackSeverity[] = ["low", "medium", "high", "critical"];
  const failIdx = severityOrder.indexOf(failOn);
  const hasFailingFindings = scanResult.results.some(
    (r) =>
      (r.verdict === "success" || r.verdict === "partial") &&
      severityOrder.indexOf(r.vector.severity) >= failIdx,
  );

  if (hasFailingFindings) {
    console.error(`\n⛔  Build failed: findings at or above '${failOn}' severity detected.\n`);
    process.exit(1);
  }
}
