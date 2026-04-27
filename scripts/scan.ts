#!/usr/bin/env bun
/**
 * `lyrie scan` — operator CLI for the Lyrie OSS-Scan service.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run scripts/scan.ts <repoUrl>
 *   bun run scripts/scan.ts <repoUrl> --ref main --json
 */

import { runOssScan } from "../packages/core/src/pentest/oss-scan/service";

const args = process.argv.slice(2);
const repoUrl = args.find((a) => !a.startsWith("--"));
const refIdx = args.indexOf("--ref");
const ref = refIdx >= 0 ? args[refIdx + 1] : undefined;
const asJson = args.includes("--json");

if (!repoUrl) {
  console.error("Usage: lyrie scan <repoUrl> [--ref <branch>] [--json]");
  process.exit(2);
}

const result = await runOssScan({ repoUrl, ref });

if (asJson) {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit("ok" in result && result.ok === false ? 1 : 0);
}

console.log("");
console.log("🛡️  Lyrie OSS-Scan  ·  Lyrie.ai by OTT Cybersecurity LLC");
console.log("─────────────────────────────────────────────────────────────────");

if ("ok" in result && result.ok === false) {
  console.error(`✗ Scan rejected: ${result.reason}`);
  if (result.detail) console.error(`  detail: ${result.detail}`);
  process.exit(1);
}

const r = result;
console.log(`  repo:          ${r.resolvedUrl}`);
console.log(`  files:         ${r.filesScanned}`);
console.log(`  languages:     ${r.languages.map((l) => `${l.language}(${l.rulesRun})`).join(" ")}`);
console.log(`  entries:       ${r.attackSurface.entryPoints}`);
console.log(`  boundaries:    ${r.attackSurface.trustBoundaries}`);
console.log(`  flows:         ${r.attackSurface.dataFlows}`);
console.log(`  dependencies:  ${r.attackSurface.dependencies}`);
console.log(`  findings:      ${r.findings.length}`);
console.log("");

if (r.findings.length > 0) {
  console.log("📋 Confirmed findings");
  for (const v of r.findings.slice(0, 25)) {
    const f = v.finding;
    console.log(
      `  [${f.severity.toUpperCase().padEnd(8)}] ${f.title}  (confidence ${(v.confidence * 100).toFixed(0)}%)`,
    );
    if (f.file) console.log(`              ${f.file}:${f.line ?? "?"}`);
    if (v.poc?.kind === "automatic") console.log(`              PoC: ${v.poc.payload.split("\n").slice(0, 2).join(" / ")}`);
    if (v.remediation?.summary) console.log(`              fix: ${v.remediation.summary.slice(0, 100)}…`);
  }
  console.log("");
}

console.log(`signature: ${r.signature}`);
console.log(`service:   ${r.serviceVersion}`);
console.log("");
