#!/usr/bin/env bun
/**
 * `lyrie understand` — operator CLI for the Lyrie Attack-Surface Mapper.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 *
 * Usage:
 *   bun run scripts/understand.ts                      # map current workspace
 *   bun run scripts/understand.ts --root /path/to/repo
 *   bun run scripts/understand.ts --json
 *   bun run scripts/understand.ts --deps-only
 */

import { buildAttackSurface } from "../packages/core/src/pentest/attack-surface";

const args = parseArgs(process.argv.slice(2));
const root = args.root ?? process.cwd();
const asJson = "json" in args;
const depsOnly = "deps-only" in args;

const map = await buildAttackSurface({ root, depsOnly });

if (asJson) {
  process.stdout.write(JSON.stringify(map, null, 2) + "\n");
  process.exit(0);
}

const lines: string[] = [];
lines.push("");
lines.push("🛡️  Lyrie Attack-Surface Map  ·  Lyrie.ai by OTT Cybersecurity LLC");
lines.push("─────────────────────────────────────────────────────────────────");
lines.push(`  root:          ${map.root}`);
lines.push(`  generated:     ${map.generatedAt}`);
lines.push(`  mapper:        ${map.mapperVersion}`);
lines.push(`  files seen:    ${map.filesInspected}  (ignored ${map.filesIgnored})`);
lines.push(`  entries:       ${map.entryPoints.length}`);
lines.push(`  boundaries:    ${map.trustBoundaries.length}`);
lines.push(`  flows:         ${map.dataFlows.length}`);
lines.push(`  dependencies:  ${map.dependencies.length}`);
lines.push("");

if (map.hotspots.length > 0) {
  lines.push("🔥 Top hotspots");
  for (const h of map.hotspots.slice(0, 10)) {
    lines.push(`  [${String(h.score).padStart(2)}] ${h.file}`);
    for (const r of h.reasons.slice(0, 4)) lines.push(`        ${r}`);
  }
  lines.push("");
}

const byKind: Record<string, number> = {};
for (const e of map.entryPoints) byKind[e.kind] = (byKind[e.kind] ?? 0) + 1;
if (Object.keys(byKind).length > 0) {
  lines.push("🚪 Entry points by kind");
  for (const [k, n] of Object.entries(byKind).sort((a, b) => b[1] - a[1])) {
    lines.push(`  ${String(n).padStart(4)} × ${k}`);
  }
  lines.push("");
}

const flowsByRisk = [...map.dataFlows].sort((a, b) => b.risk - a.risk).slice(0, 8);
if (flowsByRisk.length > 0) {
  lines.push("⚠️  Highest-risk data flows");
  for (const f of flowsByRisk) {
    lines.push(`  [risk ${String(f.risk).padStart(2)}] ${f.source} → ${f.sink}`);
    lines.push(`             ${f.file}:${f.line}`);
    lines.push(`             ${f.evidence}`);
  }
  lines.push("");
}

lines.push(`signature: ${map.signature}`);
lines.push("");

console.log(lines.join("\n"));

function parseArgs(argv: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const k = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      out[k] = next;
      i++;
    } else {
      out[k] = "true";
    }
  }
  return out;
}
