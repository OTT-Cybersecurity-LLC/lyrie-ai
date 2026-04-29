#!/usr/bin/env bun
/**
 * lyrie evolve dream — Dream Cycle CLI
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Usage:
 *   bun run scripts/dream-evolve.ts [--dry-run] [--outcomes <path>] [--skills-dir <path>]
 *
 * Runs the full LyrieEvolve Dream Cycle batch:
 *   1. Score unprocessed outcomes
 *   2. Extract new skills
 *   3. Prune stale skills
 *   4. Print report
 */

import { runDreamCycle } from "../packages/core/src/evolve/dream-cycle";

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const outcomesIdx = args.indexOf("--outcomes");
const outcomesPath = outcomesIdx >= 0 ? args[outcomesIdx + 1] : undefined;
const skillsDirIdx = args.indexOf("--skills-dir");
const skillsDir = skillsDirIdx >= 0 ? args[skillsDirIdx + 1] : undefined;

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
lyrie evolve dream — Dream Cycle Pipeline

Usage:
  bun run scripts/dream-evolve.ts [options]

Options:
  --dry-run           Preview changes without writing to disk
  --outcomes <path>   Path to outcomes.jsonl (default: ~/.lyrie/evolve/outcomes.jsonl)
  --skills-dir <path> Directory for auto-generated skills
  --help              Show this help

The Dream Cycle:
  1. Count unprocessed outcomes in outcomes.jsonl
  2. Extract skill patterns from high-quality outcomes (score >= 0.5)
  3. Prune stale skills (avgScore < 0.3 after 5+ uses)
  4. Report summary

Lyrie.ai by OTT Cybersecurity LLC
`);
  process.exit(0);
}

console.log(`\n🌙 LyrieEvolve Dream Cycle${dryRun ? " [DRY RUN]" : ""}\n`);
console.log(`   Lyrie.ai by OTT Cybersecurity LLC\n`);

try {
  const report = await runDreamCycle({ dryRun, outcomesPath, skillsDir });

  console.log(`📊 Dream Cycle Report`);
  console.log(`   Run at:              ${new Date(report.runAt).toISOString()}`);
  console.log(`   Mode:                ${report.dryRun ? "DRY RUN (no writes)" : "LIVE"}`);
  console.log(`   Unprocessed outcomes: ${report.unprocessedOutcomes}`);
  console.log(`   Skills extracted:    ${report.extractedSkills}`);
  console.log(`   Duplicates skipped:  ${report.skippedDuplicates}`);
  console.log(`   Skills pruned:       ${report.pruned.length}`);
  console.log(`   Total skills:        ${report.totalSkills}`);

  if (report.pruned.length > 0) {
    console.log(`\n🗑️  Pruned skills:`);
    for (const p of report.pruned) {
      console.log(`   - ${p.filename}: ${p.reason}`);
    }
  }

  console.log(`\n✅ Dream Cycle complete.\n`);
} catch (err) {
  console.error(`❌ Dream Cycle failed:`, err instanceof Error ? err.message : err);
  process.exit(1);
}
