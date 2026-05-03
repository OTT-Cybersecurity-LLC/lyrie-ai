#!/usr/bin/env bun
/**
 * lyrie evolve — LyrieEvolve CLI
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Subcommands:
 *   status              Show evolve system status
 *   extract             Extract skills from outcomes
 *   dream [--dry-run]   Run the Dream Cycle pipeline
 *   stats               Show outcome statistics
 *   skills list         List auto-generated skills
 *   skills show <id>    Show a specific skill
 *   skills prune        Prune stale skills
 *   train [options]     Export training data for H200 fine-tuning
 */
// train subcommand options:
//   --export atropos|openai-sft|sharegpt   format (default: atropos)
//   --min-score 0.5                         minimum outcome score
//   --domains cyber,code,...                comma-separated domain filter
//   --out ./training.jsonl                  output path
//   --status                                show ready-sample stats without exporting

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { SkillExtractor } from "../packages/core/src/evolve/skill-extractor";
import { runDreamCycle, findPruneCandidates, pruneSkills } from "../packages/core/src/evolve/dream-cycle";
import { SCORER_VERSION } from "../packages/core/src/evolve/scorer";
import { EXTRACTOR_VERSION } from "../packages/core/src/evolve/skill-extractor";
import { DREAM_VERSION } from "../packages/core/src/evolve/dream-cycle";
import { CONTEXTURE_VERSION } from "../packages/core/src/evolve/contexture";
import { TrainingExporter, TRAINING_EXPORTER_VERSION } from "../packages/core/src/evolve/training-exporter";
import type { TaskOutcome } from "../packages/core/src/evolve/scorer";
import type { ExportDomain, ExportFormat } from "../packages/core/src/evolve/training-exporter";

// ─── Config ─────────────────────────────────────────────────────────────────

const DEFAULT_OUTCOMES_PATH = join(homedir(), ".lyrie", "evolve", "outcomes.jsonl");
const DEFAULT_SKILLS_DIR = join(homedir(), ".lyrie", "evolve", "skills");

// ─── Helpers ─────────────────────────────────────────────────────────────────

function readOutcomes(path: string): TaskOutcome[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .flatMap((l) => {
      try { return [JSON.parse(l) as TaskOutcome]; } catch { return []; }
    });
}

function printHelp() {
  console.log(`
lyrie evolve — LyrieEvolve CLI (v0.5.0)
Lyrie.ai by OTT Cybersecurity LLC

Usage:
  bun run scripts/evolve.ts <command> [options]

Commands:
  status              Show LyrieEvolve system status
  extract             Extract skills from high-quality outcomes
  dream [--dry-run]   Run the full Dream Cycle pipeline
  stats               Show outcome statistics by domain and score
  skills list         List all auto-generated skills
  skills show <id>    Show content of a specific skill file
  skills prune        Identify and remove stale skills
  train               Export high-quality outcomes as a training batch
    --export <fmt>      Format: atropos | openai-sft | sharegpt (default: atropos)
    --min-score <n>     Min score 0.0-1.0 (default: 0.5)
    --domains <list>    Comma-separated: cyber,seo,trading,code,all (default: all)
    --out <path>        Output JSONL file path
    --status            Show ready-sample stats without exporting

Options:
  --outcomes <path>   Override outcomes.jsonl path
  --skills-dir <path> Override skills directory path
  --dry-run           Preview without writing
  --help, -h          Show this help

Lyrie.ai by OTT Cybersecurity LLC
`);
}

// ─── Commands ────────────────────────────────────────────────────────────────

async function cmdStatus(outcomesPath: string, skillsDir: string) {
  const outcomes = readOutcomes(outcomesPath);
  const skillCount = existsSync(skillsDir)
    ? readdirSync(skillsDir).filter((f) => f.endsWith(".md")).length
    : 0;
  const highQuality = outcomes.filter((o) => o.score >= 0.5).length;

  console.log(`\n🧠 LyrieEvolve Status\n`);
  console.log(`   Scorer:      ${SCORER_VERSION}`);
  console.log(`   Extractor:   ${EXTRACTOR_VERSION}`);
  console.log(`   Dream Cycle: ${DREAM_VERSION}`);
  console.log(`   Contexture:  ${CONTEXTURE_VERSION}`);
  console.log(``);
  console.log(`📊 Outcomes: ${outcomes.length} total, ${highQuality} high-quality (score >= 0.5)`);
  console.log(`🎯 Auto-Skills: ${skillCount} files in ${skillsDir}`);
  console.log(`📁 Outcomes file: ${outcomesPath} (${existsSync(outcomesPath) ? "exists" : "missing"})`);
  console.log(``);
}

async function cmdExtract(outcomesPath: string, skillsDir: string, dryRun: boolean) {
  console.log(`\n🔍 Extracting skills${dryRun ? " [DRY RUN]" : ""}...\n`);
  const extractor = new SkillExtractor({ outcomesPath, skillsDir, dryRun });
  const result = await extractor.extract();
  console.log(`   Patterns found: ${result.patterns.length}`);
  console.log(`   Written:        ${result.written}`);
  console.log(`   Duplicates:     ${result.skippedDuplicates}`);
  for (const p of result.patterns) {
    console.log(`   ✅ ${p.name} (${p.domain}, score=${p.avgScore.toFixed(2)})`);
  }
  console.log(``);
}

async function cmdDream(outcomesPath: string, skillsDir: string, dryRun: boolean) {
  console.log(`\n🌙 Dream Cycle${dryRun ? " [DRY RUN]" : ""}...\n`);
  const report = await runDreamCycle({ outcomesPath, skillsDir, dryRun });
  console.log(`   Outcomes processed: ${report.unprocessedOutcomes}`);
  console.log(`   Skills extracted:   ${report.extractedSkills}`);
  console.log(`   Duplicates:         ${report.skippedDuplicates}`);
  console.log(`   Skills pruned:      ${report.pruned.length}`);
  console.log(`   Total skills:       ${report.totalSkills}`);
  if (report.pruned.length > 0) {
    console.log(`\n🗑️  Pruned:`);
    for (const p of report.pruned) {
      console.log(`   - ${p.filename}: ${p.reason}`);
    }
  }
  console.log(``);
}

async function cmdStats(outcomesPath: string) {
  const outcomes = readOutcomes(outcomesPath);
  if (outcomes.length === 0) {
    console.log(`\nNo outcomes found at ${outcomesPath}\n`);
    return;
  }

  console.log(`\n📈 Outcome Statistics\n`);
  console.log(`   Total: ${outcomes.length}`);

  const byDomain = new Map<string, number[]>();
  for (const o of outcomes) {
    const scores = byDomain.get(o.domain) ?? [];
    scores.push(o.score);
    byDomain.set(o.domain, scores);
  }

  for (const [domain, scores] of byDomain) {
    const avg = scores.reduce((a, b) => a + b, 0) / scores.length;
    const highQ = scores.filter((s) => s >= 0.5).length;
    console.log(`   ${domain.padEnd(10)}: ${scores.length} outcomes, avg=${avg.toFixed(2)}, high-quality=${highQ}`);
  }

  const byScore: Record<string, number> = { "0": 0, "0.5": 0, "1": 0 };
  for (const o of outcomes) {
    byScore[String(o.score)] = (byScore[String(o.score)] ?? 0) + 1;
  }
  console.log(`\n   Score distribution:`);
  console.log(`   Score 0   (fail):    ${byScore["0"] ?? 0}`);
  console.log(`   Score 0.5 (partial): ${byScore["0.5"] ?? 0}`);
  console.log(`   Score 1   (success): ${byScore["1"] ?? 0}`);
  console.log(``);
}

async function cmdSkillsList(skillsDir: string) {
  if (!existsSync(skillsDir)) {
    console.log(`\nNo skills directory at ${skillsDir}\n`);
    return;
  }
  const files = readdirSync(skillsDir).filter((f) => f.endsWith(".md"));
  console.log(`\n🎯 Auto-Generated Skills (${files.length})\n`);
  for (const f of files) {
    const stat = statSync(join(skillsDir, f));
    const content = readFileSync(join(skillsDir, f), "utf8");
    const nameMatch = content.match(/^# (.+)$/m);
    const name = nameMatch ? nameMatch[1] : f;
    console.log(`   ${f.padEnd(40)} ${name}`);
  }
  console.log(``);
}

async function cmdSkillsShow(skillsDir: string, id: string) {
  const filename = id.endsWith(".md") ? id : `${id}.md`;
  const path = join(skillsDir, filename);
  if (!existsSync(path)) {
    console.error(`❌ Skill not found: ${path}`);
    process.exit(1);
  }
  console.log(readFileSync(path, "utf8"));
}

async function cmdSkillsPrune(skillsDir: string, dryRun: boolean) {
  console.log(`\n🗑️  Pruning stale skills${dryRun ? " [DRY RUN]" : ""}...\n`);
  const candidates = findPruneCandidates(skillsDir, 0.3, 5);
  if (candidates.length === 0) {
    console.log(`   No stale skills found.\n`);
    return;
  }
  for (const c of candidates) {
    console.log(`   ${dryRun ? "[would prune]" : "[pruning]"} ${c.filename}: ${c.reason}`);
  }
  pruneSkills(skillsDir, candidates, dryRun);
  console.log(`\n   ${dryRun ? "Would have pruned" : "Pruned"} ${candidates.length} skill(s).\n`);
}

async function cmdTrain(
  outcomesPath: string,
  trainArgs: string[],
) {
  const exporter = new TrainingExporter({ outcomesPath });

  // --status flag: print stats and exit
  if (trainArgs.includes("--status")) {
    const s = exporter.status();
    const lastExport = s.lastExportTimestamp
      ? new Date(s.lastExportTimestamp).toISOString()
      : "never";
    console.log(`\n🎓 LyrieEvolve Training Status\n`);
    console.log(`   Version:       ${TRAINING_EXPORTER_VERSION}`);
    console.log(`   Outcomes file: ${s.outcomesPath}`);
    console.log(`   Total samples: ${s.totalOutcomes}`);
    console.log(`   Ready (≥0.5):  ${s.readySamples}`);
    console.log(`   Last outcome:  ${lastExport}`);
    if (Object.keys(s.byDomain).length > 0) {
      console.log(`\n   Domain breakdown:`);
      for (const [domain, count] of Object.entries(s.byDomain)) {
        console.log(`     ${domain.padEnd(10)} ${count} samples`);
      }
    } else {
      console.log(`   (no ready samples — run lyrie evolve dream to process outcomes)`);
    }
    console.log(``);
    return;
  }

  // Parse train-specific flags
  const fmtIdx = trainArgs.indexOf("--export");
  const format: ExportFormat =
    fmtIdx >= 0 && trainArgs[fmtIdx + 1]
      ? (trainArgs[fmtIdx + 1] as ExportFormat)
      : "atropos";

  const minScoreIdx = trainArgs.indexOf("--min-score");
  const minScore = minScoreIdx >= 0 && trainArgs[minScoreIdx + 1]
    ? parseFloat(trainArgs[minScoreIdx + 1]!)
    : 0.5;

  const domainsIdx = trainArgs.indexOf("--domains");
  const domains: ExportDomain[] =
    domainsIdx >= 0 && trainArgs[domainsIdx + 1]
      ? (trainArgs[domainsIdx + 1]!.split(",").map((d) => d.trim()) as ExportDomain[])
      : ["all"];

  const outIdx = trainArgs.indexOf("--out");
  const outputPath =
    outIdx >= 0 && trainArgs[outIdx + 1]
      ? trainArgs[outIdx + 1]!
      : join(homedir(), ".lyrie", "evolve", `training-${Date.now()}.jsonl`);

  const validFormats: ExportFormat[] = ["atropos", "openai-sft", "sharegpt"];
  if (!validFormats.includes(format)) {
    console.error(`❌ Unknown format: ${format}. Valid: ${validFormats.join(", ")}`);
    process.exit(1);
  }

  console.log(`\n🎓 LyrieEvolve Training Export\n`);
  console.log(`   Format:    ${format}`);
  console.log(`   Min score: ${minScore}`);
  console.log(`   Domains:   ${domains.join(", ")}`);
  console.log(`   Output:    ${outputPath}`);
  console.log(``);

  const result = await exporter.export({
    format,
    minScore,
    domains,
    outputPath,
    maxSamples: 10000,
  });

  console.log(`   ✅ Exported: ${result.samplesExported} samples`);
  console.log(`   📁 Written:  ${result.outputPath}`);
  console.log(`   💾 Size:     ${(result.sizeBytes / 1024).toFixed(1)} KB`);
  if (Object.keys(result.domainsBreakdown).length > 0) {
    console.log(`\n   Domain breakdown:`);
    for (const [domain, count] of Object.entries(result.domainsBreakdown)) {
      console.log(`     ${domain.padEnd(10)} ${count} samples`);
    }
  }
  console.log(``);
}

// ─── Main ────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  printHelp();
  process.exit(0);
}

// Parse shared options
const dryRun = args.includes("--dry-run");
const outcomesIdx = args.indexOf("--outcomes");
const outcomesPath = outcomesIdx >= 0 && args[outcomesIdx + 1]
  ? args[outcomesIdx + 1]!
  : DEFAULT_OUTCOMES_PATH;
const skillsDirIdx = args.indexOf("--skills-dir");
const skillsDir = skillsDirIdx >= 0 && args[skillsDirIdx + 1]
  ? args[skillsDirIdx + 1]!
  : DEFAULT_SKILLS_DIR;

const command = args[0];
const subCommand = args[1];

try {
  switch (command) {
    case "status":
      await cmdStatus(outcomesPath, skillsDir);
      break;
    case "extract":
      await cmdExtract(outcomesPath, skillsDir, dryRun);
      break;
    case "dream":
      await cmdDream(outcomesPath, skillsDir, dryRun);
      break;
    case "stats":
      await cmdStats(outcomesPath);
      break;
    case "skills":
      switch (subCommand) {
        case "list":
          await cmdSkillsList(skillsDir);
          break;
        case "show":
          await cmdSkillsShow(skillsDir, args[2] ?? "");
          break;
        case "prune":
          await cmdSkillsPrune(skillsDir, dryRun);
          break;
        default:
          console.error(`❌ Unknown skills subcommand: ${subCommand}`);
          console.log("Available: list, show <id>, prune");
          process.exit(1);
      }
      break;
    case "train":
      // Pass all remaining args after "train" subcommand so train-specific
      // flags (--export, --min-score, --domains, --out, --status) are available.
      await cmdTrain(outcomesPath, args.slice(1));
      break;
    default:
      console.error(`❌ Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
} catch (err) {
  console.error(`❌ Error:`, err instanceof Error ? err.message : err);
  process.exit(1);
}
