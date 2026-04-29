/**
 * Lyrie LyrieEvolve — Dream Cycle Pipeline (core logic)
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * The Dream Cycle is a batch pipeline that runs while Lyrie is idle:
 *   1. Score any unprocessed outcomes
 *   2. Extract skills from high-quality outcomes
 *   3. Prune stale/low-value skills (score < 0.3 after 5+ uses)
 *   4. Build a report
 *
 * Designed to be called from `scripts/dream-evolve.ts` and `lyrie evolve dream`.
 *
 * © OTT Cybersecurity LLC — All rights reserved.
 */

import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

import { SkillExtractor } from "./skill-extractor";
import type { SkillPattern } from "./skill-extractor";
import type { TaskOutcome } from "./scorer";

// ─── Types ─────────────────────────────────────────────────────────────────

export interface DreamCycleOptions {
  /** Path to outcomes.jsonl. Default: ~/.lyrie/evolve/outcomes.jsonl. */
  outcomesPath?: string;
  /** Directory containing auto-generated skills. */
  skillsDir?: string;
  /** When true, no disk writes are performed. */
  dryRun?: boolean;
  /** Prune threshold: skills with score below this are candidates. Default: 0.3. */
  pruneScoreThreshold?: number;
  /** Prune use count minimum: must have been used this many times. Default: 5. */
  pruneMinUses?: number;
  /** Injectable extractor (for tests). */
  extractor?: SkillExtractor;
}

export interface PruneCandidate {
  filename: string;
  reason: string;
}

export interface DreamReport {
  runAt: number;
  dryRun: boolean;
  unprocessedOutcomes: number;
  extractedSkills: number;
  skippedDuplicates: number;
  pruned: PruneCandidate[];
  totalSkills: number;
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}

// ─── Pruning logic ─────────────────────────────────────────────────────────

/**
 * Read all auto-generated skill files and return those that should be pruned.
 *
 * Pruning criteria (AND):
 *   - avgScore < pruneScoreThreshold
 *   - useCount >= pruneMinUses (has been tried enough times to confirm it's bad)
 */
export function findPruneCandidates(
  skillsDir: string,
  pruneScoreThreshold: number,
  pruneMinUses: number,
): PruneCandidate[] {
  if (!existsSync(skillsDir)) return [];

  const files = readdirSync(skillsDir).filter((f) => f.endsWith(".md"));
  const candidates: PruneCandidate[] = [];

  for (const filename of files) {
    const content = readFileSync(join(skillsDir, filename), "utf8");

    // Parse avgScore from markdown header: **Avg Score:** 0.25
    const scoreMatch = content.match(/\*\*Avg Score:\*\*\s*([\d.]+)/);
    const avgScore = scoreMatch ? parseFloat(scoreMatch[1]!) : 1;

    // Parse useCount from metadata comments (not in base template, but check anyway)
    // For now, parse from a <!-- uses: N --> comment if present.
    const usesMatch = content.match(/<!--\s*uses:\s*(\d+)\s*-->/);
    const useCount = usesMatch ? parseInt(usesMatch[1]!, 10) : 0;

    if (avgScore < pruneScoreThreshold && useCount >= pruneMinUses) {
      candidates.push({
        filename,
        reason: `avgScore=${avgScore} < ${pruneScoreThreshold}, useCount=${useCount} >= ${pruneMinUses}`,
      });
    }
  }

  return candidates;
}

/**
 * Prune (delete) skill files identified as candidates.
 * In dryRun mode, files are not deleted.
 */
export function pruneSkills(
  skillsDir: string,
  candidates: PruneCandidate[],
  dryRun: boolean,
): void {
  if (dryRun) return;
  const { unlinkSync } = require("node:fs");
  for (const c of candidates) {
    try {
      unlinkSync(join(skillsDir, c.filename));
    } catch {
      // Ignore if already deleted
    }
  }
}

// ─── Dream Cycle runner ────────────────────────────────────────────────────

export async function runDreamCycle(opts: DreamCycleOptions = {}): Promise<DreamReport> {
  const outcomesPath =
    opts.outcomesPath ?? join(homedir(), ".lyrie", "evolve", "outcomes.jsonl");
  const skillsDir =
    opts.skillsDir ?? join(homedir(), ".lyrie", "evolve", "skills");
  const dryRun = opts.dryRun ?? false;
  const pruneScoreThreshold = opts.pruneScoreThreshold ?? 0.3;
  const pruneMinUses = opts.pruneMinUses ?? 5;

  // Step 1: Read unprocessed outcomes.
  let unprocessedCount = 0;
  if (existsSync(outcomesPath)) {
    const lines = readFileSync(outcomesPath, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0);
    unprocessedCount = lines.length;
  }

  // Step 2: Extract skills from high-quality outcomes.
  const extractor =
    opts.extractor ??
    new SkillExtractor({
      outcomesPath,
      skillsDir,
      dryRun,
    });

  let extractedSkills = 0;
  let skippedDuplicates = 0;

  if (unprocessedCount > 0) {
    const result = await extractor.extract();
    extractedSkills = result.written;
    skippedDuplicates = result.skippedDuplicates;
  }

  // Step 3: Prune low-value skills.
  const pruneCandidates = findPruneCandidates(
    skillsDir,
    pruneScoreThreshold,
    pruneMinUses,
  );
  pruneSkills(skillsDir, pruneCandidates, dryRun);

  // Step 4: Count remaining skills.
  const totalSkills = existsSync(skillsDir)
    ? readdirSync(skillsDir).filter((f) => f.endsWith(".md")).length
    : 0;

  const report: DreamReport = {
    runAt: Date.now(),
    dryRun,
    unprocessedOutcomes: unprocessedCount,
    extractedSkills,
    skippedDuplicates,
    pruned: pruneCandidates,
    totalSkills,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };

  return report;
}

export const DREAM_VERSION = "lyrie-evolve-dream-1.0.0";
