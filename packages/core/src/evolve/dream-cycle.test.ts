/**
 * Lyrie LyrieEvolve — Dream Cycle unit tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";

import {
  runDreamCycle,
  findPruneCandidates,
  pruneSkills,
  DREAM_VERSION,
} from "./dream-cycle";
import type { TaskOutcome } from "./scorer";

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  const dir = join(tmpdir(), `dream-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeOutcomes(dir: string, outcomes: Partial<TaskOutcome>[]): string {
  const path = join(dir, "outcomes.jsonl");
  const defaults: TaskOutcome = {
    id: "o1",
    timestamp: Date.now(),
    domain: "general",
    score: 1,
    signals: { completed: true },
    useCount: 0,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
  };
  const lines = outcomes.map((o) => JSON.stringify({ ...defaults, ...o }));
  writeFileSync(path, lines.join("\n") + "\n", "utf8");
  return path;
}

function writeSkillFile(dir: string, filename: string, avgScore: number, uses: number): void {
  const content = `# Test Skill\n\n**Avg Score:** ${avgScore}\n**Domain:** general\n<!-- uses: ${uses} -->\n\nSome steps.\n`;
  writeFileSync(join(dir, filename), content, "utf8");
}

// ─── findPruneCandidates ───────────────────────────────────────────────────

describe("findPruneCandidates", () => {
  test("returns empty for non-existent dir", () => {
    const result = findPruneCandidates("/tmp/no-such-dir-xyz", 0.3, 5);
    expect(result).toEqual([]);
  });

  test("identifies low-score high-use skills", () => {
    const dir = makeTmpDir();
    writeSkillFile(dir, "bad-skill.md", 0.1, 10);
    const candidates = findPruneCandidates(dir, 0.3, 5);
    expect(candidates.length).toBe(1);
    expect(candidates[0]!.filename).toBe("bad-skill.md");
  });

  test("keeps good skills", () => {
    const dir = makeTmpDir();
    writeSkillFile(dir, "good-skill.md", 0.9, 10);
    const candidates = findPruneCandidates(dir, 0.3, 5);
    expect(candidates.length).toBe(0);
  });

  test("keeps low-score but low-use skills (not enough evidence)", () => {
    const dir = makeTmpDir();
    writeSkillFile(dir, "new-bad.md", 0.1, 2); // only 2 uses, threshold is 5
    const candidates = findPruneCandidates(dir, 0.3, 5);
    expect(candidates.length).toBe(0);
  });
});

// ─── pruneSkills ──────────────────────────────────────────────────────────

describe("pruneSkills", () => {
  test("dryRun does not delete files", () => {
    const dir = makeTmpDir();
    writeSkillFile(dir, "prune-me.md", 0.1, 10);
    pruneSkills(dir, [{ filename: "prune-me.md", reason: "test" }], true);
    expect(existsSync(join(dir, "prune-me.md"))).toBe(true);
  });

  test("deletes files when not dryRun", () => {
    const dir = makeTmpDir();
    writeSkillFile(dir, "delete-me.md", 0.1, 10);
    pruneSkills(dir, [{ filename: "delete-me.md", reason: "test" }], false);
    expect(existsSync(join(dir, "delete-me.md"))).toBe(false);
  });
});

// ─── runDreamCycle ────────────────────────────────────────────────────────

describe("runDreamCycle", () => {
  test("DREAM_VERSION is defined", () => {
    expect(DREAM_VERSION).toMatch(/lyrie-evolve-dream/);
  });

  test("dryRun with no outcomes returns zero stats", async () => {
    const dir = makeTmpDir();
    const report = await runDreamCycle({
      outcomesPath: join(dir, "missing.jsonl"),
      skillsDir: join(dir, "skills"),
      dryRun: true,
    });
    expect(report.unprocessedOutcomes).toBe(0);
    expect(report.extractedSkills).toBe(0);
    expect(report.dryRun).toBe(true);
    expect(report.signature).toBe("Lyrie.ai by OTT Cybersecurity LLC");
  });

  test("counts unprocessed outcomes", async () => {
    const dir = makeTmpDir();
    const outcomesPath = writeOutcomes(dir, [
      { score: 1, domain: "code" },
      { score: 1, domain: "seo" },
    ]);
    const report = await runDreamCycle({
      outcomesPath,
      skillsDir: join(dir, "skills"),
      dryRun: true,
    });
    expect(report.unprocessedOutcomes).toBe(2);
  });

  test("report includes pruned list", async () => {
    const dir = makeTmpDir();
    const skillsDir = join(dir, "skills");
    mkdirSync(skillsDir, { recursive: true });
    writeSkillFile(skillsDir, "stale.md", 0.1, 10);

    const report = await runDreamCycle({
      outcomesPath: join(dir, "missing.jsonl"),
      skillsDir,
      dryRun: true,
      pruneScoreThreshold: 0.3,
      pruneMinUses: 5,
    });

    expect(report.pruned.length).toBe(1);
    expect(report.pruned[0]!.filename).toBe("stale.md");
  });

  test("report has runAt timestamp", async () => {
    const before = Date.now();
    const report = await runDreamCycle({ dryRun: true });
    expect(report.runAt).toBeGreaterThanOrEqual(before);
  });
});
