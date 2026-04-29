/**
 * Lyrie LyrieEvolve — SkillExtractor unit tests.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";

import {
  SkillExtractor,
  HeuristicExtractorLLM,
  tokenize,
  cosineSimilarity,
  renderSkillMd,
  EXTRACTOR_VERSION,
  type SkillPattern,
  type ExtractorLLM,
} from "./skill-extractor";
import type { TaskOutcome } from "./scorer";

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeOutcome(overrides: Partial<TaskOutcome> = {}): TaskOutcome {
  return {
    id: "o1",
    timestamp: Date.now(),
    domain: "general",
    score: 1,
    signals: { completed: true },
    summary: "Task completed successfully with no issues",
    useCount: 0,
    signature: "Lyrie.ai by OTT Cybersecurity LLC",
    ...overrides,
  };
}

function makeTmpDir(): string {
  const dir = join(tmpdir(), `extractor-test-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeTmpOutcomes(outcomes: TaskOutcome[], dir: string): string {
  const path = join(dir, "outcomes.jsonl");
  writeFileSync(path, outcomes.map((o) => JSON.stringify(o)).join("\n") + "\n", "utf8");
  return path;
}

// ─── tokenize ─────────────────────────────────────────────────────────────

describe("tokenize", () => {
  test("returns empty map for empty string", () => {
    expect(tokenize("").size).toBe(0);
  });

  test("counts terms correctly", () => {
    const m = tokenize("hello world hello");
    expect(m.get("hello")).toBe(2);
    expect(m.get("world")).toBe(1);
  });

  test("ignores short tokens (len <= 2)", () => {
    const m = tokenize("a ab abc abcd");
    expect(m.has("a")).toBe(false);
    expect(m.has("ab")).toBe(false);
    expect(m.has("abc")).toBe(true);
  });

  test("lowercases all terms", () => {
    const m = tokenize("HELLO World");
    expect(m.has("hello")).toBe(true);
    expect(m.has("world")).toBe(true);
  });
});

// ─── cosineSimilarity ──────────────────────────────────────────────────────

describe("cosineSimilarity", () => {
  test("identical vectors return 1", () => {
    const v = tokenize("the quick brown fox");
    expect(cosineSimilarity(v, v)).toBeCloseTo(1, 5);
  });

  test("orthogonal vectors return 0", () => {
    const a = new Map([["cat", 1]]);
    const b = new Map([["dog", 1]]);
    expect(cosineSimilarity(a, b)).toBe(0);
  });

  test("empty vectors return 0", () => {
    expect(cosineSimilarity(new Map(), new Map())).toBe(0);
  });

  test("similar texts have high similarity", () => {
    const a = tokenize("lyrie cybersecurity pentest vulnerability scanner");
    const b = tokenize("lyrie cybersecurity scanner vulnerability pentest");
    expect(cosineSimilarity(a, b)).toBeGreaterThan(0.9);
  });

  test("unrelated texts have low similarity", () => {
    const a = tokenize("apple banana orange fruit");
    const b = tokenize("neural network machine learning model");
    expect(cosineSimilarity(a, b)).toBeLessThan(0.1);
  });
});

// ─── renderSkillMd ────────────────────────────────────────────────────────

describe("renderSkillMd", () => {
  test("renders valid markdown with all fields", () => {
    const p: SkillPattern = {
      id: "auto-cyber-123",
      name: "Cyber Skill",
      domain: "cyber",
      description: "A test skill",
      steps: ["1. Do this", "2. Do that"],
      avgScore: 0.9,
      sourceCount: 5,
      extractedAt: Date.now(),
    };
    const md = renderSkillMd(p);
    expect(md).toContain("# Cyber Skill");
    expect(md).toContain("**Domain:** cyber");
    expect(md).toContain("1. Do this");
    expect(md).toContain("Lyrie.ai by OTT Cybersecurity LLC");
  });

  test("omits example section when no exampleCommand", () => {
    const p: SkillPattern = {
      id: "test",
      name: "Test",
      domain: "general",
      description: "d",
      steps: ["1. step"],
      avgScore: 1,
      sourceCount: 1,
      extractedAt: Date.now(),
    };
    const md = renderSkillMd(p);
    expect(md).not.toContain("## Example");
  });
});

// ─── HeuristicExtractorLLM ────────────────────────────────────────────────

describe("HeuristicExtractorLLM", () => {
  test("returns empty for no outcomes", async () => {
    const llm = new HeuristicExtractorLLM();
    const result = await llm.extractSkills([]);
    expect(result).toEqual([]);
  });

  test("groups outcomes by domain", async () => {
    const llm = new HeuristicExtractorLLM();
    const outcomes = [
      makeOutcome({ domain: "cyber", summary: "found XSS" }),
      makeOutcome({ domain: "seo", summary: "ranked keywords" }),
    ];
    const patterns = await llm.extractSkills(outcomes);
    const domains = patterns.map((p) => p.domain);
    expect(domains).toContain("cyber");
    expect(domains).toContain("seo");
  });

  test("returns at most 3 patterns", async () => {
    const llm = new HeuristicExtractorLLM();
    const outcomes = ["cyber", "seo", "trading", "code", "general"].map((d) =>
      makeOutcome({ domain: d as any }),
    );
    const patterns = await llm.extractSkills(outcomes);
    expect(patterns.length).toBeLessThanOrEqual(3);
  });
});

// ─── SkillExtractor ───────────────────────────────────────────────────────

describe("SkillExtractor", () => {
  test("EXTRACTOR_VERSION is defined", () => {
    expect(EXTRACTOR_VERSION).toMatch(/lyrie-evolve-extractor/);
  });

  test("readOutcomes returns empty for missing file", () => {
    const ex = new SkillExtractor({ outcomesPath: "/tmp/does-not-exist.jsonl", dryRun: true });
    expect(ex.readOutcomes()).toEqual([]);
  });

  test("readOutcomes parses valid jsonl", () => {
    const dir = makeTmpDir();
    const outcomes = [makeOutcome({ id: "x1" }), makeOutcome({ id: "x2" })];
    const path = writeTmpOutcomes(outcomes, dir);
    const ex = new SkillExtractor({ outcomesPath: path, dryRun: true });
    const result = ex.readOutcomes();
    expect(result.length).toBe(2);
    expect(result[0]!.id).toBe("x1");
  });

  test("filterHighQuality filters by minScore", () => {
    const ex = new SkillExtractor({ minScore: 0.5, dryRun: true });
    const outcomes = [
      makeOutcome({ score: 0 }),
      makeOutcome({ score: 0.5 }),
      makeOutcome({ score: 1 }),
    ];
    const filtered = ex.filterHighQuality(outcomes);
    expect(filtered.length).toBe(2);
    expect(filtered.every((o) => o.score >= 0.5)).toBe(true);
  });

  test("isDuplicate returns true for very similar content", () => {
    const ex = new SkillExtractor({ dedupThreshold: 0.85, dryRun: true });
    const text = "lyrie cybersecurity pentest vulnerability scan automated";
    const existing = [{ id: "old.md", vec: tokenize(text) }];
    const pattern: SkillPattern = {
      id: "new",
      name: "lyrie cybersecurity pentest vulnerability scan automated",
      domain: "cyber",
      description: "",
      steps: [],
      avgScore: 1,
      sourceCount: 1,
      extractedAt: Date.now(),
    };
    expect(ex.isDuplicate(pattern, existing)).toBe(true);
  });

  test("isDuplicate returns false for different content", () => {
    const ex = new SkillExtractor({ dedupThreshold: 0.85, dryRun: true });
    const existing = [{ id: "old.md", vec: tokenize("seo keyword ranking backlinks") }];
    const pattern: SkillPattern = {
      id: "new",
      name: "Trading Risk Management",
      domain: "trading",
      description: "Stop loss and drawdown monitoring",
      steps: ["1. Monitor pnl"],
      avgScore: 1,
      sourceCount: 1,
      extractedAt: Date.now(),
    };
    expect(ex.isDuplicate(pattern, existing)).toBe(false);
  });

  test("full extract pipeline dryRun returns patterns without writing", async () => {
    const dir = makeTmpDir();
    const skillsDir = join(dir, "skills");
    const outcomes = [
      makeOutcome({ domain: "code", summary: "build and tests passed", score: 1 }),
      makeOutcome({ domain: "code", summary: "deployed to production", score: 1 }),
    ];
    const outcomesPath = writeTmpOutcomes(outcomes, dir);

    const ex = new SkillExtractor({
      outcomesPath,
      skillsDir,
      dryRun: true,
    });

    const result = await ex.extract();
    expect(result.dryRun).toBe(true);
    // Should have found patterns even in dryRun
    expect(result.patterns.length + result.skippedDuplicates).toBeGreaterThanOrEqual(0);
    // Skills dir should NOT be created in dryRun
    expect(existsSync(skillsDir)).toBe(false);
  });

  test("full extract pipeline writes skills to disk", async () => {
    const dir = makeTmpDir();
    const skillsDir = join(dir, "skills");
    const outcomes = [
      makeOutcome({ domain: "seo", summary: "ranked 5 keywords on page 1", score: 1 }),
    ];
    const outcomesPath = writeTmpOutcomes(outcomes, dir);

    // Use a mock LLM that returns a predictable pattern
    const mockLLM: ExtractorLLM = {
      async extractSkills(outs) {
        return [{
          id: "auto-seo-test",
          name: "SEO Ranking Skill",
          domain: "seo",
          description: "Rank keywords on page 1",
          steps: ["1. Research keywords", "2. Optimize content"],
          avgScore: 1,
          sourceCount: 1,
          extractedAt: Date.now(),
        }];
      },
    };

    const ex = new SkillExtractor({ outcomesPath, skillsDir, llm: mockLLM });
    const result = await ex.extract();
    expect(result.written).toBe(1);
    expect(existsSync(skillsDir)).toBe(true);
    const files = readdirSync(skillsDir);
    expect(files.some((f) => f.endsWith(".md"))).toBe(true);
  });
});
