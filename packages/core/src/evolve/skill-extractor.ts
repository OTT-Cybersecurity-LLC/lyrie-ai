/**
 * Lyrie LyrieEvolve — Skill Auto-Generation
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Reads scored outcomes from outcomes.jsonl, finds high-quality sessions
 * (score >= 0.5), uses an LLM to extract 1-3 reusable skill patterns,
 * writes OpenClaw-compatible SKILL.md files to skills/auto-generated/,
 * and uses cosine similarity to deduplicate against existing skills.
 *
 * © OTT Cybersecurity LLC — All rights reserved.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";
import type { TaskOutcome, Domain } from "./scorer";

// ─── Public types ──────────────────────────────────────────────────────────

export interface SkillPattern {
  /** Stable skill id (slug). */
  id: string;
  /** Human-readable skill name. */
  name: string;
  /** Domain this skill belongs to. */
  domain: Domain;
  /** Short description for the SKILL.md header. */
  description: string;
  /** Step-by-step instructions extracted from outcomes. */
  steps: string[];
  /** Example invocation command or usage. */
  exampleCommand?: string;
  /** Average score of source outcomes (0–1). */
  avgScore: number;
  /** Number of source outcomes used. */
  sourceCount: number;
  /** Unix ms timestamp of extraction. */
  extractedAt: number;
}

/** Result of a single extraction run. */
export interface ExtractionResult {
  patterns: SkillPattern[];
  skippedDuplicates: number;
  written: number;
  dryRun: boolean;
}

/** LLM interface for skill extraction (injectable for tests). */
export interface ExtractorLLM {
  extractSkills(outcomes: TaskOutcome[]): Promise<SkillPattern[]>;
}

export interface SkillExtractorOptions {
  /** Path to outcomes.jsonl (default: ~/.lyrie/evolve/outcomes.jsonl). */
  outcomesPath?: string;
  /** Directory to write skill files (default: skills/auto-generated/). */
  skillsDir?: string;
  /** Minimum score to consider an outcome for extraction. */
  minScore?: number;
  /** Cosine similarity threshold for dedup (skip if > this). */
  dedupThreshold?: number;
  /** Shield guard for scanning extracted text. */
  shield?: ShieldGuardLike;
  /** Skip disk writes. */
  dryRun?: boolean;
  /** Injectable LLM implementation. */
  llm?: ExtractorLLM;
}

// ─── Text vectorization helpers ────────────────────────────────────────────

/**
 * Simple bag-of-words tf vector from text.
 * Returns a Map<term, frequency>.
 */
export function tokenize(text: string): Map<string, number> {
  const terms = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 2);
  const freq = new Map<string, number>();
  for (const t of terms) {
    freq.set(t, (freq.get(t) ?? 0) + 1);
  }
  return freq;
}

/**
 * Cosine similarity between two term-frequency maps.
 * Range: 0 (orthogonal) to 1 (identical).
 */
export function cosineSimilarity(a: Map<string, number>, b: Map<string, number>): number {
  let dot = 0;
  let normA = 0;
  let normB = 0;

  for (const [term, freqA] of a) {
    const freqB = b.get(term) ?? 0;
    dot += freqA * freqB;
    normA += freqA * freqA;
  }
  for (const [, freqB] of b) {
    normB += freqB * freqB;
  }

  if (normA === 0 || normB === 0) return 0;
  return dot / (Math.sqrt(normA) * Math.sqrt(normB));
}

// ─── Default LLM (heuristic fallback — no network required) ───────────────

/**
 * Heuristic skill extractor that groups outcomes by domain and
 * synthesizes patterns from high-score runs. This is the built-in
 * fallback; callers can inject a real LLM via options.llm.
 */
export class HeuristicExtractorLLM implements ExtractorLLM {
  async extractSkills(outcomes: TaskOutcome[]): Promise<SkillPattern[]> {
    if (outcomes.length === 0) return [];

    // Group by domain.
    const byDomain = new Map<Domain, TaskOutcome[]>();
    for (const o of outcomes) {
      const list = byDomain.get(o.domain) ?? [];
      list.push(o);
      byDomain.set(o.domain, list);
    }

    const patterns: SkillPattern[] = [];

    for (const [domain, domainOutcomes] of byDomain) {
      // Take up to 3 skills per domain per run.
      const avgScore =
        domainOutcomes.reduce((s, o) => s + o.score, 0) / domainOutcomes.length;

      const summaries = domainOutcomes
        .filter((o) => o.summary)
        .map((o) => o.summary!)
        .slice(0, 5);

      const slug = `auto-${domain}-${Date.now()}`;
      const pattern: SkillPattern = {
        id: slug,
        name: `Auto-Generated ${capitalize(domain)} Skill`,
        domain,
        description: `Automatically extracted from ${domainOutcomes.length} high-quality ${domain} task outcomes (avg score: ${avgScore.toFixed(2)}).`,
        steps: summaries.length > 0
          ? summaries.map((s, i) => `${i + 1}. ${s}`)
          : [`1. Apply ${domain} best practices based on past successful outcomes.`],
        avgScore,
        sourceCount: domainOutcomes.length,
        extractedAt: Date.now(),
      };

      patterns.push(pattern);
    }

    return patterns.slice(0, 3);
  }
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ─── SKILL.md template ─────────────────────────────────────────────────────

export function renderSkillMd(p: SkillPattern): string {
  const date = new Date(p.extractedAt).toISOString().split("T")[0];
  return `# ${p.name}

> _Lyrie.ai by OTT Cybersecurity LLC — Auto-Generated Skill._

**Domain:** ${p.domain}
**Avg Score:** ${p.avgScore.toFixed(2)}
**Sources:** ${p.sourceCount} outcomes
**Generated:** ${date}

## Description

${p.description}

## Steps

${p.steps.join("\n")}

${p.exampleCommand ? `## Example\n\n\`\`\`\n${p.exampleCommand}\n\`\`\`` : ""}

---
_Auto-generated by LyrieEvolve. Review before use. Signature: Lyrie.ai by OTT Cybersecurity LLC._
`;
}

// ─── SkillExtractor class ──────────────────────────────────────────────────

export class SkillExtractor {
  private readonly outcomesPath: string;
  private readonly skillsDir: string;
  private readonly minScore: number;
  private readonly dedupThreshold: number;
  private readonly shield: ShieldGuardLike;
  private readonly dryRun: boolean;
  private readonly llm: ExtractorLLM;

  constructor(opts: SkillExtractorOptions = {}) {
    this.outcomesPath =
      opts.outcomesPath ?? join(homedir(), ".lyrie", "evolve", "outcomes.jsonl");
    // Default skills dir relative to repo root (3 levels up from packages/core/src)
    this.skillsDir = opts.skillsDir ?? join(__dirname, "..", "..", "..", "..", "skills", "auto-generated");
    this.minScore = opts.minScore ?? 0.5;
    this.dedupThreshold = opts.dedupThreshold ?? 0.85;
    this.shield = opts.shield ?? ShieldGuard.fallback();
    this.dryRun = opts.dryRun ?? false;
    this.llm = opts.llm ?? new HeuristicExtractorLLM();
  }

  /** Read outcomes.jsonl and return all entries. */
  readOutcomes(): TaskOutcome[] {
    if (!existsSync(this.outcomesPath)) return [];
    const lines = readFileSync(this.outcomesPath, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0);
    const outcomes: TaskOutcome[] = [];
    for (const line of lines) {
      try {
        outcomes.push(JSON.parse(line) as TaskOutcome);
      } catch {
        // skip malformed lines
      }
    }
    return outcomes;
  }

  /** Filter outcomes to those with score >= minScore. */
  filterHighQuality(outcomes: TaskOutcome[]): TaskOutcome[] {
    return outcomes.filter((o) => o.score >= this.minScore);
  }

  /**
   * Read existing skill files from skillsDir and return their text vectors.
   */
  loadExistingVectors(): Array<{ id: string; vec: Map<string, number> }> {
    if (!existsSync(this.skillsDir)) return [];
    const files = readdirSync(this.skillsDir).filter((f) => f.endsWith(".md"));
    return files.map((f) => {
      const text = readFileSync(join(this.skillsDir, f), "utf8");
      return { id: f, vec: tokenize(text) };
    });
  }

  /**
   * Check if a new pattern is a duplicate of any existing skill.
   */
  isDuplicate(
    pattern: SkillPattern,
    existingVectors: Array<{ id: string; vec: Map<string, number> }>,
  ): boolean {
    const newText = `${pattern.name} ${pattern.description} ${pattern.steps.join(" ")}`;
    const newVec = tokenize(newText);
    for (const existing of existingVectors) {
      const sim = cosineSimilarity(newVec, existing.vec);
      if (sim > this.dedupThreshold) return true;
    }
    return false;
  }

  /**
   * Shield-scan a pattern. Returns scanned (possibly redacted) pattern.
   */
  shieldScan(pattern: SkillPattern): SkillPattern {
    const text = `${pattern.name} ${pattern.description}`;
    const verdict = this.shield.scanRecalled(text);
    if (verdict.blocked) {
      return {
        ...pattern,
        name: "[Shield-Redacted]",
        description: "[Content blocked by Shield Doctrine]",
        steps: ["[Redacted]"],
      };
    }
    return pattern;
  }

  /** Write a skill pattern to disk as SKILL.md. */
  writeSkill(pattern: SkillPattern): string {
    const filename = `${pattern.id}.md`;
    const path = join(this.skillsDir, filename);
    const content = renderSkillMd(pattern);
    if (!this.dryRun) {
      if (!existsSync(this.skillsDir)) {
        mkdirSync(this.skillsDir, { recursive: true });
      }
      writeFileSync(path, content, "utf8");
    }
    return path;
  }

  /**
   * Full extraction pipeline:
   * 1. Read outcomes.jsonl
   * 2. Filter score >= minScore
   * 3. LLM extract patterns
   * 4. Shield scan
   * 5. Cosine dedup
   * 6. Write SKILL.md files
   */
  async extract(): Promise<ExtractionResult> {
    const outcomes = this.readOutcomes();
    const qualified = this.filterHighQuality(outcomes);

    if (qualified.length === 0) {
      return { patterns: [], skippedDuplicates: 0, written: 0, dryRun: this.dryRun };
    }

    const rawPatterns = await this.llm.extractSkills(qualified);
    const existingVectors = this.loadExistingVectors();

    let skippedDuplicates = 0;
    let written = 0;
    const finalPatterns: SkillPattern[] = [];

    for (const raw of rawPatterns) {
      const scanned = this.shieldScan(raw);

      if (this.isDuplicate(scanned, existingVectors)) {
        skippedDuplicates++;
        continue;
      }

      this.writeSkill(scanned);
      written++;
      finalPatterns.push(scanned);

      // Add new pattern to existing vectors for subsequent dedup checks
      const newText = `${scanned.name} ${scanned.description} ${scanned.steps.join(" ")}`;
      existingVectors.push({ id: scanned.id, vec: tokenize(newText) });
    }

    return {
      patterns: finalPatterns,
      skippedDuplicates,
      written,
      dryRun: this.dryRun,
    };
  }
}

export const EXTRACTOR_VERSION = "lyrie-evolve-extractor-1.0.0";
