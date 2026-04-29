/**
 * Lyrie LyrieEvolve — Contexture Layer
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * The Contexture Layer retrieves relevant skill contexts from past successful
 * outcomes and builds prompt injections for the active agent turn.
 *
 * Architecture:
 *   - Stores SkillContext entries in an in-memory table (with optional
 *     LanceDB-backed persistence when available)
 *   - Retrieves top-K contexts via cosine similarity
 *   - Applies MMR (Maximal Marginal Relevance) diversity to avoid repetition
 *   - Builds a structured prompt injection string for LyrieEngine consumption
 *
 * © OTT Cybersecurity LLC — All rights reserved.
 */

import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";
import { tokenize, cosineSimilarity } from "./skill-extractor";
import type { Domain } from "./scorer";

// ─── Public types ──────────────────────────────────────────────────────────

export interface SkillContext {
  /** Stable id for this context entry. */
  id: string;
  /** The domain this context applies to. */
  domain: Domain;
  /** Summary of the skill or lesson learned. */
  summary: string;
  /** Average score of contributing outcomes (0–1). */
  score: number;
  /** Number of times this context has been successfully used. */
  useCount: number;
  /** Unix ms timestamp when this context was stored. */
  storedAt: number;
  /** Provenance. */
  signature: "Lyrie.ai by OTT Cybersecurity LLC";
}

/** Result of an MMR retrieval. */
export interface RetrievalResult {
  context: SkillContext;
  /** Cosine similarity to query (0–1). */
  relevance: number;
  /** MMR score (after diversity penalty). */
  mmrScore: number;
}

export interface ContextureOptions {
  /** Shield guard for scanning stored contexts. */
  shield?: ShieldGuardLike;
  /** MMR lambda: 0 = pure diversity, 1 = pure relevance. Default: 0.7. */
  mmrLambda?: number;
  /** Max contexts to store (evicts lowest-score entries). Default: 1000. */
  maxEntries?: number;
}

// ─── MMR implementation ────────────────────────────────────────────────────

/**
 * Maximal Marginal Relevance selection.
 *
 * Given candidate results sorted by relevance, pick `topK` entries
 * that balance relevance vs. diversity (low similarity to already-selected).
 *
 * λ = 1 → pure relevance (greedy top-K)
 * λ = 0 → pure diversity
 */
export function mmrSelect(
  query: Map<string, number>,
  candidates: Array<{ context: SkillContext; relevance: number }>,
  topK: number,
  lambda: number,
): RetrievalResult[] {
  if (candidates.length === 0) return [];

  const selected: RetrievalResult[] = [];
  const remaining = [...candidates];

  // Pre-compute text vectors for each candidate.
  const vecs = new Map<string, Map<string, number>>(
    remaining.map((c) => [
      c.context.id,
      tokenize(`${c.context.summary} ${c.context.domain}`),
    ]),
  );

  while (selected.length < topK && remaining.length > 0) {
    let bestIdx = -1;
    let bestScore = -Infinity;

    for (let i = 0; i < remaining.length; i++) {
      const cand = remaining[i]!;
      const candVec = vecs.get(cand.context.id)!;

      // Relevance term: cosine(query, candidate)
      const relevanceTerm = lambda * cand.relevance;

      // Diversity term: 1 - max cosine(candidate, already selected)
      let maxSim = 0;
      for (const sel of selected) {
        const selVec = vecs.get(sel.context.id)!;
        const sim = cosineSimilarity(candVec, selVec);
        if (sim > maxSim) maxSim = sim;
      }
      const diversityTerm = (1 - lambda) * (1 - maxSim);

      const mmrScore = relevanceTerm + diversityTerm;

      if (mmrScore > bestScore) {
        bestScore = mmrScore;
        bestIdx = i;
      }
    }

    if (bestIdx < 0) break;
    const chosen = remaining[bestIdx]!;
    selected.push({
      context: chosen.context,
      relevance: chosen.relevance,
      mmrScore: bestScore,
    });
    remaining.splice(bestIdx, 1);
  }

  return selected;
}

// ─── Contexture class ──────────────────────────────────────────────────────

export class Contexture {
  private readonly table: Map<string, SkillContext> = new Map();
  private readonly shield: ShieldGuardLike;
  private readonly mmrLambda: number;
  private readonly maxEntries: number;

  constructor(opts: ContextureOptions = {}) {
    this.shield = opts.shield ?? ShieldGuard.fallback();
    this.mmrLambda = opts.mmrLambda ?? 0.7;
    this.maxEntries = opts.maxEntries ?? 1000;
  }

  /** Store a SkillContext (Shield-scanned). */
  store(ctx: SkillContext): void {
    const verdict = this.shield.scanRecalled(ctx.summary);
    if (verdict.blocked) return; // Silently drop Shield-blocked content.

    // Evict if at capacity (remove lowest score entry).
    if (this.table.size >= this.maxEntries) {
      let lowestId = "";
      let lowestScore = Infinity;
      for (const [id, entry] of this.table) {
        if (entry.score < lowestScore) {
          lowestScore = entry.score;
          lowestId = id;
        }
      }
      if (lowestId) this.table.delete(lowestId);
    }

    this.table.set(ctx.id, ctx);
  }

  /** Update use count for a context (called after it's successfully used). */
  markUsed(id: string): void {
    const ctx = this.table.get(id);
    if (ctx) {
      this.table.set(id, { ...ctx, useCount: ctx.useCount + 1 });
    }
  }

  /** Delete a context by id. */
  delete(id: string): boolean {
    return this.table.delete(id);
  }

  /** Return all stored contexts. */
  all(): SkillContext[] {
    return Array.from(this.table.values());
  }

  /** Return count of stored contexts. */
  size(): number {
    return this.table.size;
  }

  /**
   * Retrieve top-K relevant SkillContexts for a query + domain filter.
   * Uses cosine similarity + MMR diversity.
   */
  retrieve(query: string, domain?: Domain, topK: number = 3): RetrievalResult[] {
    const queryVec = tokenize(query);

    let candidates = Array.from(this.table.values());
    if (domain) {
      candidates = candidates.filter((c) => c.domain === domain);
    }

    if (candidates.length === 0) return [];

    // Compute relevance scores.
    const scored = candidates.map((ctx) => {
      const ctxVec = tokenize(`${ctx.summary} ${ctx.domain}`);
      const relevance = cosineSimilarity(queryVec, ctxVec);
      return { context: ctx, relevance };
    });

    // Sort by relevance descending.
    scored.sort((a, b) => b.relevance - a.relevance);

    // Apply MMR for diversity.
    return mmrSelect(queryVec, scored, topK, this.mmrLambda);
  }

  /**
   * Build a prompt injection string from retrieved contexts.
   * Returns a structured block suitable for prepending to a system prompt.
   */
  buildInjection(contexts: RetrievalResult[]): string {
    if (contexts.length === 0) return "";

    const lines: string[] = [
      "<!-- LyrieEvolve Contexture — Lyrie.ai by OTT Cybersecurity LLC -->",
      "<lyrie_context>",
      "The following skill contexts were retrieved from past successful task outcomes.",
      "Apply these patterns to improve your current response.",
      "",
    ];

    for (let i = 0; i < contexts.length; i++) {
      const r = contexts[i]!;
      lines.push(`[Context ${i + 1}] Domain: ${r.context.domain} | Score: ${r.context.score.toFixed(2)} | Relevance: ${r.relevance.toFixed(2)}`);
      lines.push(r.context.summary);
      lines.push("");
    }

    lines.push("</lyrie_context>");
    return lines.join("\n");
  }

  /**
   * Full retrieve + inject pipeline: retrieve topK contexts and build injection.
   */
  retrieveAndInject(query: string, domain?: Domain, topK: number = 3): string {
    const results = this.retrieve(query, domain, topK);
    return this.buildInjection(results);
  }
}

export const CONTEXTURE_VERSION = "lyrie-evolve-contexture-1.0.0";

/** Shared table name for LanceDB (reserved for future persistence). */
export const CONTEXTURE_TABLE = "lyrie_contexture";
