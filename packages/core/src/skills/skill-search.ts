/**
 * SkillSearch — Fuzzy/keyword search over skill descriptions and names.
 *
 * No external dependencies. Scores candidates by:
 *   1. Exact substring match in name (highest weight)
 *   2. Exact substring match in description
 *   3. Partial word overlap in name
 *   4. Partial word overlap in description / triggers
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { SkillManifest } from "./skill-types";

export interface SearchResult {
  manifest: SkillManifest;
  score: number;
}

// ─── Tokenizer ───────────────────────────────────────────────────────────────

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

// ─── Scorer ──────────────────────────────────────────────────────────────────

function scoreManifest(manifest: SkillManifest, queryTokens: string[], queryRaw: string): number {
  const nameLower = manifest.name.toLowerCase();
  const descLower = (manifest.description ?? "").toLowerCase();
  const queryLower = queryRaw.toLowerCase();

  let score = 0;

  // Exact substring matches (highest value)
  if (nameLower.includes(queryLower)) score += 100;
  if (descLower.includes(queryLower)) score += 50;

  // Token-level overlap
  const nameTokens = tokenize(manifest.name);
  const descTokens = tokenize(manifest.description ?? "");
  const triggerTokens = (manifest.triggers ?? []).flatMap((t) => tokenize(t));

  for (const qt of queryTokens) {
    if (nameTokens.some((t) => t.includes(qt) || qt.includes(t))) score += 20;
    if (descTokens.some((t) => t.includes(qt) || qt.includes(t))) score += 10;
    if (triggerTokens.some((t) => t.includes(qt) || qt.includes(t))) score += 8;
  }

  // Exact token match bonus
  for (const qt of queryTokens) {
    if (nameTokens.includes(qt)) score += 15;
    if (descTokens.includes(qt)) score += 7;
  }

  return score;
}

// ─── SkillSearch ─────────────────────────────────────────────────────────────

export class SkillSearch {
  /**
   * Search `manifests` for those matching `query`.
   * Returns results sorted by descending score, filtered by `minScore`.
   */
  static search(
    manifests: SkillManifest[],
    query: string,
    opts: { limit?: number; minScore?: number } = {}
  ): SearchResult[] {
    const { limit = 20, minScore = 1 } = opts;
    if (!query.trim()) return manifests.slice(0, limit).map((m) => ({ manifest: m, score: 0 }));

    const queryTokens = tokenize(query);
    const results: SearchResult[] = [];

    for (const manifest of manifests) {
      const score = scoreManifest(manifest, queryTokens, query);
      if (score >= minScore) results.push({ manifest, score });
    }

    return results
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }
}
