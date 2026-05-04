/**
 * SkillRegistry — Singleton registry for SKILL.md manifests.
 *
 * Loads from ~/.lyrie/skills/ (and legacy skill directories for backward-compat),
 * indexes by name, and exposes search.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { SkillManifest } from "./skill-types";
import { SkillLoader } from "./skill-loader";
import { SkillSearch } from "./skill-search";

// ─── SkillRegistry ───────────────────────────────────────────────────────────

export class SkillRegistry {
  private static _instance: SkillRegistry | null = null;

  private manifests: Map<string, SkillManifest> = new Map();
  private loader: SkillLoader = new SkillLoader();
  private _loaded = false;

  private constructor() {}

  // ─── Singleton ───────────────────────────────────────────────────────────

  static getInstance(): SkillRegistry {
    if (!SkillRegistry._instance) {
      SkillRegistry._instance = new SkillRegistry();
    }
    return SkillRegistry._instance;
  }

  /** Reset the singleton — useful in tests. */
  static reset(): void {
    SkillRegistry._instance = null;
  }

  // ─── Loading ─────────────────────────────────────────────────────────────

  /**
   * Load skills from the given paths (or the default set if omitted).
   * Can be called multiple times to add more directories.
   */
  async loadAll(paths?: string[]): Promise<void> {
    const dirs = paths ?? SkillLoader.defaultPaths();
    for (const dir of dirs) {
      const found = await this.loader.discover(dir);
      for (const m of found) {
        // Use normalised name as key; skip duplicates (first one wins)
        const key = this._normalise(m.name);
        if (!this.manifests.has(key)) {
          this.manifests.set(key, m);
        }
      }
    }
    this._loaded = true;
  }

  get loaded(): boolean {
    return this._loaded;
  }

  // ─── Lookup ──────────────────────────────────────────────────────────────

  /** Exact name lookup (case-insensitive). */
  get(name: string): SkillManifest | undefined {
    return this.manifests.get(this._normalise(name));
  }

  /** Fuzzy search over name + description. */
  search(query: string, limit = 10): SkillManifest[] {
    return SkillSearch.search(this.list(), query, { limit }).map((r) => r.manifest);
  }

  /** All loaded manifests, sorted alphabetically by name. */
  list(): SkillManifest[] {
    return [...this.manifests.values()].sort((a, b) =>
      a.name.localeCompare(b.name)
    );
  }

  /** Total number of loaded skills. */
  get size(): number {
    return this.manifests.size;
  }

  // ─── System Prompt ───────────────────────────────────────────────────────

  /**
   * Build the text block to inject into the agent's system prompt when
   * the named skill is active. Returns an empty string if not found.
   */
  getSystemPromptFor(skillName: string): string {
    const m = this.get(skillName);
    if (!m) return "";
    return buildSystemPromptBlock(m);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private _normalise(name: string): string {
    return name.toLowerCase().trim();
  }
}

// ─── System Prompt Block Builder ─────────────────────────────────────────────

export function buildSystemPromptBlock(manifest: SkillManifest): string {
  const lines: string[] = [
    `## Active Skill: ${manifest.name}`,
  ];

  if (manifest.description) {
    lines.push(`> ${manifest.description}`);
    lines.push("");
  }

  lines.push(manifest.content);

  return lines.join("\n");
}
