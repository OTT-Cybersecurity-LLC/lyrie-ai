/**
 * Lyrie Tools Catalog — registry, search, and recommend engine.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License.
 */

import { execSync } from "node:child_process";

import { BUILTIN_TOOLS } from "./builtin";
import { CATEGORIES, CATEGORY_BY_ID } from "./categories";
import {
  CATALOG_SIGNATURE,
  CATALOG_VERSION,
  type CatalogStats,
  type CategoryDescriptor,
  type InstallStatus,
  type ToolCategory,
  type ToolDefinition,
  type ToolTag,
} from "./types";

// ─── Catalog ────────────────────────────────────────────────────────────────

export class ToolsCatalog {
  private tools: Map<string, ToolDefinition>;
  private byCategory: Map<ToolCategory, ToolDefinition[]>;
  private byTag: Map<ToolTag, ToolDefinition[]>;

  readonly version = CATALOG_VERSION;
  readonly signature = CATALOG_SIGNATURE;

  constructor(tools: ReadonlyArray<ToolDefinition> = BUILTIN_TOOLS) {
    this.tools = new Map();
    this.byCategory = new Map();
    this.byTag = new Map();

    for (const tool of tools) {
      this.register(tool);
    }
  }

  // ── Registration ────────────────────────────────────────────────────────

  /** Register or replace a tool by id. Idempotent. */
  register(tool: ToolDefinition): void {
    if (this.tools.has(tool.id)) {
      this.unregister(tool.id);
    }
    this.tools.set(tool.id, tool);

    const cat = this.byCategory.get(tool.category) ?? [];
    cat.push(tool);
    this.byCategory.set(tool.category, cat);

    for (const tag of tool.tags) {
      const list = this.byTag.get(tag) ?? [];
      list.push(tool);
      this.byTag.set(tag, list);
    }
  }

  /** Remove a tool by id. */
  unregister(id: string): boolean {
    const tool = this.tools.get(id);
    if (!tool) return false;

    this.tools.delete(id);
    const cat = this.byCategory.get(tool.category);
    if (cat) {
      const next = cat.filter((t) => t.id !== id);
      if (next.length === 0) this.byCategory.delete(tool.category);
      else this.byCategory.set(tool.category, next);
    }
    for (const tag of tool.tags) {
      const list = this.byTag.get(tag);
      if (!list) continue;
      const next = list.filter((t) => t.id !== id);
      if (next.length === 0) this.byTag.delete(tag);
      else this.byTag.set(tag, next);
    }
    return true;
  }

  // ── Lookup ──────────────────────────────────────────────────────────────

  /** Get a single tool by id. */
  get(id: string): ToolDefinition | undefined {
    return this.tools.get(id);
  }

  /** All registered tools. */
  list(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  /** All categories Lyrie ships, in display order. */
  categories(): ReadonlyArray<CategoryDescriptor> {
    return CATEGORIES;
  }

  /** Tools in one category. */
  byCategoryList(category: ToolCategory): ToolDefinition[] {
    return [...(this.byCategory.get(category) ?? [])];
  }

  /** Tools matching a tag. */
  byTagList(tag: ToolTag): ToolDefinition[] {
    return [...(this.byTag.get(tag) ?? [])];
  }

  // ── Search + Recommend ────────────────────────────────────────────────────

  /** Free-text search across name + id + description + intents. */
  search(query: string): ToolDefinition[] {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const results: Array<{ tool: ToolDefinition; score: number }> = [];

    for (const tool of this.tools.values()) {
      let score = 0;
      if (tool.id.toLowerCase().includes(q)) score += 10;
      if (tool.name.toLowerCase().includes(q)) score += 8;
      if (tool.description.toLowerCase().includes(q)) score += 4;
      for (const intent of tool.intents) {
        if (intent.toLowerCase().includes(q)) score += 6;
      }
      for (const tag of tool.tags) {
        if (tag.toLowerCase().includes(q)) score += 3;
      }
      if (score > 0) results.push({ tool, score });
    }

    results.sort((a, b) => b.score - a.score);
    return results.map((r) => r.tool);
  }

  /**
   * Recommend tools by natural-language intent. Lyrie's `r` command.
   *
   * Tokenises the input, then scores tools by:
   *   - Direct intent overlap (highest signal)
   *   - Tag overlap
   *   - Category-name overlap
   *   - Tool-name overlap
   *
   * Pure heuristic — Lyrie's agent layer can layer LLM ranking on top.
   */
  recommend(intent: string, limit = 8): ToolDefinition[] {
    const text = intent.trim().toLowerCase();
    if (!text) return [];

    const tokens = tokenize(text);
    if (tokens.length === 0) return [];

    const tokenSet = new Set(tokens);
    const phraseHints = expandPhraseHints(text);

    const results: Array<{ tool: ToolDefinition; score: number }> = [];

    for (const tool of this.tools.values()) {
      let score = 0;

      // Intent strings — strongest signal
      for (const i of tool.intents) {
        const il = i.toLowerCase();
        if (text.includes(il) || il.includes(text)) {
          score += 12;
          continue;
        }
        const intentTokens = tokenize(il);
        const overlap = intentTokens.filter((t) => tokenSet.has(t)).length;
        if (overlap > 0) score += overlap * 4;
      }

      // Phrase hints
      for (const hint of phraseHints) {
        for (const i of tool.intents) {
          if (i.toLowerCase().includes(hint)) score += 6;
        }
        if (tool.description.toLowerCase().includes(hint)) score += 3;
        if (tool.name.toLowerCase().includes(hint)) score += 4;
      }

      // Tag overlap
      for (const tag of tool.tags) {
        if (tokenSet.has(tag)) score += 5;
      }

      // Category overlap
      const cat = CATEGORY_BY_ID.get(tool.category);
      if (cat) {
        for (const word of tokenize(cat.title)) {
          if (tokenSet.has(word)) score += 3;
        }
      }

      // Tool name overlap
      for (const word of tokenize(tool.name)) {
        if (tokenSet.has(word)) score += 4;
      }

      if (score > 0) results.push({ tool, score });
    }

    results.sort((a, b) => b.score - a.score);
    return results.slice(0, limit).map((r) => r.tool);
  }

  // ── Install detection ───────────────────────────────────────────────────

  /** Synchronous install detection — fast, used by stats / list views. */
  isInstalled(tool: ToolDefinition): InstallStatus {
    const cmd = tool.install.detect;
    if (!cmd) return { installed: false, reason: "no detector configured" };

    try {
      const which = process.platform === "win32" ? "where" : "which";
      const path = execSync(`${which} ${cmd}`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 2_000,
      }).trim();

      if (!path) return { installed: false };

      let version: string | undefined;
      if (tool.install.versionFlag) {
        try {
          version = execSync(`${cmd} ${tool.install.versionFlag}`, {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
            timeout: 4_000,
          })
            .split("\n")[0]
            ?.trim()
            .slice(0, 120);
        } catch {
          /* ignore */
        }
      }
      return { installed: true, detectedPath: path, version };
    } catch {
      return { installed: false };
    }
  }

  /** Aggregated catalog stats — totals, per-category, per-tag, install count. */
  stats(): CatalogStats {
    const byCategory = Object.fromEntries(
      CATEGORIES.map((c) => [c.id, this.byCategoryList(c.id).length] as const),
    ) as Record<ToolCategory, number>;

    const byTag: Record<string, number> = {};
    for (const [tag, tools] of this.byTag.entries()) {
      byTag[tag] = tools.length;
    }

    let installed = 0;
    for (const tool of this.tools.values()) {
      if (this.isInstalled(tool).installed) installed++;
    }

    return {
      total: this.tools.size,
      byCategory,
      byTag: byTag as Record<ToolTag, number>,
      installed,
      missing: this.tools.size - installed,
    };
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

const STOP_WORDS = new Set([
  "a", "an", "and", "or", "the", "i", "want", "to", "for", "of", "on", "in",
  "with", "my", "your", "is", "are", "do", "does", "can", "would", "could",
  "scan", "find",
]);

function tokenize(s: string): string[] {
  return s
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s]+/gu, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 2 && !STOP_WORDS.has(t));
}

const PHRASE_HINTS: ReadonlyArray<readonly [RegExp, ReadonlyArray<string>]> = [
  [/(network|host|port).*(scan|map|discover)/, ["network", "port", "scan"]],
  [/sub\s*domain/, ["subdomain"]],
  [/sql\s*injection|sqli/, ["sql"]],
  [/cross.?site\s*scripting|xss/, ["xss"]],
  [/active\s*directory|kerberos|ad\b/, ["ad", "kerberos"]],
  [/(active|cloud)\s*direct/, ["cloud"]],
  [/aws|s3|ec2|iam/, ["cloud", "aws"]],
  [/azure|gcp|google\s*cloud/, ["cloud"]],
  [/k8s|kubernetes|container/, ["container", "k8s"]],
  [/mobile|android|ios|apk/, ["mobile"]],
  [/secret|credential|token|api[_-]?key/, ["secrets"]],
  [/memory\s*dump|forensic/, ["forensics"]],
  [/decompile|reverse\s*engineer/, ["rev-eng"]],
  [/password|hash\s*crack/, ["password"]],
  [/ssl|tls|certificate/, ["ssl"]],
  [/proxy|intercept/, ["proxy"]],
  [/fuzz|directory\s*discover/, ["fuzz"]],
];

function expandPhraseHints(text: string): string[] {
  const out: string[] = [];
  for (const [rx, hints] of PHRASE_HINTS) {
    if (rx.test(text)) out.push(...hints);
  }
  return out;
}
