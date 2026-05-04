/**
 * SkillLoader — Discovers and loads SKILL.md files.
 *
 * Default search paths (in order):
 *   1. ~/.lyrie/skills/                        (Lyrie-native skills)
 *   2. ~/.openclaw/workspace/skills/           (OpenClaw compatibility — all 129 skills)
 *   3. ./skills/                               (project-local)
 *
 * Each SKILL.md may have optional YAML frontmatter between `---` delimiters.
 * Skills without frontmatter are still loaded; `name` defaults to the
 * directory name.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { homedir } from "node:os";
import type { SkillManifest } from "./skill-types";

// ─── YAML frontmatter parser (zero-dep) ──────────────────────────────────────

/**
 * Parse minimal YAML frontmatter. Supports scalar strings, arrays (- item),
 * and quoted values. Good enough for SKILL.md files — not a full YAML parser.
 */
function parseFrontmatter(raw: string): { meta: Record<string, unknown>; body: string } {
  const FM_RE = /^---\r?\n([\s\S]*?)\n---\r?\n?([\s\S]*)$/;
  const match = raw.match(FM_RE);
  if (!match) return { meta: {}, body: raw };

  const [, fmBlock, body] = match;
  const meta: Record<string, unknown> = {};
  let currentKey: string | null = null;
  let currentArray: string[] | null = null;

  for (const rawLine of fmBlock.split(/\r?\n/)) {
    const line = rawLine;

    // Array item
    if (line.match(/^\s+-\s+/)) {
      const val = line.replace(/^\s+-\s+/, "").trim().replace(/^["']|["']$/g, "");
      if (currentArray) currentArray.push(val);
      continue;
    }

    // Key: value
    const kvMatch = line.match(/^(\w[\w-]*)\s*:\s*(.*)?$/);
    if (kvMatch) {
      // Flush previous array
      if (currentKey && currentArray) meta[currentKey] = currentArray;

      currentKey = kvMatch[1].trim();
      const rawVal = (kvMatch[2] ?? "").trim();

      if (rawVal === "" || rawVal === null) {
        // Might be start of block array
        currentArray = [];
        meta[currentKey] = currentArray;
      } else if (rawVal.startsWith("[")) {
        // Inline array: [a, b, c]
        currentArray = null;
        const items = rawVal
          .replace(/^\[|\]$/g, "")
          .split(",")
          .map((s) => s.trim().replace(/^["']|["']$/g, ""))
          .filter(Boolean);
        meta[currentKey] = items;
      } else {
        currentArray = null;
        meta[currentKey] = rawVal.replace(/^["']|["']$/g, "");
      }
    }
  }

  // Flush trailing array
  if (currentKey && currentArray && !Array.isArray(meta[currentKey])) {
    meta[currentKey] = currentArray;
  }

  return { meta, body: body.trimStart() };
}

// ─── SkillLoader ─────────────────────────────────────────────────────────────

export class SkillLoader {
  // ─── Default search paths ───────────────────────────────────────────────

  static defaultPaths(): string[] {
    const home = homedir();
    return [
      join(home, ".lyrie", "skills"),
      join(home, ".openclaw", "workspace", "skills"), // OpenClaw compatibility
      join(process.cwd(), "skills"),
    ];
  }

  // ─── Discover ────────────────────────────────────────────────────────────

  /**
   * Walk `rootDir` recursively and load every SKILL.md found.
   * Non-existent directories are silently skipped.
   */
  async discover(rootDir: string): Promise<SkillManifest[]> {
    const manifests: SkillManifest[] = [];
    if (!existsSync(rootDir)) return manifests;

    const skillMdPaths = this._findSkillMdFiles(rootDir);
    for (const p of skillMdPaths) {
      try {
        const m = await this.load(p);
        manifests.push(m);
      } catch {
        // Skip unreadable / malformed files
      }
    }
    return manifests;
  }

  /**
   * Load a single SKILL.md file.
   */
  async load(skillPath: string): Promise<SkillManifest> {
    if (!existsSync(skillPath)) {
      throw new Error(`SKILL.md not found: ${skillPath}`);
    }

    const content = readFileSync(skillPath, "utf-8");
    const { meta, body } = parseFrontmatter(content);

    // Derive a fallback name from the containing directory
    const dirName = basename(dirname(skillPath));

    const manifest: SkillManifest = {
      name: (meta.name as string) ?? dirName,
      description: (meta.description as string) ?? undefined,
      version: (meta.version as string) ?? undefined,
      author: (meta.author as string) ?? undefined,
      tools: this._toStringArray(meta.tools),
      channels: this._toStringArray(meta.channels),
      triggers: this._toStringArray(meta.triggers),
      location: skillPath,
      content: body || content, // full content if no frontmatter, body otherwise
    };

    return manifest;
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private _findSkillMdFiles(dir: string): string[] {
    const results: string[] = [];

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return results;
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry);
      let stat;
      try {
        stat = statSync(fullPath);
      } catch {
        continue;
      }

      if (stat.isDirectory()) {
        // Look for SKILL.md directly inside this sub-directory
        const candidate = join(fullPath, "SKILL.md");
        if (existsSync(candidate)) {
          results.push(candidate);
        } else {
          // Recurse deeper (nested skill packs)
          results.push(...this._findSkillMdFiles(fullPath));
        }
      } else if (entry === "SKILL.md") {
        results.push(fullPath);
      }
    }

    return results;
  }

  private _toStringArray(val: unknown): string[] | undefined {
    if (!val) return undefined;
    if (Array.isArray(val)) return val.map(String).filter(Boolean);
    if (typeof val === "string") {
      const trimmed = val.trim();
      return trimmed ? [trimmed] : undefined;
    }
    return undefined;
  }
}
