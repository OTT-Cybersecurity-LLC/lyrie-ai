/**
 * Lyrie Agent — OpenClaw Memory Migration
 *
 * Reads `.md` files from ~/.openclaw/workspace/memory/ (and workspace root
 * workspace files: MEMORY.md, SOUL.md, AGENTS.md, USER.md, TOOLS.md),
 * extracts memory entries from markdown sections (headers + content), and
 * imports them into Lyrie's MemoryCore-compatible JSON structure with
 * appropriate domain tagging.
 *
 * Also processes ~/.openclaw/memory/*.json (structured memory entries).
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

import { existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync } from "fs";
import { join, basename, extname } from "path";
import { homedir } from "os";

// ─── Types ────────────────────────────────────────────────────────────────────

export type MemoryDomain = "cyber" | "seo" | "trading" | "code" | "general" | "identity" | "rules";
export type MemoryImportance = "critical" | "high" | "medium" | "low";
export type MemoryCategory = "fact" | "preference" | "rule" | "entity" | "identity";

export interface MemoryImportEntry {
  id: string;
  key: string;
  content: string;
  importance: MemoryImportance;
  category: MemoryCategory;
  domain: MemoryDomain;
  source: string;
  tags: string[];
  created_at: string;
}

export interface MemoryMigrationOptions {
  /** ~/.openclaw/workspace/memory/ */
  sourceDir: string;
  /** ~/.lyrie/memory.db or ~/.lyrie/memory/openclaw-import.json */
  targetDb: string;
  dryRun: boolean;
  verbose?: boolean;
}

export interface MemoryMigrationResult {
  success: boolean;
  entriesImported: number;
  filesProcessed: number;
  errors: string[];
  warnings: string[];
  entries: MemoryImportEntry[];
}

// ─── Domain inference ─────────────────────────────────────────────────────────

const DOMAIN_KEYWORDS: Record<MemoryDomain, string[]> = {
  cyber: ["security", "cyber", "shield", "vulnerability", "cve", "pentest", "threat", "malware", "attack", "exploit", "lyrie", "antivirus"],
  seo: ["seo", "keyword", "ranking", "backlink", "google", "search", "content", "traffic", "serp", "domain", "wordpress", "overthetopseo"],
  trading: ["trading", "bybit", "crypto", "bitcoin", "btc", "eth", "futures", "position", "polymarket", "price", "portfolio", "leverage"],
  code: ["code", "typescript", "javascript", "python", "bun", "node", "npm", "deploy", "git", "docker", "kubernetes", "api", "database", "sql"],
  identity: ["soul", "identity", "persona", "name", "who i am", "agents.md", "user.md", "soul.md"],
  rules: ["rule", "never", "always", "forbidden", "must", "mandatory", "hardest", "⛔"],
  general: [],
};

function inferDomain(text: string, source: string): MemoryDomain {
  const lower = (text + " " + source).toLowerCase();

  // Identity files always go to identity domain
  if (/soul\.md|identity\.md|agents\.md|user\.md/.test(lower)) {
    return "identity";
  }

  // Score each domain
  const scores: Record<MemoryDomain, number> = {
    cyber: 0, seo: 0, trading: 0, code: 0, identity: 0, rules: 0, general: 0,
  };

  for (const [domain, keywords] of Object.entries(DOMAIN_KEYWORDS) as [MemoryDomain, string[]][]) {
    for (const kw of keywords) {
      if (lower.includes(kw)) {
        scores[domain] += 1;
      }
    }
  }

  let best: MemoryDomain = "general";
  let bestScore = 0;
  for (const [domain, score] of Object.entries(scores) as [MemoryDomain, number][]) {
    if (score > bestScore) {
      bestScore = score;
      best = domain;
    }
  }

  return best;
}

function inferImportance(text: string, isSystemFile: boolean): MemoryImportance {
  const lower = text.toLowerCase();
  if (isSystemFile) return "critical";
  if (/⛔|never|forbidden|mandatory|hardest|critical/.test(lower)) return "critical";
  if (/important|key|must|always|required/.test(lower)) return "high";
  if (/note|remember|keep/.test(lower)) return "medium";
  return "low";
}

function inferCategory(text: string, source: string): MemoryCategory {
  const lower = (text + " " + source).toLowerCase();
  if (/soul\.md|identity\.md|persona/.test(lower)) return "identity";
  if (/rule|never|must|forbidden|mandatory/.test(lower)) return "rule";
  if (/preference|prefer|like|dislike|style/.test(lower)) return "preference";
  if (/\bperson\b|name:|email:|company:|ceo|founder/.test(lower)) return "entity";
  return "fact";
}

// ─── ID generation ────────────────────────────────────────────────────────────

function generateId(prefix: string, idx: number): string {
  return `lyrie_oc_${prefix}_${Date.now().toString(36)}_${idx}`;
}

// ─── Markdown section extractor ───────────────────────────────────────────────

interface MarkdownSection {
  heading: string;
  content: string;
  depth: number;
}

export function extractMarkdownSections(markdown: string): MarkdownSection[] {
  const lines = markdown.split("\n");
  const sections: MarkdownSection[] = [];
  let currentHeading = "";
  let currentDepth = 0;
  let currentLines: string[] = [];

  function flush() {
    const content = currentLines.join("\n").trim();
    if (content || currentHeading) {
      sections.push({
        heading: currentHeading,
        content,
        depth: currentDepth,
      });
    }
    currentLines = [];
  }

  for (const line of lines) {
    const headingMatch = line.match(/^(#{1,6})\s+(.+)/);
    if (headingMatch) {
      flush();
      currentDepth = headingMatch[1].length;
      currentHeading = headingMatch[2].trim();
    } else {
      currentLines.push(line);
    }
  }
  flush();

  return sections.filter((s) => s.heading || s.content.trim().length > 20);
}

// ─── Main migration function ──────────────────────────────────────────────────

export async function migrateOpenClawMemory(
  options: MemoryMigrationOptions
): Promise<MemoryMigrationResult> {
  const { sourceDir, targetDb, dryRun, verbose = false } = options;

  const entries: MemoryImportEntry[] = [];
  const errors: string[] = [];
  const warnings: string[] = [];
  let filesProcessed = 0;
  let entryIdx = 0;

  function log(msg: string) {
    if (verbose) console.log(`  [memory] ${msg}`);
  }

  // ── 1. Workspace root files (SOUL.md, AGENTS.md, MEMORY.md, USER.md, TOOLS.md) ──

  const ocWorkspace = join(homedir(), ".openclaw", "workspace");
  const SYSTEM_FILES = ["SOUL.md", "AGENTS.md", "MEMORY.md", "USER.md", "TOOLS.md", "IDENTITY.md"];

  for (const filename of SYSTEM_FILES) {
    const filePath = join(ocWorkspace, filename);
    if (!existsSync(filePath)) continue;

    try {
      const content = readFileSync(filePath, "utf8");
      filesProcessed++;

      // Extract sections from system files
      const sections = extractMarkdownSections(content);
      for (const section of sections) {
        const text = section.heading
          ? `# ${section.heading}\n\n${section.content}`
          : section.content;

        if (text.trim().length < 10) continue;

        entries.push({
          id: generateId("sys", entryIdx++),
          key: `openclaw:${filename}:${section.heading || "root"}`,
          content: text.trim(),
          importance: "critical",
          category: inferCategory(text, filename),
          domain: inferDomain(text, filename),
          source: `openclaw:workspace/${filename}`,
          tags: ["openclaw", "system", filename.toLowerCase().replace(".md", "")],
          created_at: new Date().toISOString(),
        });
      }

      log(`${filename}: ${sections.length} sections`);
    } catch (err: any) {
      errors.push(`Failed to read ${filename}: ${err?.message}`);
    }
  }

  // ── 2. Memory directory .md files ─────────────────────────────────────────

  if (existsSync(sourceDir)) {
    const files = readdirSync(sourceDir).filter(
      (f) => extname(f) === ".md" && !f.startsWith(".")
    );

    for (const file of files) {
      const filePath = join(sourceDir, file);
      try {
        const content = readFileSync(filePath, "utf8");
        filesProcessed++;

        const sections = extractMarkdownSections(content);
        const isSystemFile = /compacted|learnings|soul|identity|agents|user/.test(file.toLowerCase());

        for (const section of sections) {
          const text = section.heading
            ? `# ${section.heading}\n\n${section.content}`
            : section.content;

          if (text.trim().length < 20) continue;

          entries.push({
            id: generateId("md", entryIdx++),
            key: `openclaw:memory:${file}:${section.heading || "root"}`,
            content: text.trim(),
            importance: inferImportance(text, isSystemFile),
            category: inferCategory(text, file),
            domain: inferDomain(text, file),
            source: `openclaw:memory/${file}`,
            tags: ["openclaw", "memory", basename(file, ".md")],
            created_at: new Date().toISOString(),
          });
        }

        log(`${file}: ${sections.length} sections → ${entries.length} total`);
      } catch (err: any) {
        errors.push(`Failed to read memory/${file}: ${err?.message}`);
      }
    }
  } else {
    warnings.push(`Memory directory not found: ${sourceDir}`);
  }

  // ── 3. Structured JSON memory entries (~/.openclaw/memory/*.json) ──────────

  const ocMemDir = join(homedir(), ".openclaw", "memory");
  if (existsSync(ocMemDir)) {
    const jsonFiles = readdirSync(ocMemDir).filter((f) => extname(f) === ".json");

    for (const file of jsonFiles) {
      const filePath = join(ocMemDir, file);
      try {
        const raw = readFileSync(filePath, "utf8");
        const parsed = JSON.parse(raw);
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        filesProcessed++;

        for (const item of arr) {
          if (!item || typeof item !== "object") continue;
          const text = String(item.text ?? item.content ?? item.value ?? "").trim();
          if (text.length < 10) continue;

          entries.push({
            id: String(item.id ?? generateId("json", entryIdx++)),
            key: `openclaw:memory.json:${file}:${entryIdx}`,
            content: text,
            importance: mapImportance(item.importance),
            category: mapCategory(item.category),
            domain: inferDomain(text, file),
            source: `openclaw:memory/${file}`,
            tags: Array.isArray(item.tags) ? item.tags : ["openclaw", "memory"],
            created_at: String(item.createdAt ?? item.created_at ?? new Date().toISOString()),
          });
          entryIdx++;
        }

        log(`${file}: ${arr.length} JSON entries`);
      } catch {
        // Skip malformed JSON silently
      }
    }
  }

  // ── 4. Write output ──────────────────────────────────────────────────────────

  if (!dryRun && entries.length > 0) {
    try {
      // Ensure parent directory exists
      const targetDir = targetDb.endsWith(".json")
        ? join(targetDb, "..")
        : targetDb;
      mkdirSync(targetDir, { recursive: true });

      if (targetDb.endsWith(".json")) {
        writeFileSync(targetDb, JSON.stringify(entries, null, 2) + "\n", "utf8");
      } else {
        // Write as JSON next to the target path for now (SQLite requires bun:sqlite)
        const jsonPath = targetDb.replace(/\.db$/, "-import.json");
        writeFileSync(jsonPath, JSON.stringify(entries, null, 2) + "\n", "utf8");
      }
    } catch (err: any) {
      errors.push(`Failed to write memory output: ${err?.message}`);
    }
  }

  return {
    success: errors.length === 0,
    entriesImported: entries.length,
    filesProcessed,
    errors,
    warnings,
    entries,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function mapImportance(raw: unknown): MemoryImportance {
  const v = String(raw ?? "").toLowerCase();
  if (v === "critical" || Number(raw) >= 1.0) return "critical";
  if (v === "high" || Number(raw) >= 0.85) return "high";
  if (v === "medium" || Number(raw) >= 0.5) return "medium";
  return "low";
}

function mapCategory(raw: unknown): MemoryCategory {
  const v = String(raw ?? "fact").toLowerCase();
  if (v === "preference") return "preference";
  if (v === "rule") return "rule";
  if (v === "entity") return "entity";
  if (v === "identity") return "identity";
  return "fact";
}
