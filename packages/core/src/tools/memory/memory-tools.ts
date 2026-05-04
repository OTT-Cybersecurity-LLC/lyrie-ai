/**
 * memory_store / memory_recall / memory_forget — Lyrie v1.2 built-in tools.
 *
 * Advanced memory system with:
 *   ✅ Auto-categorization — infers category from content
 *   ✅ Importance scoring  — auto-scores 0-1 from keywords
 *   ✅ Deduplication       — checks for similar entries before storing
 *   ✅ TTL / expiry        — optional expiresAt field
 *
 * Backed by SQLite FTS5 via MemoryCore.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { Database } from "bun:sqlite";
import { existsSync, mkdirSync } from "fs";
import { join } from "path";
import type { Tool } from "../tool-executor";

// ─── Types ───────────────────────────────────────────────────────────────────

export type MemoryCategory =
  | "preference"
  | "fact"
  | "decision"
  | "entity"
  | "rule"
  | "other";

export interface MemoryRecord {
  id: string;
  text: string;
  category: MemoryCategory;
  importance: number; // 0-1
  createdAt: string;
  expiresAt?: string;
}

export interface StoreOptions {
  category?: MemoryCategory;
  importance?: number;
  ttlDays?: number;
}

export interface RecallOptions {
  limit?: number;
  category?: MemoryCategory;
  minImportance?: number;
}

export interface ForgetOptions {
  memoryId?: string;
  query?: string;
}

// ─── Auto-categorization ─────────────────────────────────────────────────────

const CATEGORY_PATTERNS: Array<{ pattern: RegExp; category: MemoryCategory }> = [
  { pattern: /\b(prefer|like|hate|love|want|dislike|favorite|favourite|always use|never use)\b/i, category: "preference" },
  { pattern: /\b(decided|decision|choose|chose|going with|will use|selected)\b/i, category: "decision" },
  // Note: emoji chars are non-word — no \b around them
  { pattern: /[⛔🔴]|\b(rule:|must|never|always|forbidden|required|mandatory)\b/i, category: "rule" },
  { pattern: /\b(is a|is an|are a|are an|named|called|known as|refers to)\b/i, category: "entity" },
];

export function inferCategory(text: string): MemoryCategory {
  for (const { pattern, category } of CATEGORY_PATTERNS) {
    if (pattern.test(text)) return category;
  }
  return "fact";
}

// ─── Importance scoring ──────────────────────────────────────────────────────

const IMPORTANCE_RULES: Array<{ pattern: RegExp; score: number }> = [
  // Emoji are non-word — no \b; 'critical'/'never' etc. keep word boundaries
  { pattern: /[⛔🔴]|\b(critical|never|forbidden|hardest rule|above everything)\b/i, score: 1.0 },
  // 'rule:' ends in colon (non-word) — match with lookahead instead of \b
  { pattern: /rule:|\b(must not|must never|always must|mandatory|required)\b/i, score: 0.9 },
  { pattern: /\b(important|significant|key|essential|primary|core)\b/i, score: 0.8 },
  { pattern: /\b(prefer|decision|decided|selected|choose|chose)\b/i, score: 0.7 },
  { pattern: /\b(note|remember|consider|should|recommended)\b/i, score: 0.6 },
];

export function scoreImportance(text: string): number {
  for (const { pattern, score } of IMPORTANCE_RULES) {
    if (pattern.test(text)) return score;
  }
  return 0.5; // neutral fact default
}

// ─── ID generation ───────────────────────────────────────────────────────────

function generateId(): string {
  return `lm_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

// ─── Similarity check for dedup ──────────────────────────────────────────────

/**
 * Simple Jaccard-like word overlap.  If the overlap ratio of words between
 * two texts exceeds the threshold (default 0.7), they're considered duplicates.
 */
export function textSimilarity(a: string, b: string, threshold = 0.55): boolean {
  const words = (s: string) =>
    new Set(s.toLowerCase().replace(/[^\w\s]/g, "").split(/\s+/).filter(Boolean));
  const wa = words(a);
  const wb = words(b);
  const intersection = [...wa].filter((w) => wb.has(w)).length;
  const union = new Set([...wa, ...wb]).size;
  if (union === 0) return false;
  return intersection / union >= threshold;
}

// ─── SQLite backend ──────────────────────────────────────────────────────────

// Standalone FTS5 table (no content= link) — triggers keep it in sync with the
// main table via rowid. This approach avoids the content-table pitfall where
// FTS5 can't read back deleted rows during the ad trigger.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS lyrie_memories (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'fact',
    importance REAL NOT NULL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    expires_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_lm_category ON lyrie_memories(category);
  CREATE INDEX IF NOT EXISTS idx_lm_importance ON lyrie_memories(importance);
  CREATE VIRTUAL TABLE IF NOT EXISTS lyrie_memories_fts USING fts5(
    text,
    tokenize="unicode61"
  );
  CREATE TRIGGER IF NOT EXISTS lyrie_memories_ai
    AFTER INSERT ON lyrie_memories BEGIN
      INSERT INTO lyrie_memories_fts(rowid, text) VALUES (new.rowid, new.text);
    END;
  CREATE TRIGGER IF NOT EXISTS lyrie_memories_ad
    AFTER DELETE ON lyrie_memories BEGIN
      DELETE FROM lyrie_memories_fts WHERE rowid = old.rowid;
    END;
  CREATE TRIGGER IF NOT EXISTS lyrie_memories_au
    AFTER UPDATE OF text ON lyrie_memories BEGIN
      DELETE FROM lyrie_memories_fts WHERE rowid = old.rowid;
      INSERT INTO lyrie_memories_fts(rowid, text) VALUES (new.rowid, new.text);
    END;
`;

export class MemoryStore {
  private db: Database;
  private initialized = false;

  constructor(dbPath?: string) {
    const dir = dbPath
      ? (dbPath.includes("/") ? dbPath.replace(/\/[^/]+$/, "") : ".")
      : join(process.env.HOME || "~", ".lyrie", "memory");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const path = dbPath || join(dir, "lyrie-memory.db");
    this.db = new Database(path, { create: true });
    this.init();
  }

  private init(): void {
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    try {
      this.db.exec(SCHEMA);
    } catch (e) {
      // FTS5 not available — create plain table only
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS lyrie_memories (
          id TEXT PRIMARY KEY,
          text TEXT NOT NULL,
          category TEXT NOT NULL DEFAULT 'fact',
          importance REAL NOT NULL DEFAULT 0.5,
          created_at TEXT NOT NULL,
          expires_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_lm_category ON lyrie_memories(category);
        CREATE INDEX IF NOT EXISTS idx_lm_importance ON lyrie_memories(importance);
      `);
    }
    this.initialized = true;
  }

  /** Store a memory. Returns id, isNew (false = updated existing). */
  store(text: string, opts: StoreOptions = {}): { id: string; isNew: boolean } {
    const category = opts.category ?? inferCategory(text);
    const importance = opts.importance ?? scoreImportance(text);
    const now = nowISO();
    const expiresAt = opts.ttlDays
      ? new Date(Date.now() + opts.ttlDays * 86_400_000).toISOString()
      : null;

    // Dedup: check if a similar memory already exists
    const existing = this.db
      .query("SELECT id, text FROM lyrie_memories WHERE category = ?")
      .all(category) as Array<{ id: string; text: string }>;

    for (const row of existing) {
      if (textSimilarity(row.text, text)) {
        // Update existing instead of creating duplicate
        this.db
          .prepare(
            "UPDATE lyrie_memories SET text=?, importance=?, created_at=?, expires_at=? WHERE id=?"
          )
          .run(text, importance, now, expiresAt, row.id);
        return { id: row.id, isNew: false };
      }
    }

    // Insert new
    const id = generateId();
    this.db
      .prepare(
        "INSERT INTO lyrie_memories (id, text, category, importance, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .run(id, text, category, importance, now, expiresAt);

    return { id, isNew: true };
  }

  /** FTS5-powered search with LIKE fallback. Returns ranked results. */
  recall(query: string, opts: RecallOptions = {}): MemoryRecord[] {
    const limit = opts.limit ?? 5;
    const now = nowISO();

    let rows: any[];
    try {
      // FTS5 subquery approach — rowid-matched, avoids content-table pitfalls
      let sql = `
        SELECT m.* FROM lyrie_memories m
        WHERE m.rowid IN (
          SELECT rowid FROM lyrie_memories_fts WHERE text MATCH ?
        )
          AND (m.expires_at IS NULL OR m.expires_at > ?)
      `;
      const params: any[] = [query, now];
      if (opts.category) { sql += " AND m.category = ?"; params.push(opts.category); }
      if (opts.minImportance !== undefined) { sql += " AND m.importance >= ?"; params.push(opts.minImportance); }
      sql += " ORDER BY m.importance DESC LIMIT ?";
      params.push(limit);
      rows = this.db.query(sql).all(...params) as any[];
    } catch {
      // FTS5 not available — LIKE fallback
      let sql = `
        SELECT * FROM lyrie_memories
        WHERE text LIKE ?
          AND (expires_at IS NULL OR expires_at > ?)
      `;
      const params: any[] = [`%${query}%`, now];
      if (opts.category) { sql += " AND category = ?"; params.push(opts.category); }
      if (opts.minImportance !== undefined) { sql += " AND importance >= ?"; params.push(opts.minImportance); }
      sql += " ORDER BY importance DESC LIMIT ?";
      params.push(limit);
      rows = this.db.query(sql).all(...params) as any[];
    }

    return rows.map((r) => ({
      id: r.id,
      text: r.text,
      category: r.category as MemoryCategory,
      importance: r.importance,
      createdAt: r.created_at,
      expiresAt: r.expires_at ?? undefined,
    }));
  }

  /**
   * Delete by id or by query (removes all matching).
   *
   * NOTE: We check existence before DELETE rather than relying on `result.changes`
   * because FTS5 delete triggers inflate `changes()` with shadow-table operations.
   */
  forget(opts: ForgetOptions): { deleted: number } {
    if (opts.memoryId) {
      const existing = this.db
        .query("SELECT id FROM lyrie_memories WHERE id = ?")
        .get(opts.memoryId);
      if (!existing) return { deleted: 0 };
      this.db.prepare("DELETE FROM lyrie_memories WHERE id = ?").run(opts.memoryId);
      return { deleted: 1 };
    }

    if (opts.query) {
      // Recall matching ids, then delete each by id (also avoids changes() inflation)
      const matches = this.recall(opts.query, { limit: 100 });
      if (matches.length === 0) return { deleted: 0 };
      let deleted = 0;
      for (const m of matches) {
        const exists = this.db.query("SELECT id FROM lyrie_memories WHERE id = ?").get(m.id);
        if (exists) {
          this.db.prepare("DELETE FROM lyrie_memories WHERE id = ?").run(m.id);
          deleted++;
        }
      }
      return { deleted };
    }

    return { deleted: 0 };
  }

  /** Mark expired memories (for inspection/audit). */
  countExpired(): number {
    const now = nowISO();
    const row = this.db
      .query("SELECT COUNT(*) as c FROM lyrie_memories WHERE expires_at IS NOT NULL AND expires_at <= ?")
      .get(now) as any;
    return row?.c ?? 0;
  }

  close(): void {
    this.db.close();
  }
}

// ─── Singleton store ─────────────────────────────────────────────────────────

let _store: MemoryStore | null = null;

export function getMemoryStore(): MemoryStore {
  if (!_store) _store = new MemoryStore();
  return _store;
}

/** For testing: inject a custom store (in-memory DB). */
export function setMemoryStore(store: MemoryStore): void {
  _store = store;
}

// ─── Tool: memory_store ──────────────────────────────────────────────────────

export const memoryStoreTool: Tool = {
  name: "memory_store",
  description:
    "Save important information to long-term memory. Auto-categorizes and scores importance. Deduplicates similar entries automatically.",
  parameters: {
    text: {
      type: "string",
      description: "The information to remember",
      required: true,
    },
    category: {
      type: "string",
      description:
        'Category hint (auto-detected if omitted): preference | fact | decision | entity | rule | other',
      enum: ["preference", "fact", "decision", "entity", "rule", "other"],
    },
    importance: {
      type: "number",
      description: "Importance 0-1 (auto-scored if omitted)",
    },
    ttlDays: {
      type: "number",
      description: "Auto-expire after N days (optional)",
    },
  },
  risk: "safe",
  execute: async (args) => {
    try {
      const store = getMemoryStore();
      const { id, isNew } = store.store(args.text, {
        category: args.category as MemoryCategory | undefined,
        importance: args.importance,
        ttlDays: args.ttlDays,
      });
      return {
        success: true,
        output: isNew
          ? `Memory stored. id=${id}`
          : `Similar memory updated. id=${id}`,
        metadata: { id, isNew },
      };
    } catch (err: any) {
      return { success: false, output: "", error: `memory_store failed: ${err.message}` };
    }
  },
};

// ─── Tool: memory_recall ─────────────────────────────────────────────────────

export const memoryRecallTool: Tool = {
  name: "memory_recall",
  description:
    "Search long-term memory by query. Returns ranked results, newest and highest-importance first.",
  parameters: {
    query: {
      type: "string",
      description: "Search query",
      required: true,
    },
    limit: {
      type: "number",
      description: "Max results (default: 5)",
      default: 5,
    },
    category: {
      type: "string",
      description: "Filter by category",
      enum: ["preference", "fact", "decision", "entity", "rule", "other"],
    },
    minImportance: {
      type: "number",
      description: "Only return memories with importance >= this value (0-1)",
    },
  },
  risk: "safe",
  execute: async (args) => {
    try {
      const store = getMemoryStore();
      const results = store.recall(args.query, {
        limit: args.limit,
        category: args.category as MemoryCategory | undefined,
        minImportance: args.minImportance,
      });

      if (results.length === 0) {
        return {
          success: true,
          output: `No memories found for: "${args.query}"`,
          metadata: { count: 0 },
        };
      }

      const formatted = results
        .map(
          (r, i) =>
            `${i + 1}. [${r.category}] (importance=${r.importance.toFixed(2)}) ${r.text}` +
            (r.expiresAt ? ` [expires: ${r.expiresAt}]` : "")
        )
        .join("\n");

      return {
        success: true,
        output: formatted,
        metadata: { count: results.length, results },
      };
    } catch (err: any) {
      return { success: false, output: "", error: `memory_recall failed: ${err.message}` };
    }
  },
};

// ─── Tool: memory_forget ─────────────────────────────────────────────────────

export const memoryForgetTool: Tool = {
  name: "memory_forget",
  description:
    "Delete a specific memory by ID, or delete all memories matching a search query.",
  parameters: {
    memoryId: {
      type: "string",
      description: "Specific memory ID to delete",
    },
    query: {
      type: "string",
      description: "Delete all memories matching this query",
    },
  },
  risk: "moderate",
  execute: async (args) => {
    if (!args.memoryId && !args.query) {
      return {
        success: false,
        output: "",
        error: "Provide either memoryId or query",
      };
    }
    try {
      const store = getMemoryStore();
      const { deleted } = store.forget({
        memoryId: args.memoryId,
        query: args.query,
      });
      return {
        success: true,
        output: deleted > 0 ? `Deleted ${deleted} memory(ies).` : "No matching memories found.",
        metadata: { deleted },
      };
    } catch (err: any) {
      return { success: false, output: "", error: `memory_forget failed: ${err.message}` };
    }
  },
};
