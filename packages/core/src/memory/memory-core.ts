/**
 * MemoryCore — Persistent, self-healing memory system for Lyrie Agent.
 *
 * Architecture:
 * - SQLite via bun:sqlite for structured, durable storage
 * - Tables: conversations, memories, rules, projects, entities
 * - Real keyword + fuzzy search (vector search ready to plug in later)
 * - Hourly auto-backup to archive directory
 * - Self-healing: detects and repairs corrupted database
 * - Import from MASTER-MEMORY.md into SQLite
 *
 * © OTT Cybersecurity LLC — Production quality.
 */

import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, copyFileSync, statSync } from "fs";
import { join, basename } from "path";

// ─── Types ───────────────────────────────────────────────────────────────────

export type Importance = "critical" | "high" | "medium" | "low";
export type Source = "user" | "system" | "agent" | "recovered" | "imported";

export interface MemoryEntry {
  id: string;
  key: string;
  content: string;
  importance: Importance;
  source: Source;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface ConversationMessage {
  id: number;
  user_id: string;
  role: "user" | "assistant" | "system";
  content: string;
  channel: string;
  timestamp: string;
}

export interface RuleEntry {
  id: number;
  rule: string;
  source: Source;
  active: boolean;
  created_at: string;
}

export interface ProjectEntry {
  id: number;
  name: string;
  description: string;
  status: string;
  metadata: string;
  created_at: string;
  updated_at: string;
}

export interface EntityEntry {
  id: number;
  name: string;
  type: string;
  data: string;
  created_at: string;
  updated_at: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateId(): string {
  return `lyrie_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

/** Simple fuzzy match: all query words must appear somewhere in the text. */
function fuzzyMatch(text: string, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const lower = text.toLowerCase();
  return words.every((w) => lower.includes(w));
}

/** Score a memory result for ranking. Higher = better match. */
function scoreResult(entry: { key: string; content: string; importance: string; tags?: string }, query: string): number {
  const importanceWeight: Record<string, number> = { critical: 40, high: 20, medium: 10, low: 5 };
  const q = query.toLowerCase();
  let score = importanceWeight[entry.importance] || 5;

  // Exact key match bonus
  if (entry.key.toLowerCase() === q) score += 100;
  // Key contains query
  else if (entry.key.toLowerCase().includes(q)) score += 50;
  // Content contains query
  if (entry.content.toLowerCase().includes(q)) score += 20;
  // Tag match
  if (entry.tags && entry.tags.toLowerCase().includes(q)) score += 15;

  return score;
}

// ─── Schema ──────────────────────────────────────────────────────────────────

const SCHEMA_VERSION = 1;

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
  );

  CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    content TEXT NOT NULL,
    importance TEXT NOT NULL DEFAULT 'medium',
    source TEXT NOT NULL DEFAULT 'user',
    tags TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    channel TEXT NOT NULL DEFAULT 'default',
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL DEFAULT 'user',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    data TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_memories_key ON memories(key);
  CREATE INDEX IF NOT EXISTS idx_memories_importance ON memories(importance);
  CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, channel);
  CREATE INDEX IF NOT EXISTS idx_conversations_ts ON conversations(timestamp);
  CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);
  CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
`;

// ─── MemoryCore ──────────────────────────────────────────────────────────────

export class MemoryCore {
  private basePath: string;
  private dbPath: string;
  private archivePath: string;
  private db!: Database;
  private initialized = false;
  private backupIntervalId: ReturnType<typeof setInterval> | null = null;

  constructor(basePath?: string) {
    this.basePath = basePath || join(process.env.HOME || "~", ".lyrie", "memory");
    this.dbPath = join(this.basePath, "lyrie-memory.db");
    this.archivePath = join(this.basePath, "archive");
  }

  // ─── Lifecycle ───────────────────────────────────────────────────────────

  async initialize(): Promise<void> {
    // Ensure directories
    for (const dir of [this.basePath, this.archivePath]) {
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    }

    // Open (or create) SQLite database
    this.db = this.openDatabase();

    // Run self-healing check
    await this.heal();

    // Start hourly auto-backup
    this.startAutoBackup();

    this.initialized = true;

    const memCount = this.db.query("SELECT COUNT(*) as c FROM memories").get() as any;
    const convCount = this.db.query("SELECT COUNT(*) as c FROM conversations").get() as any;
    const ruleCount = this.db.query("SELECT COUNT(*) as c FROM rules WHERE active = 1").get() as any;

    console.log(`   → Memory initialized (SQLite): ${memCount.c} memories, ${convCount.c} messages, ${ruleCount.c} rules`);
    console.log(`   → Self-healing: active`);
    console.log(`   → Auto-backup: every 1h → ${this.archivePath}`);
  }

  /** Graceful shutdown. */
  async shutdown(): Promise<void> {
    if (this.backupIntervalId) {
      clearInterval(this.backupIntervalId);
      this.backupIntervalId = null;
    }
    if (this.db) {
      this.createBackup(); // Final backup
      this.db.close();
    }
    this.initialized = false;
  }

  // ─── Database Management ─────────────────────────────────────────────────

  private openDatabase(): Database {
    try {
      const db = new Database(this.dbPath, { create: true });
      db.exec("PRAGMA journal_mode = WAL;");
      db.exec("PRAGMA busy_timeout = 5000;");
      db.exec("PRAGMA foreign_keys = ON;");
      db.exec(SCHEMA_SQL);

      // Set schema version if not exists
      const ver = db.query("SELECT version FROM schema_version LIMIT 1").get() as any;
      if (!ver) {
        db.exec(`INSERT INTO schema_version (version) VALUES (${SCHEMA_VERSION});`);
      }

      return db;
    } catch (err) {
      console.error("⚠️ Failed to open database, attempting recovery...", err);
      return this.recoverDatabase();
    }
  }

  private recoverDatabase(): Database {
    // Move corrupted DB to archive
    if (existsSync(this.dbPath)) {
      const corruptPath = join(this.archivePath, `corrupted-${Date.now()}.db`);
      try {
        copyFileSync(this.dbPath, corruptPath);
      } catch {}
      try {
        const { unlinkSync } = require("fs");
        unlinkSync(this.dbPath);
      } catch {}
      console.log(`♻️ Corrupted DB archived to ${basename(corruptPath)}`);
    }

    // Create fresh DB, then try to restore from latest backup
    const db = new Database(this.dbPath, { create: true });
    db.exec("PRAGMA journal_mode = WAL;");
    db.exec(SCHEMA_SQL);
    db.exec(`INSERT INTO schema_version (version) VALUES (${SCHEMA_VERSION});`);

    // Attempt to import from latest backup
    const backups = this.getBackupFiles();
    if (backups.length > 0) {
      try {
        const latestBackup = backups[backups.length - 1];
        console.log(`♻️ Restoring from backup: ${basename(latestBackup)}`);
        const backupDb = new Database(latestBackup, { readonly: true });
        // Copy memories
        const mems = backupDb.query("SELECT * FROM memories").all();
        const insertMem = db.prepare(
          "INSERT OR IGNORE INTO memories (id, key, content, importance, source, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        );
        for (const m of mems as any[]) {
          insertMem.run(m.id, m.key, m.content, m.importance, m.source, m.tags, m.created_at, m.updated_at);
        }
        backupDb.close();
        console.log(`♻️ Restored ${mems.length} memories from backup`);
      } catch (err) {
        console.warn("⚠️ Backup restoration failed:", err);
      }
    }

    return db;
  }

  private getBackupFiles(): string[] {
    if (!existsSync(this.archivePath)) return [];
    return readdirSync(this.archivePath)
      .filter((f) => f.startsWith("backup-") && f.endsWith(".db"))
      .sort()
      .map((f) => join(this.archivePath, f));
  }

  // ─── Self-Healing ────────────────────────────────────────────────────────

  async heal(): Promise<{ ok: boolean; issues: string[] }> {
    const issues: string[] = [];

    try {
      // Integrity check
      const result = this.db.query("PRAGMA integrity_check").get() as any;
      if (result?.integrity_check !== "ok") {
        issues.push(`Integrity check failed: ${result?.integrity_check}`);
        console.warn("⚠️ Database integrity issue detected — recovering...");
        this.db.close();
        this.db = this.recoverDatabase();
      }
    } catch (err) {
      issues.push(`Integrity check error: ${err}`);
      this.db.close();
      this.db = this.recoverDatabase();
    }

    // Verify all tables exist
    const tables = ["memories", "conversations", "rules", "projects", "entities"];
    for (const table of tables) {
      const exists = this.db.query(
        `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
      ).get(table);
      if (!exists) {
        issues.push(`Missing table: ${table}`);
        this.db.exec(SCHEMA_SQL); // Re-create schema
        break;
      }
    }

    // Create backup after healing
    this.createBackup();

    return { ok: issues.length === 0, issues };
  }

  // ─── Backup ──────────────────────────────────────────────────────────────

  private createBackup(): void {
    try {
      const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      const backupPath = join(this.archivePath, `backup-${ts}.db`);
      if (existsSync(backupPath)) return; // Already backed up this second
      // Use SQLite's built-in backup (safe for WAL mode)
      this.db.exec(`VACUUM INTO '${backupPath.replace(/'/g, "''")}'`);

      // Keep only last 48 backups (2 days of hourly)
      const backups = this.getBackupFiles();
      if (backups.length > 48) {
        const { unlinkSync } = require("fs");
        for (const old of backups.slice(0, backups.length - 48)) {
          try { unlinkSync(old); } catch {}
        }
      }
    } catch (err) {
      console.warn("⚠️ Backup failed:", err);
    }
  }

  private startAutoBackup(): void {
    // Backup every hour
    this.backupIntervalId = setInterval(() => {
      this.createBackup();
    }, 60 * 60 * 1000);
  }

  // ─── Memories CRUD ───────────────────────────────────────────────────────

  async store(
    key: string,
    content: string,
    importance: Importance = "medium",
    source: Source = "user",
    tags: string[] = []
  ): Promise<string> {
    const id = generateId();
    const now = nowISO();
    this.db.prepare(
      "INSERT INTO memories (id, key, content, importance, source, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, key, content, importance, source, tags.join(","), now, now);
    return id;
  }

  async update(id: string, updates: Partial<Pick<MemoryEntry, "key" | "content" | "importance" | "tags">>): Promise<boolean> {
    const existing = this.db.query("SELECT id FROM memories WHERE id = ?").get(id) as any;
    if (!existing) return false;

    const sets: string[] = [];
    const vals: any[] = [];
    if (updates.key !== undefined) { sets.push("key = ?"); vals.push(updates.key); }
    if (updates.content !== undefined) { sets.push("content = ?"); vals.push(updates.content); }
    if (updates.importance !== undefined) { sets.push("importance = ?"); vals.push(updates.importance); }
    if (updates.tags !== undefined) { sets.push("tags = ?"); vals.push(updates.tags.join(",")); }
    sets.push("updated_at = ?");
    vals.push(nowISO());
    vals.push(id);

    this.db.prepare(`UPDATE memories SET ${sets.join(", ")} WHERE id = ?`).run(...vals);
    return true;
  }

  async delete(id: string): Promise<boolean> {
    const result = this.db.prepare("DELETE FROM memories WHERE id = ?").run(id);
    return result.changes > 0;
  }

  async get(id: string): Promise<MemoryEntry | null> {
    const row = this.db.query("SELECT * FROM memories WHERE id = ?").get(id) as any;
    if (!row) return null;
    return { ...row, tags: row.tags ? row.tags.split(",") : [] };
  }

  /**
   * Search memories with keyword + fuzzy matching.
   * Ranked by relevance score (importance + match quality).
   */
  async recall(query: string, options: { limit?: number; importance?: Importance; source?: Source } = {}): Promise<MemoryEntry[]> {
    const limit = options.limit || 10;

    let sql = "SELECT * FROM memories WHERE 1=1";
    const params: any[] = [];

    if (options.importance) {
      sql += " AND importance = ?";
      params.push(options.importance);
    }
    if (options.source) {
      sql += " AND source = ?";
      params.push(options.source);
    }

    const rows = this.db.query(sql).all(...params) as any[];

    // Filter by fuzzy match and score
    return rows
      .filter((r) => fuzzyMatch(`${r.key} ${r.content} ${r.tags || ""}`, query))
      .sort((a, b) => scoreResult(b, query) - scoreResult(a, query))
      .slice(0, limit)
      .map((r) => ({ ...r, tags: r.tags ? r.tags.split(",") : [] }));
  }

  /** Count all memories. */
  memoryCount(): number {
    const row = this.db.query("SELECT COUNT(*) as c FROM memories").get() as any;
    return row?.c || 0;
  }

  // ─── Conversations ───────────────────────────────────────────────────────

  async storeMessage(
    userId: string,
    role: "user" | "assistant" | "system",
    content: string,
    channel: string = "default"
  ): Promise<number> {
    const result = this.db.prepare(
      "INSERT INTO conversations (user_id, role, content, channel, timestamp) VALUES (?, ?, ?, ?, ?)"
    ).run(userId, role, content, channel, nowISO());
    return Number(result.lastInsertRowid);
  }

  async getConversationHistory(
    userId: string,
    options: { channel?: string; limit?: number } = {}
  ): Promise<ConversationMessage[]> {
    const limit = options.limit || 50;
    let sql = "SELECT * FROM conversations WHERE user_id = ?";
    const params: any[] = [userId];

    if (options.channel) {
      sql += " AND channel = ?";
      params.push(options.channel);
    }

    sql += " ORDER BY timestamp DESC LIMIT ?";
    params.push(limit);

    const rows = this.db.query(sql).all(...params) as ConversationMessage[];
    return rows.reverse(); // Return in chronological order
  }

  async searchConversations(query: string, options: { userId?: string; limit?: number } = {}): Promise<ConversationMessage[]> {
    const limit = options.limit || 20;
    let sql = "SELECT * FROM conversations WHERE content LIKE ?";
    const params: any[] = [`%${query}%`];

    if (options.userId) {
      sql += " AND user_id = ?";
      params.push(options.userId);
    }

    sql += " ORDER BY timestamp DESC LIMIT ?";
    params.push(limit);

    return this.db.query(sql).all(...params) as ConversationMessage[];
  }

  /** Prune old conversations keeping only the last N per user+channel. */
  async pruneConversations(keepPerUser: number = 500): Promise<number> {
    // Get distinct user/channel combos
    const combos = this.db.query(
      "SELECT DISTINCT user_id, channel FROM conversations"
    ).all() as any[];

    let totalDeleted = 0;
    for (const { user_id, channel } of combos) {
      const count = this.db.query(
        "SELECT COUNT(*) as c FROM conversations WHERE user_id = ? AND channel = ?"
      ).get(user_id, channel) as any;

      if (count.c > keepPerUser) {
        const toDelete = count.c - keepPerUser;
        this.db.prepare(
          `DELETE FROM conversations WHERE id IN (
            SELECT id FROM conversations WHERE user_id = ? AND channel = ?
            ORDER BY timestamp ASC LIMIT ?
          )`
        ).run(user_id, channel, toDelete);
        totalDeleted += toDelete;
      }
    }
    return totalDeleted;
  }

  // ─── Rules ───────────────────────────────────────────────────────────────

  async addRule(rule: string, source: Source = "user"): Promise<number> {
    const result = this.db.prepare(
      "INSERT OR IGNORE INTO rules (rule, source, active, created_at) VALUES (?, ?, 1, ?)"
    ).run(rule, source, nowISO());
    return Number(result.lastInsertRowid);
  }

  async getRules(activeOnly: boolean = true): Promise<RuleEntry[]> {
    const sql = activeOnly
      ? "SELECT * FROM rules WHERE active = 1 ORDER BY created_at"
      : "SELECT * FROM rules ORDER BY created_at";
    return this.db.query(sql).all() as RuleEntry[];
  }

  async deactivateRule(id: number): Promise<boolean> {
    const result = this.db.prepare("UPDATE rules SET active = 0 WHERE id = ?").run(id);
    return result.changes > 0;
  }

  // ─── Projects ────────────────────────────────────────────────────────────

  async addProject(name: string, description: string = "", status: string = "active", metadata: Record<string, any> = {}): Promise<number> {
    const now = nowISO();
    const result = this.db.prepare(
      "INSERT INTO projects (name, description, status, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(name, description, status, JSON.stringify(metadata), now, now);
    return Number(result.lastInsertRowid);
  }

  async getProjects(status?: string): Promise<ProjectEntry[]> {
    if (status) {
      return this.db.query("SELECT * FROM projects WHERE status = ? ORDER BY updated_at DESC").all(status) as ProjectEntry[];
    }
    return this.db.query("SELECT * FROM projects ORDER BY updated_at DESC").all() as ProjectEntry[];
  }

  async updateProject(id: number, updates: Partial<Pick<ProjectEntry, "name" | "description" | "status" | "metadata">>): Promise<boolean> {
    const sets: string[] = [];
    const vals: any[] = [];
    if (updates.name !== undefined) { sets.push("name = ?"); vals.push(updates.name); }
    if (updates.description !== undefined) { sets.push("description = ?"); vals.push(updates.description); }
    if (updates.status !== undefined) { sets.push("status = ?"); vals.push(updates.status); }
    if (updates.metadata !== undefined) { sets.push("metadata = ?"); vals.push(updates.metadata); }
    if (sets.length === 0) return false;
    sets.push("updated_at = ?"); vals.push(nowISO()); vals.push(id);
    const result = this.db.prepare(`UPDATE projects SET ${sets.join(", ")} WHERE id = ?`).run(...vals);
    return result.changes > 0;
  }

  // ─── Entities ────────────────────────────────────────────────────────────

  async addEntity(name: string, type: string, data: Record<string, any> = {}): Promise<number> {
    const now = nowISO();
    const result = this.db.prepare(
      "INSERT INTO entities (name, type, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)"
    ).run(name, type, JSON.stringify(data), now, now);
    return Number(result.lastInsertRowid);
  }

  async getEntities(type?: string): Promise<EntityEntry[]> {
    if (type) {
      return this.db.query("SELECT * FROM entities WHERE type = ? ORDER BY name").all(type) as EntityEntry[];
    }
    return this.db.query("SELECT * FROM entities ORDER BY type, name").all() as EntityEntry[];
  }

  async findEntity(name: string, type?: string): Promise<EntityEntry | null> {
    let sql = "SELECT * FROM entities WHERE name LIKE ?";
    const params: any[] = [`%${name}%`];
    if (type) { sql += " AND type = ?"; params.push(type); }
    sql += " LIMIT 1";
    return (this.db.query(sql).get(...params) as EntityEntry) || null;
  }

  async updateEntity(id: number, data: Record<string, any>): Promise<boolean> {
    const result = this.db.prepare(
      "UPDATE entities SET data = ?, updated_at = ? WHERE id = ?"
    ).run(JSON.stringify(data), nowISO(), id);
    return result.changes > 0;
  }

  // ─── Import from MASTER-MEMORY.md ────────────────────────────────────────

  async importFromMasterMemory(filePath: string): Promise<{ imported: number; errors: string[] }> {
    const errors: string[] = [];
    let imported = 0;

    if (!existsSync(filePath)) {
      return { imported: 0, errors: [`File not found: ${filePath}`] };
    }

    const content = readFileSync(filePath, "utf-8");
    const sections = content.split(/^##\s+/m).filter(Boolean);

    for (const section of sections) {
      const lines = section.trim().split("\n");
      const heading = lines[0]?.trim();
      const body = lines.slice(1).join("\n").trim();

      if (!heading || !body) continue;

      try {
        // Detect section type and import accordingly
        if (/rule/i.test(heading)) {
          // Import rules
          const ruleLines = body.split("\n").filter((l) => l.trim().startsWith("-") || l.trim().match(/^\d+\./));
          for (const rl of ruleLines) {
            const ruleText = rl.replace(/^[-\d.)\s]+/, "").trim();
            if (ruleText.length > 5) {
              await this.addRule(ruleText, "imported");
              imported++;
            }
          }
        } else if (/project/i.test(heading)) {
          // Import projects
          const projectLines = body.split("\n").filter((l) => l.trim().startsWith("-") || l.trim().startsWith("*"));
          for (const pl of projectLines) {
            const projName = pl.replace(/^[-*\s]+/, "").trim();
            if (projName.length > 3) {
              await this.addProject(projName, "", "imported");
              imported++;
            }
          }
        } else {
          // Import as generic memory
          await this.store(heading, body, "medium", "imported", ["master-memory"]);
          imported++;
        }
      } catch (err) {
        errors.push(`Error importing section "${heading}": ${err}`);
      }
    }

    return { imported, errors };
  }

  // ─── Also write updated MASTER-MEMORY.md for human readability ────────

  async exportToMasterMemory(filePath: string): Promise<void> {
    const memories = this.db.query("SELECT * FROM memories ORDER BY importance DESC, created_at").all() as any[];
    const rules = await this.getRules(true);
    const projects = await this.getProjects();

    let md = `# LYRIE AGENT — MASTER MEMORY\n`;
    md += `**Exported:** ${nowISO()}\n`;
    md += `**Memories:** ${memories.length} | **Rules:** ${rules.length} | **Projects:** ${projects.length}\n\n`;
    md += `---\n\n`;

    if (rules.length) {
      md += `## Rules\n`;
      for (const r of rules) {
        md += `- ${r.rule}\n`;
      }
      md += `\n`;
    }

    if (projects.length) {
      md += `## Projects\n`;
      for (const p of projects) {
        md += `- **${p.name}** (${p.status}): ${p.description}\n`;
      }
      md += `\n`;
    }

    if (memories.length) {
      md += `## Memories\n\n`;
      for (const m of memories) {
        md += `### ${m.key}\n`;
        md += `*${m.importance} | ${m.source} | ${m.created_at}*\n`;
        md += `${m.content}\n\n`;
      }
    }

    writeFileSync(filePath, md, "utf-8");
  }

  // ─── Status ──────────────────────────────────────────────────────────────

  status(): string {
    if (!this.initialized) return "🔴 Not initialized";

    const memCount = this.memoryCount();
    const convCount = (this.db.query("SELECT COUNT(*) as c FROM conversations").get() as any)?.c || 0;
    const ruleCount = (this.db.query("SELECT COUNT(*) as c FROM rules WHERE active = 1").get() as any)?.c || 0;
    const projCount = (this.db.query("SELECT COUNT(*) as c FROM projects").get() as any)?.c || 0;
    const entCount = (this.db.query("SELECT COUNT(*) as c FROM entities").get() as any)?.c || 0;

    const dbSize = existsSync(this.dbPath) ? (statSync(this.dbPath).size / 1024).toFixed(1) : "0";

    return `🟢 Active | ${memCount} memories, ${convCount} msgs, ${ruleCount} rules, ${projCount} projects, ${entCount} entities | DB: ${dbSize}KB`;
  }

  /** Get raw DB handle for advanced queries. */
  getDb(): Database {
    return this.db;
  }
}
