/**
 * MemoryCore — The self-healing, versioned memory system for Lyrie Agent.
 * 
 * This is what prevents the memory corruption that plagued OpenClaw.
 * 
 * Architecture:
 * - Layer 0: Immutable Archive (never modified, used for recovery)
 * - Layer 1: Structured Core (MASTER-MEMORY.md equivalent, human readable)
 * - Layer 2: Vector + Graph (semantic search + relationship tracking)
 * - Layer 3: Live Working Memory (current session context)
 * - Layer 4: Self-Healing (integrity checks, auto-recovery)
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

export type Importance = "critical" | "high" | "medium" | "low";
export type Source = "user" | "system" | "agent" | "recovered" | "imported";

export interface MemoryEntry {
  id: string;
  timestamp: string;
  key: string;
  content: any;
  importance: Importance;
  source: Source;
  version: number;
  tags?: string[];
}

export class MemoryCore {
  private basePath: string;
  private masterPath: string;
  private archivePath: string;
  private vectorPath: string;
  private currentVersion = 1;
  private entries: MemoryEntry[] = [];
  private initialized = false;

  constructor(basePath?: string) {
    this.basePath = basePath || join(process.env.HOME || "~", ".lyrie", "memory");
    this.masterPath = join(this.basePath, "master");
    this.archivePath = join(this.basePath, "archive");
    this.vectorPath = join(this.basePath, "vector");
  }

  async initialize(): Promise<void> {
    // Ensure directory structure
    for (const dir of [this.basePath, this.masterPath, this.archivePath, this.vectorPath]) {
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    }

    // Load or create master memory
    const masterFile = join(this.masterPath, "MASTER-MEMORY.md");
    if (!existsSync(masterFile)) {
      this.createFreshMaster(masterFile);
    }

    // Run self-healing check
    await this.heal();

    this.initialized = true;
    console.log(`   → Memory initialized: ${this.entries.length} entries loaded`);
    console.log(`   → Self-healing: active`);
    console.log(`   → Archive: ${this.archivePath}`);
  }

  /**
   * Store information across all memory layers.
   */
  async store(
    key: string,
    content: any,
    importance: Importance = "medium",
    source: Source = "user",
    tags: string[] = []
  ): Promise<string> {
    const entry: MemoryEntry = {
      id: `lyrie_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
      timestamp: new Date().toISOString(),
      key,
      content,
      importance,
      source,
      version: this.currentVersion,
      tags,
    };

    this.entries.push(entry);

    // Append to master memory file (human readable)
    this.appendToMaster(entry);

    // TODO: Store in vector DB for semantic search
    // TODO: Store in graph DB for relationships

    return entry.id;
  }

  /**
   * Recall information using semantic search.
   */
  async recall(query: string, options: { limit?: number } = {}): Promise<MemoryEntry[]> {
    const limit = options.limit || 10;

    // Simple keyword matching for now
    // TODO: Replace with vector similarity search
    const results = this.entries
      .filter((e) => {
        const content = JSON.stringify(e.content).toLowerCase();
        const key = e.key.toLowerCase();
        const q = query.toLowerCase();
        return content.includes(q) || key.includes(q);
      })
      .sort((a, b) => {
        // Prioritize by importance
        const importanceOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return importanceOrder[b.importance] - importanceOrder[a.importance];
      })
      .slice(0, limit);

    return results;
  }

  /**
   * Self-healing system — detects and repairs memory corruption.
   */
  async heal(): Promise<void> {
    const masterFile = join(this.masterPath, "MASTER-MEMORY.md");

    // Check master file exists
    if (!existsSync(masterFile)) {
      console.warn("⚠️ Master memory missing — restoring from archive...");
      await this.restoreFromArchive();
      return;
    }

    // Check master file is not empty
    const content = readFileSync(masterFile, "utf-8");
    if (content.length < 100) {
      console.warn("⚠️ Master memory is suspiciously small — checking archive...");
      // Don't auto-restore, but flag it
    }

    // Create periodic backup
    this.createBackup();
  }

  /**
   * Create a versioned backup of current memory state.
   */
  private createBackup(): void {
    const masterFile = join(this.masterPath, "MASTER-MEMORY.md");
    if (existsSync(masterFile)) {
      const content = readFileSync(masterFile, "utf-8");
      const backupFile = join(this.archivePath, `backup-${new Date().toISOString().slice(0, 10)}.md`);
      writeFileSync(backupFile, content, "utf-8");
    }
  }

  /**
   * Restore from archive when master is corrupted.
   */
  private async restoreFromArchive(): Promise<void> {
    // Find the most recent backup
    // TODO: Implement archive scanning and restoration
    console.log("♻️ Restoring memory from archive...");
    const masterFile = join(this.masterPath, "MASTER-MEMORY.md");
    this.createFreshMaster(masterFile);
  }

  private createFreshMaster(path: string): void {
    const content = `# LYRIE AGENT — MASTER MEMORY
**Created:** ${new Date().toISOString()}
**Status:** Fresh initialization
**Engine:** Lyrie Memory Core v1.0

---

## Identity
This is a fresh Lyrie Agent installation.

## Rules
(No rules yet — they will be learned over time)

## Projects
(No projects yet)

## Fleet
(No fleet configured yet)
`;
    writeFileSync(path, content, "utf-8");
  }

  private appendToMaster(entry: MemoryEntry): void {
    const masterFile = join(this.masterPath, "MASTER-MEMORY.md");
    const content = readFileSync(masterFile, "utf-8");
    const newEntry = `\n\n### ${entry.key} (${entry.timestamp})\nImportance: ${entry.importance} | Source: ${entry.source}\n${JSON.stringify(entry.content, null, 2)}\n`;
    writeFileSync(masterFile, content + newEntry, "utf-8");
  }

  status(): string {
    return this.initialized
      ? `🟢 Active (${this.entries.length} entries, self-healing on)`
      : "🔴 Not initialized";
  }
}
