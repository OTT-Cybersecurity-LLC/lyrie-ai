#!/usr/bin/env bun
/**
 * lyrie memory integrity-check — ASI06 memory-poisoning defense.
 *
 * Usage:
 *   bun run scripts/memory-integrity.ts [--fix] [--json] [--db <path>]
 *
 * Options:
 *   --fix        Re-hash all drifted entries (trust current content).
 *   --json       Output report as JSON.
 *   --db <path>  Path to SQLite memory database. Defaults to ~/.lyrie/memory/lyrie-memory.db
 *   --help, -h   Show this help.
 *
 * Examples:
 *   lyrie memory integrity-check                # run check, print report
 *   lyrie memory integrity-check --json         # machine-readable output
 *   lyrie memory integrity-check --fix          # repair drifted hashes
 *
 * Exit codes:
 *   0 — all entries clean (or --fix completed)
 *   1 — integrity failures found (without --fix)
 *   2 — usage error
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { join } from "path";
import { existsSync } from "fs";
import { Database } from "bun:sqlite";
import {
  MemoryIntegrityChecker,
  type IntegrityStore,
  type HashedEntry,
  type IntegrityReport,
} from "../packages/core/src/memory/integrity-checker";

// ─── Args ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const fix = args.includes("--fix");
const asJson = args.includes("--json");
const help = args.includes("--help") || args.includes("-h");
const dbIdx = args.indexOf("--db");
const dbPath = dbIdx >= 0 ? args[dbIdx + 1] : join(process.env.HOME ?? "/tmp", ".lyrie", "memory", "lyrie-memory.db");

if (help) {
  console.log(`
lyrie memory integrity-check — detect memory drift (ASI06 defense)

USAGE
  lyrie memory integrity-check [--fix] [--json] [--db <path>]

OPTIONS
  --fix          Re-hash all drifted entries (trust current content)
  --json         Output report as JSON
  --db <path>    Path to SQLite DB (default: ~/.lyrie/memory/lyrie-memory.db)
  --help, -h     Show this help

EXIT CODES
  0  All clean
  1  Integrity failures detected
  2  Usage error
`.trim());
  process.exit(0);
}

// ─── SQLite-backed IntegrityStore ─────────────────────────────────────────────

/**
 * Wraps the existing MemoryCore SQLite to read/write hashed entries.
 * Uses a separate `memory_hashes` table so it doesn't interfere with the
 * main `memories` table schema.
 */
class SqliteIntegrityStore implements IntegrityStore {
  private db: Database;

  constructor(dbPath: string) {
    if (!existsSync(dbPath)) {
      throw new Error(`Database not found: ${dbPath}\nRun \`lyrie memory integrity-check\` after Lyrie has been initialized.`);
    }
    this.db = new Database(dbPath, { readonly: false });
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memory_hashes (
        id TEXT PRIMARY KEY,
        content TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        hashed_at INTEGER NOT NULL,
        metadata TEXT DEFAULT '{}'
      );
    `);
  }

  async put(entry: HashedEntry): Promise<void> {
    this.db.prepare(`
      INSERT OR REPLACE INTO memory_hashes (id, content, content_hash, hashed_at, metadata)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      entry.id,
      entry.content,
      entry.contentHash,
      entry.hashedAt,
      JSON.stringify(entry.metadata ?? {})
    );
  }

  async get(id: string): Promise<HashedEntry | null> {
    const row = this.db.query("SELECT * FROM memory_hashes WHERE id = ?").get(id) as any;
    if (!row) return null;
    return rowToEntry(row);
  }

  async getAll(): Promise<HashedEntry[]> {
    const rows = this.db.query("SELECT * FROM memory_hashes").all() as any[];
    return rows.map(rowToEntry);
  }

  /** Backfill: import all existing memory entries from the memories table so
   *  they get hashed for the first time. Idempotent.
   */
  async backfillFromMemories(): Promise<number> {
    // Check if memories table exists
    const tbl = this.db.query("SELECT name FROM sqlite_master WHERE type='table' AND name='memories'").get() as any;
    if (!tbl) return 0;

    const rows = this.db.query("SELECT id, content FROM memories").all() as Array<{ id: string; content: string }>;
    const checker = new MemoryIntegrityChecker(this);
    let count = 0;
    for (const row of rows) {
      const existing = await this.get(row.id);
      if (!existing) {
        await checker.hashAndStore({ id: row.id, content: row.content });
        count++;
      }
    }
    return count;
  }

  close(): void { this.db.close(); }
}

function rowToEntry(row: any): HashedEntry {
  return {
    id: row.id,
    content: row.content,
    contentHash: row.content_hash,
    hashedAt: row.hashed_at,
    metadata: JSON.parse(row.metadata ?? "{}"),
  };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  let store: SqliteIntegrityStore;

  try {
    store = new SqliteIntegrityStore(dbPath);
  } catch (err: any) {
    console.error(`❌ ${err.message}`);
    process.exit(2);
  }

  const checker = new MemoryIntegrityChecker(store);

  // Backfill: first run will hash all existing memories
  const backfilled = await store.backfillFromMemories();
  if (backfilled > 0 && !asJson) {
    console.log(`ℹ️  Backfilled ${backfilled} entries for first-time integrity baseline.`);
  }

  if (fix) {
    // --fix mode: trust current content, re-hash everything
    const report = await checker.runIntegrityCheck();
    if (report.failedEntries.length === 0) {
      if (asJson) {
        console.log(JSON.stringify({ fixed: 0, message: "Nothing to fix — all clean." }));
      } else {
        console.log("✅ Nothing to fix — all entries are clean.");
      }
      store.close();
      process.exit(0);
    }

    const { fixed } = await checker.fixHashes();
    if (asJson) {
      console.log(JSON.stringify({ fixed, message: `Re-hashed ${fixed} drifted entry(entries).` }));
    } else {
      console.log(`🔧 Re-hashed ${fixed} drifted entry(entries). Integrity baseline updated.`);
    }
    store.close();
    process.exit(0);
  }

  // Normal check mode
  const report: IntegrityReport = await checker.runIntegrityCheck();

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }

  store.close();
  process.exit(report.failedEntries.length > 0 ? 1 : 0);
}

function printReport(r: IntegrityReport): void {
  const status = r.failedEntries.length === 0 ? "✅ CLEAN" : "🚨 DRIFT DETECTED";
  console.log(`\n${status}`);
  console.log(`  Total entries:  ${r.totalEntries}`);
  console.log(`  Passed:         ${r.passedEntries}`);
  console.log(`  Failed:         ${r.failedEntries.length}`);
  console.log(`  Duration:       ${r.checkDurationMs}ms\n`);

  if (r.failedEntries.length > 0) {
    console.log("Failed entries (possible tampering):");
    for (const f of r.failedEntries) {
      console.log(`  ❌ ${f.id}`);
      console.log(`     stored:   ${f.storedHash}`);
      console.log(`     current:  ${f.computedHash}`);
      console.log(`     preview:  ${f.content.slice(0, 80)}${f.content.length > 80 ? "…" : ""}`);
    }
    console.log(`\nRun with --fix to re-baseline (only if you trust the current content).`);
  }
}

main();
