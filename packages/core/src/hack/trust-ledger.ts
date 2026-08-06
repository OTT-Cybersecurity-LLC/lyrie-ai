/**
 * Lyrie Hack — Continuous Trust Ledger.
 *
 * Lyrie.ai by OTT Cybersecurity LLC — https://lyrie.ai — MIT License
 *
 * Persists every `computeTrustScore()` result for a target as an append-only
 * history in SQLite (via `bun:sqlite`, matching the pattern used in
 * `memory/memory-core.ts` and `memory/conversation-store.ts`), so a target's
 * trust score can be tracked run-over-run rather than only ever seen as a
 * single point-in-time number.
 *
 * This is the "snapshot + diff" pattern from `watch/store.ts` and
 * `watch/diff.ts` applied to trust scores instead of posture snapshots:
 * each `record()` call persists one `TrustLedgerEntry`, and `delta()`
 * compares the two most recent entries for a target to surface
 * regressions/improvements since the last recorded run.
 *
 * Determinism: `record()` is a straight persistence of the caller-supplied
 * `HackReport`/`TrustScoreBreakdown` — no scoring logic lives here (that's
 * `trust-score.ts`'s job). The only I/O this module performs is the SQLite
 * database itself, plus a best-effort `git rev-parse HEAD` shell-out to
 * attach a commit SHA when the ledger is being written from inside a git
 * checkout (never required — failures are swallowed and `commitSha` is
 * simply omitted).
 */

import { Database } from "bun:sqlite";
import { execSync } from "node:child_process";

import type { HackReport } from "./report-engine";
import type { TrustScoreBreakdown, TrustScoreDeduction } from "./trust-score";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface TrustLedgerEntry {
  id: string;
  runId: string;
  target: string;
  /** Best-effort `git rev-parse HEAD` at record time. Omitted outside a git repo. */
  commitSha?: string;
  score: number;
  breakdown: TrustScoreBreakdown;
  recordedAt: string;
  mode: HackReport["mode"];
}

export interface TrustLedgerDelta {
  current: TrustLedgerEntry;
  previous: TrustLedgerEntry;
  scoreDelta: number;
  /** Severities whose counted-finding count increased since the previous entry. */
  regressions: TrustScoreDeduction[];
  /** Severities whose counted-finding count decreased since the previous entry. */
  improvements: TrustScoreDeduction[];
}

// ─── Schema ──────────────────────────────────────────────────────────────────

const SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS trust_ledger (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    target TEXT NOT NULL,
    commit_sha TEXT,
    score INTEGER NOT NULL,
    breakdown TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    mode TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_trust_ledger_target ON trust_ledger(target);
  CREATE INDEX IF NOT EXISTS idx_trust_ledger_recorded_at ON trust_ledger(recorded_at);
`;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function generateId(): string {
  return `trust_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

/**
 * Best-effort `git rev-parse HEAD`. Returns `undefined` (never throws) when
 * `git` is unavailable or the cwd isn't inside a git repo — a trust ledger
 * running outside a checkout (e.g. against a live URL target) must still
 * work with no commit SHA attached.
 */
function tryGitCommitSha(): string | undefined {
  try {
    const sha = execSync("git rev-parse HEAD", {
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
    }).trim();
    return sha.length > 0 ? sha : undefined;
  } catch {
    return undefined;
  }
}

interface TrustLedgerRow {
  id: string;
  run_id: string;
  target: string;
  commit_sha: string | null;
  score: number;
  breakdown: string;
  recorded_at: string;
  mode: string;
}

function rowToEntry(row: TrustLedgerRow): TrustLedgerEntry {
  return {
    id: row.id,
    runId: row.run_id,
    target: row.target,
    commitSha: row.commit_sha ?? undefined,
    score: row.score,
    breakdown: JSON.parse(row.breakdown) as TrustScoreBreakdown,
    recordedAt: row.recorded_at,
    mode: row.mode as HackReport["mode"],
  };
}

// ─── TrustLedger ─────────────────────────────────────────────────────────────

/**
 * Append-only SQLite-backed history of `computeTrustScore()` results per
 * target. Accepts either a filesystem path (opened via `bun:sqlite`) or an
 * already-open `Database` instance, following the same constructor
 * flexibility as `MemoryCore`.
 */
export class TrustLedger {
  private db: Database;
  private initialized = false;

  constructor(dbOrPath: string | Database = ":memory:") {
    this.db = dbOrPath instanceof Database ? dbOrPath : new Database(dbOrPath, { create: true });
  }

  /** Create the `trust_ledger` table + indexes if they don't already exist. Idempotent. */
  initialize(): void {
    this.db.exec(SCHEMA_SQL);
    this.initialized = true;
  }

  private ensureInitialized(): void {
    if (!this.initialized) this.initialize();
  }

  /** Persist one trust-score record for `report.target` and return the stored entry. */
  record(report: HackReport, breakdown: TrustScoreBreakdown): TrustLedgerEntry {
    this.ensureInitialized();

    const entry: TrustLedgerEntry = {
      id: generateId(),
      runId: report.runId,
      target: report.target,
      commitSha: tryGitCommitSha(),
      score: breakdown.score,
      breakdown,
      recordedAt: nowISO(),
      mode: report.mode,
    };

    this.db
      .prepare(
        `INSERT INTO trust_ledger (id, run_id, target, commit_sha, score, breakdown, recorded_at, mode)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        entry.id,
        entry.runId,
        entry.target,
        entry.commitSha ?? null,
        entry.score,
        JSON.stringify(entry.breakdown),
        entry.recordedAt,
        entry.mode,
      );

    return entry;
  }

  /** Most-recent-first history of recorded entries for `target`, capped at `limit` (default 50). */
  history(target: string, limit: number = 50): TrustLedgerEntry[] {
    this.ensureInitialized();
    const rows = this.db
      .query(
        `SELECT * FROM trust_ledger WHERE target = ? ORDER BY recorded_at DESC, id DESC LIMIT ?`,
      )
      .all(target, limit) as TrustLedgerRow[];
    return rows.map(rowToEntry);
  }

  /** The single most recent entry for `target`, or `undefined` if none exist. */
  latest(target: string): TrustLedgerEntry | undefined {
    const [entry] = this.history(target, 1);
    return entry;
  }

  /**
   * Compare the two most recent entries for `target`. Returns `undefined` if
   * fewer than 2 entries have been recorded for that target yet.
   *
   * `regressions` = severities whose counted-finding `count` increased from
   * the previous entry to the current one; `improvements` = severities whose
   * count decreased. Deductions are compared using the CURRENT entry's
   * per-severity count/weight/subtotal (i.e. what the finding looks like now).
   */
  delta(target: string): TrustLedgerDelta | undefined {
    const [current, previous] = this.history(target, 2);
    if (!current || !previous) return undefined;

    const previousCounts = new Map(previous.breakdown.deductions.map((d) => [d.severity, d.count]));

    const regressions: TrustScoreDeduction[] = [];
    const improvements: TrustScoreDeduction[] = [];

    for (const d of current.breakdown.deductions) {
      const prevCount = previousCounts.get(d.severity) ?? 0;
      if (d.count > prevCount) regressions.push(d);
      else if (d.count < prevCount) improvements.push(d);
    }

    return {
      current,
      previous,
      scoreDelta: current.score - previous.score,
      regressions,
      improvements,
    };
  }

  /**
   * Human-readable one-liner summarizing a `delta()` result, e.g.
   * "Trust score: 91 → 68 (-23). Regression: +1 critical in latest scan."
   */
  formatDeltaSummary(delta: TrustLedgerDelta): string {
    const sign = delta.scoreDelta > 0 ? "+" : "";
    const base = `Trust score: ${delta.previous.score} → ${delta.current.score} (${sign}${delta.scoreDelta}).`;

    if (delta.regressions.length === 0 && delta.improvements.length === 0) {
      return `${base} No change in finding counts.`;
    }

    const parts: string[] = [];
    if (delta.regressions.length > 0) {
      const previousCounts = new Map(
        delta.previous.breakdown.deductions.map((d) => [d.severity, d.count]),
      );
      const text = delta.regressions
        .map((d) => `+${d.count - (previousCounts.get(d.severity) ?? 0)} ${d.severity}`)
        .join(", ");
      parts.push(`Regression: ${text} in latest scan.`);
    }
    if (delta.improvements.length > 0) {
      const previousCounts = new Map(
        delta.previous.breakdown.deductions.map((d) => [d.severity, d.count]),
      );
      const text = delta.improvements
        .map((d) => `-${(previousCounts.get(d.severity) ?? 0) - d.count} ${d.severity}`)
        .join(", ");
      parts.push(`Improvement: ${text} resolved.`);
    }

    return `${base} ${parts.join(" ")}`;
  }

  /** Close the underlying database handle. Safe to call multiple times. */
  close(): void {
    this.db.close();
  }

  /** Get the raw DB handle for advanced queries, matching MemoryCore's `getDb()`. */
  getDb(): Database {
    return this.db;
  }
}
