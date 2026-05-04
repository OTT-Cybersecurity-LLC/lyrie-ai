/**
 * CronStore — SQLite-backed persistence for Lyrie cron jobs.
 *
 * Uses bun:sqlite (zero-dep, built-in). Stores jobs + run history.
 * Survives daemon restarts by persisting nextRunAt per job.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { Database } from "bun:sqlite";
import { mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import type { CronJob, CronRun, CronSchedule, CronPayload, CronDelivery } from "./job";

// ─── Schema ───────────────────────────────────────────────────────────────────

const SCHEMA_SQL = `
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cron_jobs (
  id              TEXT PRIMARY KEY,
  name            TEXT,
  enabled         INTEGER NOT NULL DEFAULT 1,
  schedule_json   TEXT NOT NULL,
  payload_json    TEXT NOT NULL,
  delivery_json   TEXT,
  last_run_at     INTEGER,
  next_run_at     INTEGER,
  run_count       INTEGER NOT NULL DEFAULT 0,
  delete_after_run INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS cron_runs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id      TEXT NOT NULL REFERENCES cron_jobs(id) ON DELETE CASCADE,
  started_at  INTEGER NOT NULL,
  finished_at INTEGER NOT NULL,
  success     INTEGER NOT NULL DEFAULT 0,
  output      TEXT,
  error       TEXT
);

CREATE INDEX IF NOT EXISTS idx_cron_runs_job ON cron_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_cron_jobs_next ON cron_jobs(next_run_at) WHERE enabled = 1;
`;

// ─── CronStore ────────────────────────────────────────────────────────────────

export class CronStore {
  private db: Database;

  constructor(dbPath: string) {
    const dir = dirname(dbPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    this.db = new Database(dbPath, { create: true });
    this.db.exec(SCHEMA_SQL);
  }

  // ─── Jobs ──────────────────────────────────────────────────────────────────

  upsertJob(job: CronJob): void {
    const stmt = this.db.prepare(`
      INSERT INTO cron_jobs
        (id, name, enabled, schedule_json, payload_json, delivery_json,
         last_run_at, next_run_at, run_count, delete_after_run, created_at)
      VALUES
        ($id, $name, $enabled, $schedule, $payload, $delivery,
         $lastRunAt, $nextRunAt, $runCount, $deleteAfterRun, $createdAt)
      ON CONFLICT(id) DO UPDATE SET
        name            = excluded.name,
        enabled         = excluded.enabled,
        schedule_json   = excluded.schedule_json,
        payload_json    = excluded.payload_json,
        delivery_json   = excluded.delivery_json,
        last_run_at     = excluded.last_run_at,
        next_run_at     = excluded.next_run_at,
        run_count       = excluded.run_count,
        delete_after_run= excluded.delete_after_run
    `);
    stmt.run({
      $id: job.id,
      $name: job.name ?? null,
      $enabled: job.enabled ? 1 : 0,
      $schedule: JSON.stringify(job.schedule),
      $payload: JSON.stringify(job.payload),
      $delivery: job.delivery ? JSON.stringify(job.delivery) : null,
      $lastRunAt: job.lastRunAt ?? null,
      $nextRunAt: job.nextRunAt ?? null,
      $runCount: job.runCount,
      $deleteAfterRun: job.deleteAfterRun ? 1 : 0,
      $createdAt: job.createdAt,
    });
  }

  getJob(id: string): CronJob | undefined {
    const row = this.db.prepare("SELECT * FROM cron_jobs WHERE id = ?").get(id) as Record<string, unknown> | null;
    return row ? this.rowToJob(row) : undefined;
  }

  listJobs(includeDisabled = false): CronJob[] {
    const sql = includeDisabled
      ? "SELECT * FROM cron_jobs ORDER BY created_at ASC"
      : "SELECT * FROM cron_jobs WHERE enabled = 1 ORDER BY created_at ASC";
    const rows = this.db.prepare(sql).all() as Record<string, unknown>[];
    return rows.map(r => this.rowToJob(r));
  }

  updateJob(id: string, patch: Partial<Pick<CronJob, "name" | "enabled" | "schedule" | "payload" | "delivery" | "deleteAfterRun" | "nextRunAt">>): boolean {
    const job = this.getJob(id);
    if (!job) return false;
    const updated: CronJob = {
      ...job,
      ...patch,
    };
    this.upsertJob(updated);
    return true;
  }

  touchRun(id: string, lastRunAt: number, nextRunAt: number | undefined): void {
    this.db.prepare(`
      UPDATE cron_jobs SET
        last_run_at = ?,
        next_run_at = ?,
        run_count   = run_count + 1
      WHERE id = ?
    `).run(lastRunAt, nextRunAt ?? null, id);
  }

  deleteJob(id: string): boolean {
    const r = this.db.prepare("DELETE FROM cron_jobs WHERE id = ?").run(id);
    return r.changes > 0;
  }

  // ─── Runs ──────────────────────────────────────────────────────────────────

  insertRun(run: Omit<CronRun, "id">): number {
    const r = this.db.prepare(`
      INSERT INTO cron_runs (job_id, started_at, finished_at, success, output, error)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(run.jobId, run.startedAt, run.finishedAt, run.success ? 1 : 0, run.output ?? null, run.error ?? null);
    return r.lastInsertRowid as number;
  }

  getRuns(jobId: string, limit = 20): CronRun[] {
    const rows = this.db.prepare(
      "SELECT * FROM cron_runs WHERE job_id = ? ORDER BY started_at DESC LIMIT ?"
    ).all(jobId, limit) as Record<string, unknown>[];
    return rows.map(r => ({
      id: r.id as number,
      jobId: r.job_id as string,
      startedAt: r.started_at as number,
      finishedAt: r.finished_at as number,
      success: (r.success as number) === 1,
      output: r.output as string | undefined,
      error: r.error as string | undefined,
    }));
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private rowToJob(r: Record<string, unknown>): CronJob {
    return {
      id: r.id as string,
      name: r.name as string | undefined,
      enabled: (r.enabled as number) === 1,
      schedule: JSON.parse(r.schedule_json as string) as CronSchedule,
      payload: JSON.parse(r.payload_json as string) as CronPayload,
      delivery: r.delivery_json ? (JSON.parse(r.delivery_json as string) as CronDelivery) : undefined,
      lastRunAt: r.last_run_at as number | undefined,
      nextRunAt: r.next_run_at as number | undefined,
      runCount: r.run_count as number,
      deleteAfterRun: (r.delete_after_run as number) === 1,
      createdAt: r.created_at as number,
    };
  }

  close(): void {
    this.db.close();
  }
}
