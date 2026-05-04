/**
 * LyrieCronScheduler — The core scheduling engine.
 *
 * Features:
 * - SQLite-backed (survives restart via persisted nextRunAt)
 * - at / every / cron schedule kinds
 * - Cron expression parsing (hand-rolled, zero external deps)
 * - Timezone support via Intl.DateTimeFormat
 * - Emits events: job:fired, job:completed, job:failed
 * - Integrates with lyrie daemon
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { randomUUID } from "crypto";
import { CronStore } from "./store";
import { CronRunner } from "./runner";
import type { CronJob, CronSchedule, CronPayload, CronDelivery, CronEvent } from "./job";

// ─── Cron expression parser (hand-rolled, 5-field) ────────────────────────────

/**
 * Parses a 5-field cron expression and computes the next fire time after `after`.
 *
 * Field order: minute hour dom month dow
 * Supports: * , - /
 */
export function nextCronTime(expr: string, after: Date, tz = "UTC"): Date {
  const fields = expr.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(`Invalid cron expression (expected 5 fields): "${expr}"`);
  }

  const [minF, hourF, domF, monF, dowF] = fields;

  // Work in the target timezone using Intl
  const parts = (d: Date) => {
    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: false,
    });
    const p = Object.fromEntries(fmt.formatToParts(d).map(x => [x.type, x.value]));
    return {
      year: parseInt(p.year), month: parseInt(p.month),
      day: parseInt(p.day), hour: parseInt(p.hour === "24" ? "0" : p.hour),
      minute: parseInt(p.minute), second: parseInt(p.second),
      dow: d.getDay(), // will recompute below
    };
  };

  const matches = (val: number, field: string, min: number, max: number): boolean => {
    if (field === "*") return true;
    for (const part of field.split(",")) {
      if (part.includes("/")) {
        const [rangeStr, stepStr] = part.split("/");
        const step = parseInt(stepStr);
        const [lo, hi] = rangeStr === "*" ? [min, max] : rangeStr.split("-").map(Number);
        for (let v = lo; v <= hi; v += step) if (v === val) return true;
      } else if (part.includes("-")) {
        const [lo, hi] = part.split("-").map(Number);
        if (val >= lo && val <= hi) return true;
      } else {
        if (parseInt(part) === val) return true;
      }
    }
    return false;
  };

  // Start 1 minute after `after`
  const candidate = new Date(after.getTime() + 60_000);
  candidate.setSeconds(0, 0);

  const MAX_ITER = 366 * 24 * 60; // 1 year of minutes
  for (let i = 0; i < MAX_ITER; i++) {
    const p = parts(candidate);
    // dow: Sunday=0..Saturday=6
    const dow = candidate.getDay();

    if (
      matches(p.month, monF, 1, 12) &&
      matches(p.day, domF, 1, 31) &&
      matches(dow, dowF, 0, 6) &&
      matches(p.hour, hourF, 0, 23) &&
      matches(p.minute, minF, 0, 59)
    ) {
      return candidate;
    }
    candidate.setTime(candidate.getTime() + 60_000);
  }

  throw new Error(`No future time found for cron expression "${expr}" in tz "${tz}"`);
}

// ─── Compute next run time ────────────────────────────────────────────────────

export function computeNextRunAt(schedule: CronSchedule, lastRunAt?: number): number | undefined {
  const now = Date.now();

  switch (schedule.kind) {
    case "at": {
      const t = new Date(schedule.at).getTime();
      return t > now ? t : undefined; // one-shot; if in the past, don't re-fire
    }

    case "every": {
      if (!lastRunAt) {
        // First run: align to anchor or fire immediately
        if (schedule.anchorMs) {
          const offset = ((now - schedule.anchorMs) % schedule.everyMs);
          const next = now + (schedule.everyMs - offset);
          return next;
        }
        return now + schedule.everyMs;
      }
      return lastRunAt + schedule.everyMs;
    }

    case "cron": {
      const after = lastRunAt ? new Date(lastRunAt) : new Date(now - 1);
      return nextCronTime(schedule.expr, after, schedule.tz ?? "UTC").getTime();
    }
  }
}

// ─── LyrieCronScheduler ───────────────────────────────────────────────────────

export type CronEventHandler = (event: CronEvent) => void;

export interface LyrieCronSchedulerOptions {
  dbPath?: string;
  tickIntervalMs?: number;
  /** Called with each fired event */
  onEvent?: CronEventHandler;
}

export class LyrieCronScheduler {
  private store: CronStore;
  private runner: CronRunner;
  private tickIntervalMs: number;
  private tickTimer: ReturnType<typeof setInterval> | null = null;
  private eventHandlers: CronEventHandler[] = [];
  private running = false;

  constructor(opts: LyrieCronSchedulerOptions = {}) {
    const dbPath = opts.dbPath ?? `${process.env.HOME ?? "~"}/.lyrie/cron.db`;
    this.store = new CronStore(dbPath);
    this.runner = new CronRunner(this.store);
    this.tickIntervalMs = opts.tickIntervalMs ?? 1_000;
    if (opts.onEvent) this.eventHandlers.push(opts.onEvent);
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  start(): void {
    if (this.running) return;
    this.running = true;
    // Recalculate nextRunAt for any jobs that lack it
    this.rehydrate();
    this.tickTimer = setInterval(() => this.tick(), this.tickIntervalMs);
  }

  stop(): void {
    if (!this.running) return;
    this.running = false;
    if (this.tickTimer) {
      clearInterval(this.tickTimer);
      this.tickTimer = null;
    }
  }

  // ─── Job Management ────────────────────────────────────────────────────────

  add(opts: {
    name?: string;
    schedule: CronSchedule;
    payload: CronPayload;
    delivery?: CronDelivery;
    deleteAfterRun?: boolean;
    enabled?: boolean;
  }): CronJob {
    const now = Date.now();
    const nextRunAt = computeNextRunAt(opts.schedule);
    const job: CronJob = {
      id: randomUUID(),
      name: opts.name,
      enabled: opts.enabled ?? true,
      schedule: opts.schedule,
      payload: opts.payload,
      delivery: opts.delivery,
      nextRunAt,
      runCount: 0,
      deleteAfterRun: opts.deleteAfterRun,
      createdAt: now,
    };
    this.store.upsertJob(job);
    return job;
  }

  remove(id: string): boolean {
    return this.store.deleteJob(id);
  }

  update(id: string, patch: Partial<Pick<CronJob, "name" | "enabled" | "schedule" | "payload" | "delivery" | "deleteAfterRun">>): boolean {
    const job = this.store.getJob(id);
    if (!job) return false;
    const updated = { ...job, ...patch };
    if (patch.schedule) {
      updated.nextRunAt = computeNextRunAt(patch.schedule, job.lastRunAt);
    }
    this.store.upsertJob(updated);
    return true;
  }

  list(includeDisabled = false): CronJob[] {
    return this.store.listJobs(includeDisabled);
  }

  get(id: string): CronJob | undefined {
    return this.store.getJob(id);
  }

  runs(jobId: string, limit = 20) {
    return this.store.getRuns(jobId, limit);
  }

  /** Trigger a job immediately regardless of schedule */
  async runNow(id: string): Promise<void> {
    const job = this.store.getJob(id);
    if (!job) throw new Error(`Job not found: ${id}`);
    await this.executeJob(job);
  }

  // ─── Tick ─────────────────────────────────────────────────────────────────

  private async tick(): Promise<void> {
    const now = Date.now();
    const due = this.store.listJobs(false).filter(j => j.nextRunAt != null && j.nextRunAt <= now);

    for (const job of due) {
      // Fire and forget (don't await in tick to avoid blocking scheduler)
      this.executeJob(job).catch(() => {/* errors are emitted as events */});
    }
  }

  private async executeJob(job: CronJob): Promise<void> {
    this.emit({ type: "job:fired", job });

    const run = await this.runner.run(job);

    // Compute next run time
    const nextRunAt = computeNextRunAt(job.schedule, run.startedAt);
    this.store.touchRun(job.id, run.startedAt, nextRunAt);

    // Delete one-shot jobs after run
    const shouldDelete = job.deleteAfterRun || job.schedule.kind === "at";
    if (shouldDelete) {
      this.store.deleteJob(job.id);
    }

    if (run.success) {
      this.emit({ type: "job:completed", job, run });
    } else {
      this.emit({
        type: "job:failed",
        job,
        run,
        error: new Error(run.error ?? "unknown error"),
      });
    }
  }

  // ─── Rehydration ──────────────────────────────────────────────────────────

  private rehydrate(): void {
    const jobs = this.store.listJobs(false);
    for (const job of jobs) {
      if (job.nextRunAt == null) {
        const nextRunAt = computeNextRunAt(job.schedule, job.lastRunAt);
        this.store.updateJob(job.id, { nextRunAt });
      }
    }
  }

  // ─── Events ────────────────────────────────────────────────────────────────

  on(handler: CronEventHandler): void {
    this.eventHandlers.push(handler);
  }

  off(handler: CronEventHandler): void {
    this.eventHandlers = this.eventHandlers.filter(h => h !== handler);
  }

  private emit(event: CronEvent): void {
    for (const h of this.eventHandlers) {
      try { h(event); } catch { /* swallow */ }
    }
  }

  // ─── Status ────────────────────────────────────────────────────────────────

  status(): { running: boolean; jobCount: number; nextJob?: { id: string; name?: string; nextRunAt: number } } {
    const jobs = this.store.listJobs(false);
    const sorted = jobs
      .filter(j => j.nextRunAt != null)
      .sort((a, b) => (a.nextRunAt ?? Infinity) - (b.nextRunAt ?? Infinity));
    const next = sorted[0];
    return {
      running: this.running,
      jobCount: jobs.length,
      nextJob: next ? { id: next.id, name: next.name, nextRunAt: next.nextRunAt! } : undefined,
    };
  }
}
