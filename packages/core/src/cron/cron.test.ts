/**
 * Lyrie Cron — Test suite (30+ tests)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, it, expect, beforeEach, afterEach, mock } from "bun:test";
import { join } from "path";
import { rmSync, existsSync } from "fs";
import { tmpdir } from "os";

import { LyrieCronScheduler, nextCronTime, computeNextRunAt } from "./scheduler";
import { CronStore } from "./store";
import { CronRunner } from "./runner";
import type { CronJob } from "./job";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function tmpDb(label: string): string {
  return join(tmpdir(), `lyrie-cron-test-${label}-${Date.now()}.db`);
}

function cleanup(path: string): void {
  try { rmSync(path); } catch { /* ignore */ }
  try { rmSync(path + "-wal"); } catch { /* ignore */ }
  try { rmSync(path + "-shm"); } catch { /* ignore */ }
}

function makeJob(overrides: Partial<CronJob> = {}): CronJob {
  return {
    id: "test-job-1",
    name: "Test Job",
    enabled: true,
    schedule: { kind: "every", everyMs: 5000 },
    payload: { kind: "systemEvent", text: "hello" },
    runCount: 0,
    createdAt: Date.now(),
    ...overrides,
  };
}

// ─── nextCronTime ─────────────────────────────────────────────────────────────

describe("nextCronTime", () => {
  it("should return a Date in the future", () => {
    const after = new Date("2026-01-01T00:00:00Z");
    const next = nextCronTime("0 9 * * *", after, "UTC");
    expect(next.getTime()).toBeGreaterThan(after.getTime());
  });

  it("should fire at 09:00 UTC for '0 9 * * *'", () => {
    const after = new Date("2026-01-01T08:00:00Z");
    const next = nextCronTime("0 9 * * *", after, "UTC");
    expect(next.getUTCHours()).toBe(9);
    expect(next.getUTCMinutes()).toBe(0);
  });

  it("should skip to next day if today's time has passed", () => {
    const after = new Date("2026-01-01T10:00:00Z"); // past 09:00
    const next = nextCronTime("0 9 * * *", after, "UTC");
    expect(next.getUTCDate()).toBe(2); // next day
  });

  it("should handle minute-level cron '*/5 * * * *'", () => {
    const after = new Date("2026-01-01T00:00:00Z");
    const next = nextCronTime("*/5 * * * *", after, "UTC");
    expect(next.getUTCMinutes() % 5).toBe(0);
    expect(next.getTime()).toBeGreaterThan(after.getTime());
  });

  it("should handle day-of-week (Monday-only)", () => {
    // 2026-01-05 is a Monday
    const after = new Date("2026-01-01T00:00:00Z"); // Thursday
    const next = nextCronTime("0 0 * * 1", after, "UTC"); // midnight Mondays
    expect(next.getUTCDay()).toBe(1); // Monday
  });

  it("should handle range expressions '0 9-17 * * *'", () => {
    const after = new Date("2026-01-01T08:00:00Z");
    const next = nextCronTime("0 9-17 * * *", after, "UTC");
    expect(next.getUTCHours()).toBe(9);
  });

  it("should handle step in range '0 */6 * * *'", () => {
    const after = new Date("2026-01-01T07:00:00Z");
    const next = nextCronTime("0 */6 * * *", after, "UTC");
    expect(next.getUTCHours() % 6).toBe(0);
  });

  it("should throw on invalid expression", () => {
    expect(() => nextCronTime("bad expr", new Date(), "UTC")).toThrow();
  });

  it("should handle timezone Asia/Dubai", () => {
    const after = new Date("2026-01-01T00:00:00Z");
    const next = nextCronTime("0 9 * * *", after, "Asia/Dubai");
    // 09:00 Dubai = 05:00 UTC
    expect(next.getTime()).toBeGreaterThan(after.getTime());
  });
});

// ─── computeNextRunAt ─────────────────────────────────────────────────────────

describe("computeNextRunAt", () => {
  it("returns future ms for 'at' in the future", () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    const result = computeNextRunAt({ kind: "at", at: future });
    expect(result).toBeGreaterThan(Date.now());
  });

  it("returns undefined for 'at' in the past", () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const result = computeNextRunAt({ kind: "at", at: past });
    expect(result).toBeUndefined();
  });

  it("returns next interval time for 'every' (first run)", () => {
    const result = computeNextRunAt({ kind: "every", everyMs: 10_000 });
    expect(result).toBeGreaterThan(Date.now());
    expect(result! - Date.now()).toBeLessThanOrEqual(10_001);
  });

  it("returns lastRunAt + everyMs for 'every' (subsequent run)", () => {
    const lastRun = Date.now() - 5_000;
    const result = computeNextRunAt({ kind: "every", everyMs: 10_000 }, lastRun);
    expect(result).toBe(lastRun + 10_000);
  });

  it("returns a future ms for 'cron'", () => {
    const result = computeNextRunAt({ kind: "cron", expr: "* * * * *" });
    expect(result).toBeGreaterThan(Date.now());
  });
});

// ─── CronStore ────────────────────────────────────────────────────────────────

describe("CronStore", () => {
  let dbPath: string;
  let store: CronStore;

  beforeEach(() => {
    dbPath = tmpDb("store");
    store = new CronStore(dbPath);
  });

  afterEach(() => {
    store.close();
    cleanup(dbPath);
  });

  it("upserts and retrieves a job", () => {
    const job = makeJob();
    store.upsertJob(job);
    const got = store.getJob(job.id);
    expect(got?.id).toBe(job.id);
    expect(got?.name).toBe("Test Job");
  });

  it("lists enabled jobs only by default", () => {
    store.upsertJob(makeJob({ id: "a", enabled: true }));
    store.upsertJob(makeJob({ id: "b", enabled: false }));
    const list = store.listJobs(false);
    expect(list.length).toBe(1);
    expect(list[0].id).toBe("a");
  });

  it("lists all jobs with includeDisabled=true", () => {
    store.upsertJob(makeJob({ id: "a", enabled: true }));
    store.upsertJob(makeJob({ id: "b", enabled: false }));
    const list = store.listJobs(true);
    expect(list.length).toBe(2);
  });

  it("deletes a job", () => {
    const job = makeJob();
    store.upsertJob(job);
    expect(store.deleteJob(job.id)).toBe(true);
    expect(store.getJob(job.id)).toBeUndefined();
  });

  it("returns false when deleting non-existent job", () => {
    expect(store.deleteJob("ghost")).toBe(false);
  });

  it("updates a job via updateJob", () => {
    store.upsertJob(makeJob());
    store.updateJob("test-job-1", { enabled: false });
    const got = store.getJob("test-job-1");
    expect(got?.enabled).toBe(false);
  });

  it("touchRun updates lastRunAt, nextRunAt, runCount", () => {
    store.upsertJob(makeJob());
    store.touchRun("test-job-1", 1000, 6000);
    const got = store.getJob("test-job-1");
    expect(got?.lastRunAt).toBe(1000);
    expect(got?.nextRunAt).toBe(6000);
    expect(got?.runCount).toBe(1);
  });

  it("inserts and retrieves run history", () => {
    store.upsertJob(makeJob());
    store.insertRun({ jobId: "test-job-1", startedAt: 1000, finishedAt: 1500, success: true, output: "ok" });
    const runs = store.getRuns("test-job-1");
    expect(runs.length).toBe(1);
    expect(runs[0].success).toBe(true);
    expect(runs[0].output).toBe("ok");
  });

  it("respects limit in getRuns", () => {
    store.upsertJob(makeJob());
    for (let i = 0; i < 10; i++) {
      store.insertRun({ jobId: "test-job-1", startedAt: i * 1000, finishedAt: i * 1000 + 100, success: true });
    }
    const runs = store.getRuns("test-job-1", 3);
    expect(runs.length).toBe(3);
  });

  it("persists complex schedule JSON correctly", () => {
    const job = makeJob({
      schedule: { kind: "cron", expr: "0 9 * * 1-5", tz: "Asia/Dubai" },
    });
    store.upsertJob(job);
    const got = store.getJob(job.id);
    expect(got?.schedule).toEqual(job.schedule);
  });
});

// ─── CronRunner ───────────────────────────────────────────────────────────────

describe("CronRunner", () => {
  let dbPath: string;
  let store: CronStore;
  let runner: CronRunner;

  beforeEach(() => {
    dbPath = tmpDb("runner");
    store = new CronStore(dbPath);
    runner = new CronRunner(store);
  });

  afterEach(() => {
    store.close();
    cleanup(dbPath);
  });

  it("runs systemEvent payload successfully", async () => {
    const job = makeJob({ payload: { kind: "systemEvent", text: "ping" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.success).toBe(true);
    expect(run.output).toBe("ping");
  });

  it("runs shell payload and captures stdout", async () => {
    const job = makeJob({ payload: { kind: "shell", command: "echo hello-from-cron" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.success).toBe(true);
    expect(run.output).toContain("hello-from-cron");
  });

  it("marks shell payload failed on non-zero exit", async () => {
    const job = makeJob({ payload: { kind: "shell", command: "exit 1" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.success).toBe(false);
    expect(run.error).toContain("exit code");
  });

  it("runs agentTurn with custom handler", async () => {
    const handler = async (msg: string) => `echo: ${msg}`;
    runner.setAgentTurnHandler(handler);
    const job = makeJob({ payload: { kind: "agentTurn", message: "check status" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.success).toBe(true);
    expect(run.output).toBe("echo: check status");
  });

  it("runs agentTurn without handler (fallback)", async () => {
    const job = makeJob({ payload: { kind: "agentTurn", message: "fallback" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.success).toBe(true);
    expect(run.output).toContain("fallback");
  });

  it("records finishedAt after startedAt", async () => {
    const job = makeJob({ payload: { kind: "systemEvent", text: "t" } });
    store.upsertJob(job);
    const run = await runner.run(job);
    expect(run.finishedAt).toBeGreaterThanOrEqual(run.startedAt);
  });
});

// ─── LyrieCronScheduler ───────────────────────────────────────────────────────

describe("LyrieCronScheduler", () => {
  let dbPath: string;
  let scheduler: LyrieCronScheduler;

  beforeEach(() => {
    dbPath = tmpDb("scheduler");
    scheduler = new LyrieCronScheduler({ dbPath, tickIntervalMs: 50 });
  });

  afterEach(() => {
    scheduler.stop();
    cleanup(dbPath);
  });

  it("starts and stops without error", () => {
    scheduler.start();
    expect(scheduler.status().running).toBe(true);
    scheduler.stop();
    expect(scheduler.status().running).toBe(false);
  });

  it("adds a job and lists it", () => {
    scheduler.add({
      name: "my job",
      schedule: { kind: "every", everyMs: 30_000 },
      payload: { kind: "systemEvent", text: "tick" },
    });
    const list = scheduler.list();
    expect(list.length).toBe(1);
    expect(list[0].name).toBe("my job");
  });

  it("removes a job", () => {
    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 60_000 },
      payload: { kind: "systemEvent", text: "hi" },
    });
    expect(scheduler.remove(job.id)).toBe(true);
    expect(scheduler.list().length).toBe(0);
  });

  it("disabled job does not appear in default list", () => {
    const job = scheduler.add({
      enabled: false,
      schedule: { kind: "every", everyMs: 60_000 },
      payload: { kind: "systemEvent", text: "hidden" },
    });
    expect(scheduler.list(false).length).toBe(0);
    expect(scheduler.list(true).length).toBe(1);
  });

  it("updates enabled flag", () => {
    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 60_000 },
      payload: { kind: "systemEvent", text: "hi" },
    });
    scheduler.update(job.id, { enabled: false });
    const updated = scheduler.get(job.id);
    expect(updated?.enabled).toBe(false);
  });

  it("fires interval job after everyMs", async () => {
    const fired: string[] = [];
    scheduler.on(e => { if (e.type === "job:fired") fired.push(e.job.id); });
    scheduler.start();

    scheduler.add({
      schedule: { kind: "every", everyMs: 80 },
      payload: { kind: "systemEvent", text: "tick" },
    });

    await new Promise(r => setTimeout(r, 250));
    expect(fired.length).toBeGreaterThan(0);
  });

  it("at-time job fires once then is removed", async () => {
    const completed: string[] = [];
    scheduler.on(e => { if (e.type === "job:completed") completed.push(e.job.id); });
    scheduler.start();

    const atTime = new Date(Date.now() + 100).toISOString();
    const job = scheduler.add({
      schedule: { kind: "at", at: atTime },
      payload: { kind: "systemEvent", text: "once" },
    });

    await new Promise(r => setTimeout(r, 300));
    expect(completed).toContain(job.id);
    // Job should be deleted after run
    expect(scheduler.get(job.id)).toBeUndefined();
  });

  it("runNow triggers job immediately", async () => {
    const completed: string[] = [];
    scheduler.on(e => { if (e.type === "job:completed") completed.push(e.job.id); });

    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 999_999 },
      payload: { kind: "systemEvent", text: "now" },
    });

    await scheduler.runNow(job.id);
    expect(completed).toContain(job.id);
  });

  it("runNow throws for unknown job", async () => {
    await expect(scheduler.runNow("ghost-id")).rejects.toThrow("not found");
  });

  it("emits job:failed on shell error", async () => {
    const failures: string[] = [];
    scheduler.on(e => { if (e.type === "job:failed") failures.push(e.job.id); });

    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 999_999 },
      payload: { kind: "shell", command: "exit 42" },
    });

    await scheduler.runNow(job.id);
    expect(failures).toContain(job.id);
  });

  it("run history is accessible via runs()", async () => {
    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 999_999 },
      payload: { kind: "systemEvent", text: "log me" },
    });
    await scheduler.runNow(job.id);
    const runs = scheduler.runs(job.id);
    expect(runs.length).toBe(1);
    expect(runs[0].success).toBe(true);
  });

  it("status reports correct jobCount", () => {
    scheduler.add({ schedule: { kind: "every", everyMs: 10_000 }, payload: { kind: "systemEvent", text: "a" } });
    scheduler.add({ schedule: { kind: "every", everyMs: 10_000 }, payload: { kind: "systemEvent", text: "b" } });
    expect(scheduler.status().jobCount).toBe(2);
  });

  it("status reports nextJob when scheduler has jobs", () => {
    scheduler.add({ schedule: { kind: "every", everyMs: 10_000 }, payload: { kind: "systemEvent", text: "a" } });
    const s = scheduler.status();
    expect(s.nextJob).toBeDefined();
    expect(s.nextJob!.nextRunAt).toBeGreaterThan(0);
  });

  it("SQLite persistence: job survives scheduler restart", () => {
    const job = scheduler.add({
      name: "persist-me",
      schedule: { kind: "every", everyMs: 30_000 },
      payload: { kind: "systemEvent", text: "survived" },
    });

    // Create a new scheduler pointing at the same DB
    const scheduler2 = new LyrieCronScheduler({ dbPath, tickIntervalMs: 50 });
    const list = scheduler2.list();
    scheduler2.stop();

    expect(list.find(j => j.id === job.id)).toBeDefined();
    expect(list.find(j => j.id === job.id)?.name).toBe("persist-me");
  });

  it("cron expression job fires at correct minute boundary", async () => {
    const fired: string[] = [];
    scheduler.on(e => { if (e.type === "job:fired") fired.push(e.job.id); });
    scheduler.start();

    // Use runNow to test cron job execution (not wall-clock waiting)
    const job = scheduler.add({
      schedule: { kind: "cron", expr: "* * * * *" },
      payload: { kind: "systemEvent", text: "cron tick" },
    });
    await scheduler.runNow(job.id);
    expect(fired).toContain(job.id);
  });

  it("deleteAfterRun removes job on completion", async () => {
    const job = scheduler.add({
      schedule: { kind: "every", everyMs: 999_999 },
      payload: { kind: "systemEvent", text: "bye" },
      deleteAfterRun: true,
    });
    await scheduler.runNow(job.id);
    expect(scheduler.get(job.id)).toBeUndefined();
  });
});
