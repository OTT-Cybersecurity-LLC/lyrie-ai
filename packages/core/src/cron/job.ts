/**
 * CronJob — Type definitions for Lyrie's cron scheduling system.
 *
 * Supports three schedule kinds:
 *   at     — one-shot, fires at a specific ISO-8601 time
 *   every  — interval-based, fires every N milliseconds
 *   cron   — cron expression (5-field), with optional timezone
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Schedule ────────────────────────────────────────────────────────────────

export type CronScheduleAt = {
  kind: "at";
  /** ISO-8601 datetime string */
  at: string;
};

export type CronScheduleEvery = {
  kind: "every";
  /** Interval in milliseconds */
  everyMs: number;
  /** Optional anchor epoch ms — aligns tick to wall clock (e.g. top of minute) */
  anchorMs?: number;
};

export type CronScheduleCron = {
  kind: "cron";
  /** Standard 5-field cron expression: min hour dom month dow */
  expr: string;
  /** IANA timezone string, e.g. "Asia/Dubai". Defaults to UTC. */
  tz?: string;
};

export type CronSchedule = CronScheduleAt | CronScheduleEvery | CronScheduleCron;

// ─── Payload ─────────────────────────────────────────────────────────────────

export type CronPayloadAgentTurn = {
  kind: "agentTurn";
  message: string;
  model?: string;
  timeoutSeconds?: number;
};

export type CronPayloadSystemEvent = {
  kind: "systemEvent";
  text: string;
};

export type CronPayloadShell = {
  kind: "shell";
  command: string;
};

export type CronPayload = CronPayloadAgentTurn | CronPayloadSystemEvent | CronPayloadShell;

// ─── Delivery ────────────────────────────────────────────────────────────────

export type CronDelivery = {
  mode: "none" | "announce" | "webhook";
  channel?: string;
  to?: string;
};

// ─── Job ─────────────────────────────────────────────────────────────────────

export interface CronJob {
  id: string;
  name?: string;
  enabled: boolean;
  schedule: CronSchedule;
  payload: CronPayload;
  delivery?: CronDelivery;
  lastRunAt?: number;
  nextRunAt?: number;
  runCount: number;
  deleteAfterRun?: boolean;
  createdAt: number;
}

// ─── Run History ─────────────────────────────────────────────────────────────

export interface CronRun {
  id: number;
  jobId: string;
  startedAt: number;
  finishedAt: number;
  success: boolean;
  output?: string;
  error?: string;
}

// ─── Events ──────────────────────────────────────────────────────────────────

export type CronEventFired = { type: "job:fired"; job: CronJob };
export type CronEventCompleted = { type: "job:completed"; job: CronJob; run: CronRun };
export type CronEventFailed = { type: "job:failed"; job: CronJob; run: CronRun; error: Error };

export type CronEvent = CronEventFired | CronEventCompleted | CronEventFailed;
