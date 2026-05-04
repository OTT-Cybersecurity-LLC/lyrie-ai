#!/usr/bin/env bun
/**
 * `lyrie cron` — Full cron management CLI for Lyrie Agent.
 *
 * Usage:
 *   lyrie cron status
 *   lyrie cron list [--all]
 *   lyrie cron add --name <name> --cron <expr> [--tz <tz>] --message <msg>
 *   lyrie cron add --every <duration> --shell <cmd>
 *   lyrie cron add --at <iso8601> --message <msg>
 *   lyrie cron update <id> --enabled <true|false>
 *   lyrie cron remove <id>
 *   lyrie cron run <id>
 *   lyrie cron runs <id>
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { LyrieCronScheduler } from "../packages/core/src/cron/scheduler";
import type { CronJob } from "../packages/core/src/cron/job";

// ─── Colors ──────────────────────────────────────────────────────────────────

const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
};
const c = (s: string, col: keyof typeof C) => C[col] + s + C.reset;
const bold = (s: string) => c(s, "bold");
const dim = (s: string) => c(s, "dim");

// ─── Duration parser ─────────────────────────────────────────────────────────

function parseDuration(s: string): number {
  const match = s.match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d)?$/i);
  if (!match) throw new Error(`Invalid duration: "${s}". Use formats like 30s, 5m, 1h, 7d`);
  const val = parseFloat(match[1]);
  switch ((match[2] ?? "ms").toLowerCase()) {
    case "ms": return val;
    case "s": return val * 1_000;
    case "m": return val * 60_000;
    case "h": return val * 3_600_000;
    case "d": return val * 86_400_000;
    default: return val;
  }
}

// ─── Scheduler factory ───────────────────────────────────────────────────────

function getScheduler(): LyrieCronScheduler {
  const dbPath = `${process.env.HOME ?? "~"}/.lyrie/cron.db`;
  return new LyrieCronScheduler({ dbPath });
}

// ─── Format helpers ──────────────────────────────────────────────────────────

function fmtTime(ms?: number): string {
  if (!ms) return dim("—");
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").slice(0, 19);
}

function fmtSchedule(job: CronJob): string {
  const s = job.schedule;
  switch (s.kind) {
    case "at": return `at ${s.at}`;
    case "every": {
      const ms = s.everyMs;
      if (ms >= 86_400_000) return `every ${ms / 86_400_000}d`;
      if (ms >= 3_600_000) return `every ${ms / 3_600_000}h`;
      if (ms >= 60_000) return `every ${ms / 60_000}m`;
      if (ms >= 1_000) return `every ${ms / 1_000}s`;
      return `every ${ms}ms`;
    }
    case "cron": return `cron "${s.expr}"${s.tz ? ` tz:${s.tz}` : ""}`;
  }
}

function fmtPayload(job: CronJob): string {
  const p = job.payload;
  switch (p.kind) {
    case "agentTurn": return `agent: "${p.message.slice(0, 40)}${p.message.length > 40 ? "…" : ""}"`;
    case "systemEvent": return `event: "${p.text}"`;
    case "shell": return `shell: ${p.command.slice(0, 40)}${p.command.length > 40 ? "…" : ""}`;
  }
}

// ─── Commands ────────────────────────────────────────────────────────────────

function cmdStatus(scheduler: LyrieCronScheduler): void {
  const s = scheduler.status();
  const all = scheduler.list(true);
  const enabled = all.filter(j => j.enabled);
  const disabled = all.filter(j => !j.enabled);

  console.log(`\n${bold("Lyrie Cron — Status")}`);
  console.log(`  Scheduler  : ${s.running ? c("● running", "green") : c("○ stopped", "dim")}`);
  console.log(`  Jobs       : ${bold(String(all.length))} total  (${enabled.length} enabled, ${disabled.length} disabled)`);
  if (s.nextJob) {
    console.log(`  Next job   : ${c(s.nextJob.name ?? s.nextJob.id, "cyan")} at ${fmtTime(s.nextJob.nextRunAt)}`);
  } else {
    console.log(`  Next job   : ${dim("none")}`);
  }
  console.log();
}

function cmdList(scheduler: LyrieCronScheduler, all: boolean): void {
  const jobs = scheduler.list(all);
  if (jobs.length === 0) {
    console.log(dim("No cron jobs found. Use `lyrie cron add` to create one."));
    return;
  }

  // Column widths
  const idW = 8;
  const nameW = 22;
  const schedW = 28;
  const nextW = 20;
  const cntW = 5;

  const header = [
    "ID".padEnd(idW),
    "NAME".padEnd(nameW),
    "SCHEDULE".padEnd(schedW),
    "NEXT RUN".padEnd(nextW),
    "RUNS".padStart(cntW),
    "ST",
  ].join("  ");
  console.log("\n" + bold(header));
  console.log(dim("─".repeat(header.length)));

  for (const job of jobs) {
    const id = job.id.slice(0, idW).padEnd(idW);
    const name = (job.name ?? "—").slice(0, nameW).padEnd(nameW);
    const sched = fmtSchedule(job).slice(0, schedW).padEnd(schedW);
    const next = fmtTime(job.nextRunAt).padEnd(nextW);
    const cnt = String(job.runCount).padStart(cntW);
    const status = job.enabled ? c("●", "green") : c("○", "dim");
    console.log(`${c(id, "cyan")}  ${name}  ${c(sched, "blue")}  ${next}  ${cnt}  ${status}`);
  }
  console.log();
}

function cmdAdd(args: string[], scheduler: LyrieCronScheduler): void {
  // Parse flags
  const get = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
  };
  const has = (flag: string): boolean => args.includes(flag);

  const name = get("--name");
  const message = get("--message");
  const shell = get("--shell");
  const at = get("--at");
  const every = get("--every");
  const cronExpr = get("--cron");
  const tz = get("--tz");
  const model = get("--model");

  // Build schedule
  let schedule: CronJob["schedule"];
  if (at) {
    schedule = { kind: "at", at };
  } else if (every) {
    schedule = { kind: "every", everyMs: parseDuration(every) };
  } else if (cronExpr) {
    schedule = { kind: "cron", expr: cronExpr, ...(tz ? { tz } : {}) };
  } else {
    console.error(c("Error: specify one of --at, --every, or --cron", "red"));
    process.exit(1);
  }

  // Build payload
  let payload: CronJob["payload"];
  if (shell) {
    payload = { kind: "shell", command: shell };
  } else if (message) {
    payload = { kind: "agentTurn", message, ...(model ? { model } : {}) };
  } else {
    console.error(c("Error: specify --message or --shell", "red"));
    process.exit(1);
  }

  const job = scheduler.add({ name, schedule, payload });
  console.log(c(`✓ Job created: ${job.id}`, "green"));
  console.log(`  Name     : ${job.name ?? dim("—")}`);
  console.log(`  Schedule : ${fmtSchedule(job)}`);
  console.log(`  Payload  : ${fmtPayload(job)}`);
  console.log(`  Next run : ${fmtTime(job.nextRunAt)}`);
  console.log();
}

function cmdUpdate(id: string, args: string[], scheduler: LyrieCronScheduler): void {
  const get = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx >= 0 ? args[idx + 1] : undefined;
  };

  const enabledStr = get("--enabled");
  if (enabledStr == null) {
    console.error(c("Error: specify at least --enabled <true|false>", "red"));
    process.exit(1);
  }

  const enabled = enabledStr === "true" || enabledStr === "1";
  const ok = scheduler.update(id, { enabled });
  if (!ok) {
    console.error(c(`Error: job not found: ${id}`, "red"));
    process.exit(1);
  }
  console.log(c(`✓ Job ${id} updated`, "green"));
  console.log(`  enabled: ${enabled}`);
}

function cmdRemove(id: string, scheduler: LyrieCronScheduler): void {
  const ok = scheduler.remove(id);
  if (!ok) {
    console.error(c(`Error: job not found: ${id}`, "red"));
    process.exit(1);
  }
  console.log(c(`✓ Job removed: ${id}`, "green"));
}

async function cmdRun(id: string, scheduler: LyrieCronScheduler): Promise<void> {
  const job = scheduler.get(id);
  if (!job) {
    console.error(c(`Error: job not found: ${id}`, "red"));
    process.exit(1);
  }
  console.log(`Running job ${c(id, "cyan")} (${job.name ?? "unnamed"})…`);
  const before = Date.now();
  await scheduler.runNow(id);
  const runs = scheduler.runs(id, 1);
  const run = runs[0];
  if (run) {
    const took = run.finishedAt - run.startedAt;
    if (run.success) {
      console.log(c(`✓ Success`, "green") + dim(` (${took}ms)`));
      if (run.output) console.log(dim("Output: ") + run.output);
    } else {
      console.log(c(`✗ Failed`, "red") + dim(` (${took}ms)`));
      if (run.error) console.log(dim("Error: ") + c(run.error, "red"));
      if (run.output) console.log(dim("Output: ") + run.output);
    }
  }
}

function cmdRuns(id: string, scheduler: LyrieCronScheduler): void {
  const job = scheduler.get(id);
  if (!job) {
    console.error(c(`Error: job not found: ${id}`, "red"));
    process.exit(1);
  }

  const runs = scheduler.runs(id, 20);
  console.log(`\n${bold(`Run history for job: ${id}`)}  ${dim(`(${job.name ?? "unnamed"})`)}`);

  if (runs.length === 0) {
    console.log(dim("  No runs yet."));
    return;
  }

  for (const run of runs) {
    const status = run.success ? c("✓", "green") : c("✗", "red");
    const took = run.finishedAt - run.startedAt;
    const ts = fmtTime(run.startedAt);
    console.log(`  ${status}  ${ts}  ${dim(`(${took}ms)`)}`);
    if (!run.success && run.error) console.log(`       ${c(run.error, "red")}`);
    if (run.output) console.log(`       ${dim(run.output.slice(0, 80))}`);
  }
  console.log();
}

// ─── Help ────────────────────────────────────────────────────────────────────

function printHelp(): void {
  console.log(`
${bold("lyrie cron")} — Cron job management

${bold("Usage:")}
  lyrie cron status
  lyrie cron list [--all]
  lyrie cron add --name <name> (--cron <expr> | --every <duration> | --at <iso>)
               (--message <msg> | --shell <cmd>)
               [--tz <tz>] [--model <model>]
  lyrie cron update <id> --enabled <true|false>
  lyrie cron remove <id>
  lyrie cron run <id>
  lyrie cron runs <id>

${bold("Schedule types:")}
  --cron "0 9 * * *"     Standard 5-field cron expression (UTC or --tz)
  --every 30m            Interval: 30s, 5m, 1h, 7d, or 500ms
  --at 2026-05-05T10:00Z One-shot ISO-8601 datetime

${bold("Payload types:")}
  --message "Run lyrie hack ./myapp"   Agent turn (LLM)
  --shell "curl -s https://lyrie.ai"  Shell command

${bold("Examples:")}
  lyrie cron add --name "Daily scan" --cron "0 9 * * *" --tz Asia/Dubai --message "Run lyrie hack ./myapp"
  lyrie cron add --every 30m --shell "curl -s https://lyrie.ai/health"
  lyrie cron add --at "2026-05-05T10:00:00Z" --message "Ship v1.1"
  lyrie cron update abc123 --enabled false
  lyrie cron remove abc123
`);
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const subcmd = argv[0];

  if (!subcmd || subcmd === "--help" || subcmd === "-h" || subcmd === "help") {
    printHelp();
    return;
  }

  const scheduler = getScheduler();

  try {
    switch (subcmd) {
      case "status":
        cmdStatus(scheduler);
        break;

      case "list":
        cmdList(scheduler, argv.includes("--all"));
        break;

      case "add":
        cmdAdd(argv.slice(1), scheduler);
        break;

      case "update": {
        const id = argv[1];
        if (!id) { console.error(c("Error: missing job <id>", "red")); process.exit(1); }
        cmdUpdate(id, argv.slice(2), scheduler);
        break;
      }

      case "remove":
      case "rm":
      case "delete": {
        const id = argv[1];
        if (!id) { console.error(c("Error: missing job <id>", "red")); process.exit(1); }
        cmdRemove(id, scheduler);
        break;
      }

      case "run": {
        const id = argv[1];
        if (!id) { console.error(c("Error: missing job <id>", "red")); process.exit(1); }
        await cmdRun(id, scheduler);
        break;
      }

      case "runs": {
        const id = argv[1];
        if (!id) { console.error(c("Error: missing job <id>", "red")); process.exit(1); }
        cmdRuns(id, scheduler);
        break;
      }

      default:
        console.error(c(`Unknown subcommand: "${subcmd}"`, "red"));
        printHelp();
        process.exit(1);
    }
  } finally {
    scheduler.stop();
  }
}

main().catch(err => {
  console.error(c(`Fatal: ${err.message}`, "red"));
  process.exit(1);
});
