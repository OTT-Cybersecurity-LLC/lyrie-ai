/**
 * CronRunner — Executes cron job payloads and records results.
 *
 * Supports:
 *   agentTurn   — invokes the Lyrie agent engine (or stubs for testing)
 *   systemEvent — logs a system event
 *   shell       — runs a shell command via Bun.spawn
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { CronJob, CronRun } from "./job";
import type { CronStore } from "./store";

export type AgentTurnHandler = (message: string, model?: string, timeoutSeconds?: number) => Promise<string>;

export class CronRunner {
  private store: CronStore;
  private agentTurnHandler?: AgentTurnHandler;

  constructor(store: CronStore, agentTurnHandler?: AgentTurnHandler) {
    this.store = store;
    this.agentTurnHandler = agentTurnHandler;
  }

  setAgentTurnHandler(handler: AgentTurnHandler): void {
    this.agentTurnHandler = handler;
  }

  async run(job: CronJob): Promise<CronRun> {
    const startedAt = Date.now();
    let output: string | undefined;
    let error: string | undefined;
    let success = false;

    try {
      switch (job.payload.kind) {
        case "agentTurn": {
          if (this.agentTurnHandler) {
            output = await this.agentTurnHandler(
              job.payload.message,
              job.payload.model,
              job.payload.timeoutSeconds,
            );
          } else {
            // No handler wired — emit as system event fallback
            output = `[agentTurn] ${job.payload.message}`;
            console.log(`[cron] job:${job.id} agentTurn (no handler): ${job.payload.message}`);
          }
          success = true;
          break;
        }

        case "systemEvent": {
          output = job.payload.text;
          console.log(`[cron] job:${job.id} systemEvent: ${job.payload.text}`);
          success = true;
          break;
        }

        case "shell": {
          const result = await this.runShell(job.payload.command);
          output = result.output;
          if (result.exitCode !== 0) {
            error = `exit code ${result.exitCode}`;
            success = false;
          } else {
            success = true;
          }
          break;
        }
      }
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
      success = false;
    }

    const finishedAt = Date.now();
    const runId = this.store.insertRun({ jobId: job.id, startedAt, finishedAt, success, output, error });

    return { id: runId, jobId: job.id, startedAt, finishedAt, success, output, error };
  }

  private async runShell(command: string): Promise<{ output: string; exitCode: number }> {
    const proc = Bun.spawn(["sh", "-c", command], {
      stdout: "pipe",
      stderr: "pipe",
    });

    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);

    const output = [stdout, stderr].filter(Boolean).join("\n").trim();
    return { output, exitCode };
  }
}
