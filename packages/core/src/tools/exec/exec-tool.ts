/**
 * exec-tool.ts — LyrieExec: unified shell execution tool.
 *
 * Single unified tool for foreground + background execution.
 * action="run"        — foreground, returns output when done
 * action="background" — spawns in background, returns sessionId immediately
 * action="poll"       — wait for a background session to finish
 * action="log"        — tail/page output from a running session
 * action="kill"       — terminate a session
 * action="list"       — list all active/recent sessions
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { Tool, ToolResult } from "../tool-executor";
import { ProcessManager } from "./process-manager";
import { requireApprovalCheck, ApprovalRequired } from "./approval";

// Singleton process manager shared across all tool invocations in this process
const pm = new ProcessManager();

// ─── Parameter schema ─────────────────────────────────────────────────────────

export const EXEC_TOOL_SCHEMA = {
  name: "exec",
  description:
    "Run shell commands. action='run' executes and waits. action='background' spawns without waiting (returns sessionId). action='poll'/'log'/'kill'/'list' manage background sessions.",
  parameters: {
    action: {
      type: "string" as const,
      description: "run | background | poll | log | kill | list",
      required: true,
      enum: ["run", "background", "poll", "log", "kill", "list"],
    },
    command: {
      type: "string" as const,
      description: "Shell command to execute (required for run/background).",
      required: false,
    },
    sessionId: {
      type: "string" as const,
      description: "Session ID returned by background (required for poll/log/kill).",
      required: false,
    },
    workdir: {
      type: "string" as const,
      description: "Working directory for the command.",
      required: false,
    },
    timeout: {
      type: "number" as const,
      description: "Timeout in milliseconds. Kills process on expiry.",
      required: false,
    },
    pty: {
      type: "boolean" as const,
      description:
        "Allocate a pseudo-terminal (for TTY-required CLIs: vim, htop, claude, etc.).",
      required: false,
    },
    env: {
      type: "object" as const,
      description: "Extra environment variables to set.",
      required: false,
    },
    limit: {
      type: "number" as const,
      description: "Max lines to return (log action).",
      required: false,
    },
    offset: {
      type: "number" as const,
      description: "Line offset for pagination (log action).",
      required: false,
    },
    pollTimeoutMs: {
      type: "number" as const,
      description: "How long poll waits before returning (default 30000ms).",
      required: false,
    },
  },
  risk: "moderate" as const,
  untrustedOutput: true,
};

// ─── Tool implementation ──────────────────────────────────────────────────────

export const lyrieExecTool: Tool = {
  ...EXEC_TOOL_SCHEMA,
  execute: async (args: Record<string, any>): Promise<ToolResult> => {
    const action = args.action as string;

    try {
      switch (action) {
        // ── run ──────────────────────────────────────────────────────────────
        case "run": {
          const command = requireCommand(args, "run");
          requireApprovalCheck(command);

          const result = await pm.run(command, {
            workdir: args.workdir,
            timeout: args.timeout,
            pty: args.pty ?? false,
            env: args.env,
          });

          const lines: string[] = [];
          if (result.truncated) {
            lines.push(`[Output truncated — ${result.truncatedLines} lines hidden, showing tail]`);
          }
          lines.push(result.stdout || "(no output)");
          if (result.exitCode !== 0) {
            lines.push(`\n[exit code: ${result.exitCode}]`);
          }

          return {
            success: result.exitCode === 0,
            output: lines.join("\n"),
            metadata: {
              exitCode: result.exitCode,
              truncated: result.truncated,
            },
          };
        }

        // ── background ───────────────────────────────────────────────────────
        case "background": {
          const command = requireCommand(args, "background");
          requireApprovalCheck(command);

          const sessionId = await pm.background(command, {
            workdir: args.workdir,
            timeout: args.timeout,
            pty: args.pty ?? false,
            env: args.env,
          });

          return {
            success: true,
            output: `Session started.\nsessionId: ${sessionId}\nUse action='poll' to wait for completion or action='log' to tail output.`,
            metadata: { sessionId },
          };
        }

        // ── poll ─────────────────────────────────────────────────────────────
        case "poll": {
          const sessionId = requireSessionId(args, "poll");
          const result = await pm.poll(sessionId, args.pollTimeoutMs ?? 30_000);

          const lines: string[] = [];
          if (result.truncated) {
            lines.push(`[Output truncated — ${result.truncatedLines} lines hidden, showing tail]`);
          }
          lines.push(result.output || "(no output yet)");
          lines.push(`\nStatus: ${result.done ? "done" : "still running"}`);
          if (result.done && result.exitCode !== undefined) {
            lines.push(`Exit code: ${result.exitCode}`);
          }

          return {
            success: true,
            output: lines.join("\n"),
            metadata: {
              done: result.done,
              exitCode: result.exitCode,
              truncated: result.truncated,
            },
          };
        }

        // ── log ──────────────────────────────────────────────────────────────
        case "log": {
          const sessionId = requireSessionId(args, "log");
          const output = await pm.log(sessionId, args.limit, args.offset);

          return {
            success: true,
            output: output || "(no output)",
            metadata: { sessionId },
          };
        }

        // ── kill ─────────────────────────────────────────────────────────────
        case "kill": {
          const sessionId = requireSessionId(args, "kill");
          await pm.kill(sessionId);

          return {
            success: true,
            output: `Session ${sessionId} killed.`,
            metadata: { sessionId },
          };
        }

        // ── list ─────────────────────────────────────────────────────────────
        case "list": {
          const sessions = pm.list();
          if (sessions.length === 0) {
            return { success: true, output: "No active sessions." };
          }

          const rows = sessions.map(
            (s) =>
              `${s.sessionId.slice(0, 8)}…  [${s.status.padEnd(7)}]  pid:${s.pid ?? "N/A"}  "${truncateCommand(s.command)}"`,
          );
          return {
            success: true,
            output: `${sessions.length} session(s):\n${rows.join("\n")}`,
            metadata: { sessions },
          };
        }

        default:
          return {
            success: false,
            output: `Unknown action: ${action}. Valid: run | background | poll | log | kill | list`,
            error: `unknown action: ${action}`,
          };
      }
    } catch (err) {
      if (err instanceof ApprovalRequired) {
        return {
          success: false,
          output: `⛔ Approval required before executing this command.\nReason: ${err.reason}\nCommand: ${err.command}\n\nThis command was blocked by Lyrie's risk detection. Request explicit user approval before proceeding.`,
          error: err.message,
          metadata: { approvalRequired: true, reason: err.reason },
        };
      }
      const error = err instanceof Error ? err : new Error(String(err));
      return {
        success: false,
        output: `exec error: ${error.message}`,
        error: error.message,
      };
    }
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function requireCommand(args: Record<string, any>, action: string): string {
  if (!args.command || typeof args.command !== "string") {
    throw new Error(`'command' is required for action='${action}'`);
  }
  return args.command;
}

function requireSessionId(args: Record<string, any>, action: string): string {
  if (!args.sessionId || typeof args.sessionId !== "string") {
    throw new Error(`'sessionId' is required for action='${action}'`);
  }
  return args.sessionId;
}

function truncateCommand(cmd: string, max = 60): string {
  return cmd.length > max ? cmd.slice(0, max) + "…" : cmd;
}

// Export the shared ProcessManager instance for testing
export { pm as processManager };
