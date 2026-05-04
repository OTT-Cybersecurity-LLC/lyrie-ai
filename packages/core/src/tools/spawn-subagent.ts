/**
 * spawn_subagent — LLM-callable built-in tool for Lyrie v1.1.
 *
 * Gives the running LLM the ability to spawn an isolated sub-agent
 * mid-conversation, wait for its result, and continue.  Equivalent to
 * OpenClaw's `sessions_spawn`.
 *
 * Usage (as a tool call):
 *   spawn_subagent({
 *     task: "scan https://example.com for open ports",
 *     model: "claude-haiku-4-5",      // optional
 *     timeoutSeconds: 120,            // optional, default 300
 *     context: "isolated"             // optional, default "isolated"
 *   })
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { Tool } from "./tool-executor";
import { defaultSubagentRunner } from "../agents/subagent-runner";

// ─── Tool definition ──────────────────────────────────────────────────────────

export const spawnSubagentTool: Tool = {
  name: "spawn_subagent",
  description:
    "Spawn an isolated sub-agent to work on a specific task. " +
    "The sub-agent runs independently, completes the task, and returns its result. " +
    "Use for: parallel work, long-running tasks, specialised analysis, " +
    "tasks that need their own tool budget, or anything the parent agent " +
    "wants to delegate without polluting its own context. " +
    'context="fork" injects the parent context summary into the sub-agent.',
  parameters: {
    task: {
      type: "string",
      description: "Full task description for the sub-agent.",
      required: true,
    },
    model: {
      type: "string",
      description:
        "Model override, e.g. \"claude-haiku-4-5\" or \"claude-opus-4-6\". " +
        "Defaults to the parent agent's current model.",
    },
    timeoutSeconds: {
      type: "number",
      description: "Max seconds to wait for the sub-agent (default: 300).",
      default: 300,
    },
    context: {
      type: "string",
      description:
        '"isolated" = clean start (default). ' +
        '"fork" = inject parent context summary before the task.',
      enum: ["isolated", "fork"],
      default: "isolated",
    },
    parentContext: {
      type: "string",
      description:
        'When context="fork", pass a compact summary of the parent ' +
        "conversation here so the sub-agent has relevant background.",
    },
  },
  risk: "moderate",
  execute: async (args) => {
    const task: string = args.task;
    if (!task || typeof task !== "string" || !task.trim()) {
      return {
        success: false,
        output: "",
        error: 'spawn_subagent: "task" is required and must be a non-empty string.',
      };
    }

    const result = await defaultSubagentRunner.run(task, {
      model: args.model,
      timeoutSeconds: args.timeoutSeconds ?? 300,
      context: (args.context ?? "isolated") as "isolated" | "fork",
      parentContext: args.parentContext,
    });

    if (!result.success) {
      return {
        success: false,
        output: result.output || "",
        error: result.error ?? "Sub-agent failed without an error message.",
        metadata: {
          durationMs: result.durationMs,
          model: result.model,
        },
      };
    }

    return {
      success: true,
      output: result.output,
      metadata: {
        durationMs: result.durationMs,
        model: result.model,
      },
    };
  },
};
