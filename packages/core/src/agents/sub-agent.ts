/**
 * SubAgent — Isolated sub-agent spawning for Lyrie Agent.
 *
 * Sub-agents run parallel tasks with:
 * - Their own conversation context
 * - Access to the same tool set (Shield-gated)
 * - Configurable max concurrency
 * - Timeout and cancellation support
 * - Result collection back to parent
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { ToolExecutor, ToolCall, ToolResult } from "../tools/tool-executor";
import type { ModelInstance } from "../engine/model-router";
import { AgentMessageBus } from "./message-bus";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface SubAgentConfig {
  /** Maximum concurrent sub-agents */
  maxConcurrent?: number;
  /** Default timeout per sub-agent in ms (default: 300000 = 5 min) */
  defaultTimeout?: number;
  /** Maximum tool calls per sub-agent (prevents infinite loops) */
  maxToolCalls?: number;
  /** Maximum conversation turns per sub-agent */
  maxTurns?: number;
}

export interface SubAgentTask {
  /** Unique task ID */
  id: string;
  /** Task description / system prompt for the sub-agent */
  instruction: string;
  /** Initial user message to kick off the sub-agent */
  input: string;
  /** Optional model override */
  model?: ModelInstance;
  /** Timeout override in ms */
  timeout?: number;
  /** Optional context to prepend */
  context?: string[];
  /** Tags for filtering */
  tags?: string[];
}

export type SubAgentStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "timeout";

export interface SubAgentResult {
  taskId: string;
  status: SubAgentStatus;
  output: string;
  toolCallsMade: number;
  turns: number;
  durationMs: number;
  error?: string;
}

interface SubAgentState {
  task: SubAgentTask;
  status: SubAgentStatus;
  messages: Array<{ role: string; content: string }>;
  toolCallsMade: number;
  turns: number;
  startTime: number;
  abortController: AbortController;
}

// ─── SubAgentManager ─────────────────────────────────────────────────────────

export class SubAgentManager {
  private tools: ToolExecutor;
  private defaultModel: ModelInstance | null = null;
  private agents: Map<string, SubAgentState> = new Map();
  private results: Map<string, SubAgentResult> = new Map();
  private maxConcurrent: number;
  private defaultTimeout: number;
  private maxToolCalls: number;
  private maxTurns: number;

  constructor(tools: ToolExecutor, config: SubAgentConfig = {}) {
    this.tools = tools;
    this.maxConcurrent = config.maxConcurrent ?? 5;
    this.defaultTimeout = config.defaultTimeout ?? 300000;
    this.maxToolCalls = config.maxToolCalls ?? 50;
    this.maxTurns = config.maxTurns ?? 20;
  }

  /**
   * Set the default model for sub-agents.
   */
  setDefaultModel(model: ModelInstance): void {
    this.defaultModel = model;
  }

  // ─── Spawn & Execute ───────────────────────────────────────────────────

  /**
   * Spawn a single sub-agent and return its result.
   */
  async spawn(task: SubAgentTask): Promise<SubAgentResult> {
    // Check concurrency limit
    const running = Array.from(this.agents.values()).filter(
      (a) => a.status === "running"
    ).length;

    if (running >= this.maxConcurrent) {
      return {
        taskId: task.id,
        status: "failed",
        output: "",
        toolCallsMade: 0,
        turns: 0,
        durationMs: 0,
        error: `Max concurrent sub-agents (${this.maxConcurrent}) reached`,
      };
    }

    const model = task.model ?? this.defaultModel;
    if (!model) {
      return {
        taskId: task.id,
        status: "failed",
        output: "",
        toolCallsMade: 0,
        turns: 0,
        durationMs: 0,
        error: "No model configured for sub-agent",
      };
    }

    const abortController = new AbortController();
    const state: SubAgentState = {
      task,
      status: "running",
      messages: [],
      toolCallsMade: 0,
      turns: 0,
      startTime: Date.now(),
      abortController,
    };

    this.agents.set(task.id, state);

    // Register this agent's message-bus channel so peers can reach it
    AgentMessageBus.getInstance().registerChannel(task.id);

    // Build initial messages
    state.messages.push({
      role: "system",
      content: buildSubAgentSystemPrompt(task.instruction),
    });

    // Add context if provided
    if (task.context?.length) {
      for (const ctx of task.context) {
        state.messages.push({ role: "system", content: `[Context] ${ctx}` });
      }
    }

    state.messages.push({ role: "user", content: task.input });

    // Set up timeout
    const timeout = task.timeout ?? this.defaultTimeout;
    const timeoutTimer = setTimeout(() => {
      abortController.abort();
    }, timeout);

    try {
      const result = await this.runAgentLoop(state, model);
      clearTimeout(timeoutTimer);
      this.results.set(task.id, result);
      return result;
    } catch (err: any) {
      clearTimeout(timeoutTimer);

      const isTimeout = abortController.signal.aborted;
      const result: SubAgentResult = {
        taskId: task.id,
        status: isTimeout ? "timeout" : "failed",
        output: "",
        toolCallsMade: state.toolCallsMade,
        turns: state.turns,
        durationMs: Date.now() - state.startTime,
        error: isTimeout
          ? `Sub-agent timed out after ${timeout}ms`
          : err.message,
      };

      state.status = result.status;
      this.results.set(task.id, result);
      return result;
    } finally {
      // Clean up state after some time; also remove bus channel
      AgentMessageBus.getInstance().unregisterChannel(task.id);
      setTimeout(() => this.agents.delete(task.id), 60000);
    }
  }

  /**
   * Spawn multiple sub-agents in parallel and collect all results.
   */
  async spawnAll(tasks: SubAgentTask[]): Promise<SubAgentResult[]> {
    const promises = tasks.map((task) => this.spawn(task));
    return Promise.all(promises);
  }

  /**
   * Cancel a running sub-agent.
   */
  cancel(taskId: string): boolean {
    const state = this.agents.get(taskId);
    if (!state || state.status !== "running") return false;

    state.abortController.abort();
    state.status = "cancelled";

    const result: SubAgentResult = {
      taskId,
      status: "cancelled",
      output: "",
      toolCallsMade: state.toolCallsMade,
      turns: state.turns,
      durationMs: Date.now() - state.startTime,
    };

    this.results.set(taskId, result);
    return true;
  }

  // ─── Agent Loop ────────────────────────────────────────────────────────

  /**
   * Run the agent's conversation loop with tool use.
   */
  private async runAgentLoop(
    state: SubAgentState,
    model: ModelInstance
  ): Promise<SubAgentResult> {
    let finalOutput = "";

    while (state.turns < this.maxTurns) {
      if (state.abortController.signal.aborted) {
        throw new Error("Aborted");
      }

      state.turns++;

      // Call the model
      const response = await model.complete(
        {
          system: state.messages.find((m) => m.role === "system")?.content ?? "",
          messages: state.messages.filter((m) => m.role !== "system"),
        },
        {
          tools: this.tools.available(),
          maxTokens: 4096,
        }
      );

      // If model returns tool calls, execute them
      if (response.toolCalls?.length) {
        // Add the assistant's response with tool calls
        state.messages.push({
          role: "assistant",
          content: response.content ?? "",
        });

        for (const toolCall of response.toolCalls) {
          if (state.toolCallsMade >= this.maxToolCalls) {
            state.messages.push({
              role: "system",
              content:
                "[Tool call limit reached. Provide your final answer now.]",
            });
            break;
          }

          if (state.abortController.signal.aborted) {
            throw new Error("Aborted");
          }

          state.toolCallsMade++;

          const result = await this.tools.execute({
            id: `${state.task.id}-${state.toolCallsMade}`,
            tool: toolCall.tool ?? toolCall.name,
            args: toolCall.args ?? toolCall.input,
          } as ToolCall);

          state.messages.push({
            role: "tool" as any,
            content: result.success
              ? result.output
              : `Error: ${result.error}`,
          });
        }

        // Continue the loop to let the model respond to tool results
        continue;
      }

      // No tool calls — model is done
      finalOutput = response.content ?? "";
      break;
    }

    // If we exhausted turns, request final answer
    if (state.turns >= this.maxTurns && !finalOutput) {
      state.messages.push({
        role: "system",
        content: "[Max turns reached. Provide your final answer now.]",
      });

      const finalResponse = await model.complete(
        {
          system: state.messages.find((m) => m.role === "system")?.content ?? "",
          messages: state.messages.filter((m) => m.role !== "system"),
        },
        { maxTokens: 2048 }
      );

      finalOutput = finalResponse.content ?? "[No response]";
    }

    state.status = "completed";

    return {
      taskId: state.task.id,
      status: "completed",
      output: finalOutput,
      toolCallsMade: state.toolCallsMade,
      turns: state.turns,
      durationMs: Date.now() - state.startTime,
    };
  }

  // ─── Status & Info ─────────────────────────────────────────────────────

  /**
   * Get the status of a sub-agent.
   */
  getStatus(taskId: string): SubAgentStatus | null {
    return this.agents.get(taskId)?.status ?? this.results.get(taskId)?.status ?? null;
  }

  /**
   * Get a completed result.
   */
  getResult(taskId: string): SubAgentResult | null {
    return this.results.get(taskId) ?? null;
  }

  /**
   * List all active sub-agents.
   */
  listActive(): Array<{
    taskId: string;
    status: SubAgentStatus;
    turns: number;
    toolCalls: number;
    runningMs: number;
  }> {
    return Array.from(this.agents.values())
      .filter((a) => a.status === "running")
      .map((a) => ({
        taskId: a.task.id,
        status: a.status,
        turns: a.turns,
        toolCalls: a.toolCallsMade,
        runningMs: Date.now() - a.startTime,
      }));
  }

  /**
   * Get stats.
   */
  stats(): {
    totalSpawned: number;
    activeCount: number;
    completedCount: number;
    failedCount: number;
    avgDurationMs: number;
  } {
    const results = Array.from(this.results.values());
    const completed = results.filter((r) => r.status === "completed");
    const failed = results.filter(
      (r) => r.status === "failed" || r.status === "timeout"
    );
    const active = Array.from(this.agents.values()).filter(
      (a) => a.status === "running"
    );

    const avgMs =
      completed.length > 0
        ? completed.reduce((sum, r) => sum + r.durationMs, 0) / completed.length
        : 0;

    return {
      totalSpawned: results.length + active.length,
      activeCount: active.length,
      completedCount: completed.length,
      failedCount: failed.length,
      avgDurationMs: Math.round(avgMs),
    };
  }

  /**
   * Shutdown: cancel all running sub-agents.
   */
  async shutdown(): Promise<void> {
    for (const [id, state] of this.agents) {
      if (state.status === "running") {
        this.cancel(id);
      }
    }
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildSubAgentSystemPrompt(instruction: string): string {
  return `You are a Lyrie sub-agent — an isolated worker spawned for a specific task.

TASK:
${instruction}

RULES:
1. Stay focused on your assigned task.
2. Use tools when you need to read files, execute commands, or search the web.
3. Be concise and report your findings clearly.
4. If you encounter errors, try to recover or report them.
5. Your final message is your result — make it count.

You have access to: exec, read_file, write_file, list_directory, web_search, web_fetch, threat_scan.
All tool calls go through the Shield for security validation.`;
}
