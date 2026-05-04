/**
 * SubagentRunner — LLM-callable sub-agent orchestration for Lyrie v1.1.
 *
 * Gives the Lyrie engine the equivalent of OpenClaw's `sessions_spawn`:
 * spawn an isolated child agent mid-conversation, wait for its result,
 * and continue.  Two context modes are supported:
 *
 *   isolated — fresh LyrieEngine with no parent history
 *   fork     — parent context injected as system-level "parent context"
 *
 * Multiple sub-agents can run in parallel via `runParallel`.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { ShieldManager } from "../engine/shield-manager";
import { ModelRouter } from "../engine/model-router";
import { MemoryCore } from "../memory/memory-core";
import { LyrieEngine } from "../engine/lyrie-engine";

// ─── Public types ─────────────────────────────────────────────────────────────

export interface SubagentOptions {
  /** Model ID override, e.g. "claude-opus-4-6". Defaults to parent model. */
  model?: string;
  /** Max seconds to wait before aborting (default: 300). */
  timeoutSeconds?: number;
  /**
   * "isolated" — fresh engine, no parent context.
   * "fork"     — parent context injected as system message.
   */
  context?: "isolated" | "fork";
  /** Inject this text as parent context (only used when context="fork"). */
  parentContext?: string;
}

export interface SubagentResult {
  success: boolean;
  /** The sub-agent's final response text. */
  output: string;
  durationMs: number;
  /** Model ID that handled the sub-agent. */
  model: string;
  error?: string;
}

export interface SubagentTask {
  task: string;
  options?: SubagentOptions;
}

// ─── SubagentRunner ───────────────────────────────────────────────────────────

export class SubagentRunner {
  /**
   * Run a task as an isolated sub-agent.
   * Returns the sub-agent's final response.
   */
  async run(task: string, options: SubagentOptions = {}): Promise<SubagentResult> {
    const startTime = Date.now();
    const timeoutMs = (options.timeoutSeconds ?? 300) * 1000;
    const modelId = options.model;

    let engine: LyrieEngine | null = null;

    try {
      engine = await this.createEngine(modelId);

      // Compose the message content
      let content = task;
      if (options.context === "fork" && options.parentContext) {
        content =
          `[Parent Context]\n${options.parentContext}\n\n[Task]\n${task}`;
      }

      // Race against timeout
      const result = await Promise.race([
        engine.process({
          role: "user",
          content,
          source: "subagent",
          timestamp: Date.now(),
        }),
        this.rejectAfter(timeoutMs, `Sub-agent timed out after ${options.timeoutSeconds ?? 300}s`),
      ]) as Awaited<ReturnType<LyrieEngine["process"]>>;

      return {
        success: true,
        output: result.message.content,
        durationMs: Date.now() - startTime,
        model: result.model,
      };
    } catch (err: any) {
      return {
        success: false,
        output: "",
        durationMs: Date.now() - startTime,
        model: modelId ?? "unknown",
        error: err?.message ?? String(err),
      };
    } finally {
      if (engine) {
        engine.shutdown().catch(() => undefined);
      }
    }
  }

  /**
   * Run multiple sub-agents in parallel.
   * Returns an array of results in the same order as the input tasks.
   */
  async runParallel(tasks: SubagentTask[]): Promise<SubagentResult[]> {
    return Promise.all(
      tasks.map((t) => this.run(t.task, t.options ?? {})),
    );
  }

  // ─── Internals ─────────────────────────────────────────────────────────

  /**
   * Build a minimal, isolated LyrieEngine suitable for a sub-agent turn.
   * No cron scheduler; no memory persistence beyond the single request.
   */
  private async createEngine(modelId?: string): Promise<LyrieEngine> {
    const shield = new ShieldManager();
    await shield.initialize();

    // Use a per-run temp directory so each sub-agent gets its own ephemeral
    // SQLite DB and does not pollute the parent's memory store.
    const tmpDir = `/tmp/lyrie-subagent-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const memory = new MemoryCore(tmpDir);
    await memory.initialize();

    const router = new ModelRouter();
    await router.initialize(this.routerConfig(modelId));

    const engine = new LyrieEngine({
      shield,
      memory,
      router,
      enableCron: false,
      maxToolTurns: 10,
      maxToolCalls: 30,
    });

    await engine.initialize();
    return engine;
  }

  /**
   * Build a minimal router config for the sub-agent.
   * Picks up API keys from the environment so the sub-agent can call models.
   */
  private routerConfig(_preferredModelId?: string) {
    // RouterConfig only carries API keys; model selection happens via route().
    return {
      anthropicApiKey: process.env.ANTHROPIC_API_KEY,
      openaiApiKey: process.env.OPENAI_API_KEY,
      googleApiKey: process.env.GOOGLE_AI_API_KEY ?? process.env.GEMINI_API_KEY,
      xaiApiKey: process.env.XAI_API_KEY,
    };
  }

  /** Returns a promise that rejects after `ms` milliseconds. */
  private rejectAfter(ms: number, message: string): Promise<never> {
    return new Promise((_, reject) =>
      setTimeout(() => reject(new Error(message)), ms),
    );
  }
}

// ─── Singleton export ─────────────────────────────────────────────────────────

/** Shared default runner. Tools and the CLI use this instance. */
export const defaultSubagentRunner = new SubagentRunner();
