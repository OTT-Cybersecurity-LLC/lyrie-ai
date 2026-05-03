/**
 * SpawnModes — Fork vs Fresh sub-agent spawning + ATP scope narrowing.
 *
 * Ported from Claude Code v2.1.88 AgentTool patterns.
 *
 * Two spawn modes:
 *   - "fork"  → inherits parent context, shares prompt cache, cheaper.
 *   - "fresh" → starts clean with zero parent context, more isolated.
 *
 * ATP trust-chain rule: a sub-agent can ONLY be granted a NARROWER tool
 * scope than its parent. Widening is rejected.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { ModelInstance } from "../engine/model-router";
import type { SubAgentTask } from "./sub-agent";

export type SpawnMode = "fork" | "fresh";

export interface SpawnOptions {
  /** Inherit parent context (fork) or start clean (fresh). */
  mode: SpawnMode;

  /**
   * Tool names this sub-agent is allowed to use.
   * MUST be a subset of the parent's scope (ATP rule).
   * Omit for "inherit parent scope verbatim" (fork only).
   */
  scope?: string[];

  /**
   * Optional model override. Forbidden in fork mode (a different model
   * cannot reuse the parent's prompt cache).
   */
  model?: ModelInstance;

  /**
   * Light-context bootstrap (Haiku-equivalent simple tasks). Skips MCP
   * server discovery, full memory recall, etc.
   */
  lightContext?: boolean;

  /**
   * Filesystem isolation: spawn the sub-agent inside a temp git worktree.
   * Auto-cleaned on completion if no changes made.
   */
  isolation?: "none" | "worktree";

  /**
   * Parent context payload (only used when mode === "fork").
   * The SubAgentManager copies the parent's compacted message history.
   */
  parentContext?: Array<{ role: string; content: string }>;

  /**
   * Parent's allowed-tools scope. Used to enforce ATP trust-chain narrowing.
   */
  parentScope?: string[];
}

/** Thrown when the sub-agent's requested scope widens the parent's. */
export class ScopeWideningError extends Error {
  constructor(extras: string[]) {
    super(
      `Sub-agent scope widening rejected (ATP trust-chain rule). ` +
        `Tools requested but not in parent scope: ${extras.join(", ")}`,
    );
    this.name = "ScopeWideningError";
  }
}

/** Thrown when fork mode is misused (e.g. with a model override). */
export class ForkMisuseError extends Error {
  constructor(reason: string) {
    super(`Fork mode misuse: ${reason}`);
    this.name = "ForkMisuseError";
  }
}

/**
 * Validate a SpawnOptions request and return the resolved scope.
 * Returns the EFFECTIVE allowed-tools list this sub-agent should use.
 */
export function resolveSpawn(opts: SpawnOptions): { scope: string[] } {
  // Rule 1: fork mode forbids model override (cache-sharing requires same model)
  if (opts.mode === "fork" && opts.model) {
    throw new ForkMisuseError(
      "Cannot override model on a fork — a different model can't reuse the parent's prompt cache. Use mode='fresh' instead.",
    );
  }

  // Rule 2: scope MUST be a subset of parent (ATP narrowing)
  let scope: string[];
  if (opts.scope) {
    if (opts.parentScope) {
      const parent = new Set(opts.parentScope);
      const widened = opts.scope.filter((t) => !parent.has(t));
      if (widened.length) throw new ScopeWideningError(widened);
    }
    scope = [...opts.scope];
  } else if (opts.parentScope) {
    // Inherit parent verbatim
    scope = [...opts.parentScope];
  } else {
    // Unscoped (no parent): empty allowlist means "use registry defaults"
    scope = [];
  }

  return { scope };
}

/**
 * Build the system-prompt addendum for a sub-agent, depending on mode.
 *
 * - fork    → reminds the agent it is a continuation; do not re-introduce.
 * - fresh   → briefs as a "smart colleague who just walked into the room".
 */
export function buildSpawnPromptAddendum(opts: SpawnOptions): string {
  if (opts.mode === "fork") {
    return [
      "# Spawn: FORK",
      "You are a forked continuation of the parent agent. You share the parent's prompt cache.",
      "- Do NOT re-introduce yourself or restate context the parent already has.",
      "- Focus narrowly on the sub-task you were spawned for.",
      "- Return ONLY the structured result the parent expects.",
    ].join("\n");
  }
  return [
    "# Spawn: FRESH",
    "You are a freshly-instantiated sub-agent. The parent has briefed you like a smart colleague who just walked into the room.",
    "- You have NOT seen the parent's conversation; only this brief.",
    "- Ask for clarification ONLY by failing fast with a clear error — do not guess.",
    "- Return a structured result the parent can synthesize.",
  ].join("\n");
}

/** Apply a spawn-options object to an existing SubAgentTask. */
export function applySpawnToTask(task: SubAgentTask, opts: SpawnOptions): SubAgentTask {
  const addendum = buildSpawnPromptAddendum(opts);
  const merged: SubAgentTask = {
    ...task,
    instruction: `${task.instruction}\n\n${addendum}`,
  };
  if (opts.mode === "fork" && opts.parentContext?.length) {
    const ctx = opts.parentContext.map((m) => `[${m.role}] ${m.content}`);
    merged.context = [...(task.context ?? []), ...ctx];
  }
  if (opts.model) merged.model = opts.model;
  return merged;
}
