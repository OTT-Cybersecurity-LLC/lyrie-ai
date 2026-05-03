/**
 * ToolRegistry — Deferred tool loading (Claude Code v2.1.88 ToolSearchTool pattern).
 *
 * Problem: with 50+ tools registered, full schemas total ~25k tokens that
 * are paid on EVERY turn even if zero tools are called.
 *
 * Solution: only the tool NAME + 1-line description appears in the system
 * prompt. Schemas are fetched on-demand by a `tool_search` tool call.
 *
 * Empirical reduction: ~15–20k tokens per turn for power users with 50+ tools.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { LyrieToolDef } from "../engine/providers/lyrie-provider";
import type { Tool } from "./tool-executor";

export interface DeferredToolEntry {
  name: string;
  description: string;
  /** True if this tool's schema is NOT included in the initial prompt. */
  isDeferred: boolean;
}

export interface ToolRegistryConfig {
  /**
   * Tools matching these names are NEVER deferred (always full schema).
   * Use for a tiny core (e.g. `tool_search`, `agent_spawn`).
   */
  alwaysLoaded?: string[];
  /**
   * Maximum schemas to return in a single tool_search call.
   * Defaults to 8.
   */
  maxSearchResults?: number;
}

export class ToolRegistry {
  private tools: Map<string, Tool> = new Map();
  private alwaysLoaded: Set<string>;
  private maxSearchResults: number;
  /** Names that the agent has already fetched the schema for (per session). */
  private hydrated: Set<string> = new Set();

  constructor(cfg: ToolRegistryConfig = {}) {
    this.alwaysLoaded = new Set(cfg.alwaysLoaded ?? ["tool_search", "agent_spawn"]);
    this.maxSearchResults = cfg.maxSearchResults ?? 8;
  }

  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  registerAll(tools: Tool[]): void {
    for (const t of tools) this.register(t);
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  get(name: string): Tool | undefined {
    return this.tools.get(name);
  }

  size(): number {
    return this.tools.size;
  }

  /**
   * The DEFERRED list — what gets injected into the system prompt initially.
   * Only NAME + short description. No parameter schema.
   */
  getDeferredList(): DeferredToolEntry[] {
    return [...this.tools.values()].map((t) => ({
      name: t.name,
      description: t.description.slice(0, 120),
      isDeferred: !this.alwaysLoaded.has(t.name),
    }));
  }

  /**
   * The schemas the agent should be able to call THIS TURN.
   *
   * - Always-loaded tools (the core)
   * - Tools the agent has already requested via tool_search this session
   */
  getActiveSchemas(): LyrieToolDef[] {
    const out: LyrieToolDef[] = [];
    for (const tool of this.tools.values()) {
      if (this.alwaysLoaded.has(tool.name) || this.hydrated.has(tool.name)) {
        out.push(this.buildSchema(tool));
      }
    }
    return out;
  }

  /** Fetch a single tool schema on demand. Marks it as hydrated. */
  fetchSchema(name: string): LyrieToolDef | undefined {
    const tool = this.tools.get(name);
    if (!tool) return undefined;
    this.hydrated.add(name);
    return this.buildSchema(tool);
  }

  /**
   * Search by query. Returns top-K matching schemas (and hydrates them).
   * Simple substring + token-overlap scoring; good enough for now.
   */
  search(query: string, limit = this.maxSearchResults): LyrieToolDef[] {
    const q = query.toLowerCase();
    const tokens = q.split(/\s+/).filter(Boolean);
    const scored: { score: number; tool: Tool }[] = [];
    for (const tool of this.tools.values()) {
      const hay = `${tool.name} ${tool.description}`.toLowerCase();
      let score = 0;
      if (hay.includes(q)) score += 10;
      for (const t of tokens) if (hay.includes(t)) score += 1;
      if (score > 0) scored.push({ score, tool });
    }
    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, limit).map((s) => {
      this.hydrated.add(s.tool.name);
      return this.buildSchema(s.tool);
    });
  }

  /** Reset hydration (e.g. for a new session). */
  resetHydration(): void {
    this.hydrated.clear();
  }

  /** Approximate token cost of the deferred section (NAMES only). */
  estimateDeferredTokens(): number {
    // ~3 tokens per tool entry on average.
    return this.tools.size * 3;
  }

  /** Approximate cost if we eagerly loaded all schemas. */
  estimateEagerTokens(): number {
    // ~500 tokens per schema on average.
    return this.tools.size * 500;
  }

  private buildSchema(tool: Tool): LyrieToolDef {
    const properties: Record<string, any> = {};
    const required: string[] = [];
    for (const [k, p] of Object.entries(tool.parameters)) {
      properties[k] = {
        type: p.type,
        description: p.description,
        ...(p.enum ? { enum: p.enum } : {}),
        ...(p.default !== undefined ? { default: p.default } : {}),
      };
      if (p.required) required.push(k);
    }
    return {
      name: tool.name,
      description: tool.description,
      parameters: { type: "object", properties, required },
    };
  }
}
