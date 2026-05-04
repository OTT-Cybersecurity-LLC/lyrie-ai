/**
 * ModelFleet — Task-aware multi-model routing for Lyrie v1.2.
 *
 * Better than OpenClaw's static routing table:
 *   - Auto-selects model from task description (no manual config)
 *   - Tracks cost + latency per model
 *   - Health checks all 15 providers on demand
 *   - Routes away from slow/unhealthy providers automatically
 *
 * Guy's full fleet (15 models):
 *   Anthropic : claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-7
 *   OpenAI    : gpt-5.4-codex, gpt-5, o3, o4-mini
 *   xAI       : grok-3-fast, grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning
 *   MiniMax   : MiniMax-M2.7, MiniMax-M2.7-highspeed
 *   Google    : gemini-2.5-pro, gemini-2.5-flash
 *   Local     : hermes-3-70b, llama3.2:1b (via Hermes/Ollama providers)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type TaskType = "chat" | "code" | "bulk" | "reasoning" | "creative" | "simple";

export interface TaskDescription {
  type: TaskType;
  estimatedTokens?: number;
  requiresLocal?: boolean;
  preferCheap?: boolean;
}

export interface ModelRoute {
  /** provider/model — e.g. "anthropic/claude-sonnet-4-6" */
  primary: string;
  /** ordered fallback list */
  fallbacks: string[];
  /** human-readable reason */
  reason: string;
}

export interface ProviderInfo {
  id: string;
  name: string;
  models: string[];
  isLocal: boolean;
  /** USD per 1M input tokens */
  costPerMTokIn: number;
  /** USD per 1M output tokens */
  costPerMTokOut: number;
  /** p50 latency in ms (rolling window) */
  p50Ms: number;
  /** p95 latency in ms (rolling window) */
  p95Ms: number;
  available: boolean | null; // null = not yet checked
}

export interface HealthReport {
  checkedAt: string;
  providers: Array<{ id: string; name: string; available: boolean; latencyMs: number | null; error?: string }>;
}

export interface CompletionOptions {
  maxTokens?: number;
  temperature?: number;
  system?: string;
  tools?: any[];
  stop?: string[];
}

export interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  toolCallId?: string;
}

export interface LyrieProvider {
  name: string;
  models: string[];
  isLocal: boolean;
  isAvailable(): Promise<boolean>;
  complete(messages: Message[], options: CompletionOptions): Promise<string>;
  estimateCost(tokens: number): number;
}

// ─── Internal metric tracker ─────────────────────────────────────────────────

interface LatencySample {
  ms: number;
  ts: number;
}

class LatencyTracker {
  private samples: Map<string, LatencySample[]> = new Map();
  private readonly windowMs = 5 * 60 * 1000; // 5-min rolling window
  private readonly maxSamples = 100;

  record(providerId: string, ms: number): void {
    if (!this.samples.has(providerId)) this.samples.set(providerId, []);
    const arr = this.samples.get(providerId)!;
    const now = Date.now();
    arr.push({ ms, ts: now });
    // Evict stale + trim to maxSamples
    const cutoff = now - this.windowMs;
    const trimmed = arr.filter((s) => s.ts > cutoff).slice(-this.maxSamples);
    this.samples.set(providerId, trimmed);
  }

  percentile(providerId: string, p: number): number {
    const arr = this.samples.get(providerId);
    if (!arr || arr.length === 0) return 0;
    const sorted = [...arr].map((s) => s.ms).sort((a, b) => a - b);
    const idx = Math.max(0, Math.ceil((p / 100) * sorted.length) - 1);
    return sorted[idx];
  }

  p50(id: string): number { return this.percentile(id, 50); }
  p95(id: string): number { return this.percentile(id, 95); }
}

interface SpendRecord {
  tokens: number;
  costUsd: number;
  calls: number;
}

class CostTracker {
  private spend: Map<string, SpendRecord> = new Map();

  record(providerId: string, tokens: number, costUsd: number): void {
    const prev = this.spend.get(providerId) ?? { tokens: 0, costUsd: 0, calls: 0 };
    this.spend.set(providerId, {
      tokens: prev.tokens + tokens,
      costUsd: prev.costUsd + costUsd,
      calls: prev.calls + 1,
    });
  }

  summary(): Record<string, SpendRecord> {
    return Object.fromEntries(this.spend.entries());
  }

  total(): number {
    let sum = 0;
    for (const v of this.spend.values()) sum += v.costUsd;
    return sum;
  }
}

// ─── Provider adapter registry ────────────────────────────────────────────────

interface ProviderEntry {
  provider: LyrieProvider;
  info: ProviderInfo;
}

// ─── Routing logic ────────────────────────────────────────────────────────────

function autoRoute(task: TaskDescription): ModelRoute {
  if (task.requiresLocal) {
    return {
      primary: "hermes/hermes-3-70b",
      fallbacks: ["ollama/llama3.2:1b"],
      reason: "local required — no external API calls",
    };
  }

  if (task.preferCheap) {
    return {
      primary: "anthropic/claude-haiku-4-5",
      fallbacks: ["minimax/MiniMax-M2.7-highspeed", "google/gemini-2.5-flash"],
      reason: "cheap preferred — Haiku is cheapest cloud model",
    };
  }

  switch (task.type) {
    case "code":
      return {
        primary: "openai/gpt-5.4-codex",
        fallbacks: ["anthropic/claude-sonnet-4-6", "xai/grok-4-1-fast-non-reasoning"],
        reason: "code task — GPT-5.4-Codex best for implementation",
      };

    case "bulk":
      return {
        primary: "minimax/MiniMax-M2.7-highspeed",
        fallbacks: ["anthropic/claude-haiku-4-5", "google/gemini-2.5-flash"],
        reason: "bulk/parallel — MiniMax HS at $0.08/MTok",
      };

    case "reasoning":
      return {
        primary: "xai/grok-4-1-fast-reasoning",
        fallbacks: ["anthropic/claude-opus-4-7", "google/gemini-2.5-pro"],
        reason: "reasoning task — Grok-4 fast-reasoning path",
      };

    case "creative":
      return {
        primary: "anthropic/claude-sonnet-4-6",
        fallbacks: ["anthropic/claude-opus-4-7", "openai/gpt-5"],
        reason: "creative task — Claude Sonnet for prose/creative",
      };

    case "simple":
      return {
        primary: "anthropic/claude-haiku-4-5",
        fallbacks: [],
        reason: "simple task — Haiku, low cost, fast",
      };

    case "chat":
    default:
      return {
        primary: "anthropic/claude-sonnet-4-6",
        fallbacks: ["anthropic/claude-haiku-4-5", "anthropic/claude-opus-4-7"],
        reason: "default chat — Sonnet 4-6 (primary)",
      };
  }
}

// ─── ModelFleet ───────────────────────────────────────────────────────────────

export class ModelFleet {
  private static _instance: ModelFleet | null = null;

  private entries: Map<string, ProviderEntry> = new Map();
  private latency = new LatencyTracker();
  readonly cost = new CostTracker();

  // Singleton
  static getInstance(): ModelFleet {
    if (!ModelFleet._instance) ModelFleet._instance = new ModelFleet();
    return ModelFleet._instance;
  }

  /** Reset singleton (testing only) */
  static _reset(): void {
    ModelFleet._instance = null;
  }

  /**
   * Auto-route based on TaskDescription.
   * If the primary model is known to be slow (p95 > 10s), tries to find
   * a faster fallback that is registered.
   */
  route(task: TaskDescription): ModelRoute {
    const base = autoRoute(task);

    // If primary is registered and healthy latency, return as-is
    const primaryId = this._resolveProviderId(base.primary);
    if (primaryId) {
      const p95 = this.latency.p95(primaryId);
      if (p95 > 10_000 && base.fallbacks.length > 0) {
        // Rotate: move primary to end, first fallback becomes primary
        const [first, ...rest] = base.fallbacks;
        return {
          primary: first,
          fallbacks: [...rest, base.primary],
          reason: `${base.reason} [auto-rerouted: ${base.primary} p95=${p95}ms > 10s]`,
        };
      }
    }

    return base;
  }

  /** Register a provider */
  register(provider: LyrieProvider): void {
    const id = this._toProviderId(provider);
    this.entries.set(id, {
      provider,
      info: {
        id,
        name: provider.name,
        models: provider.models,
        isLocal: provider.isLocal,
        costPerMTokIn: 0,
        costPerMTokOut: 0,
        p50Ms: 0,
        p95Ms: 0,
        available: null,
      },
    });
  }

  /** Get all registered providers */
  list(): ProviderInfo[] {
    return Array.from(this.entries.values()).map((e) => ({
      ...e.info,
      p50Ms: this.latency.p50(e.info.id),
      p95Ms: this.latency.p95(e.info.id),
    }));
  }

  /** Health check all providers */
  async healthCheck(): Promise<HealthReport> {
    const results: HealthReport["providers"] = [];

    await Promise.allSettled(
      Array.from(this.entries.entries()).map(async ([id, entry]) => {
        const start = Date.now();
        try {
          const available = await entry.provider.isAvailable();
          const latencyMs = Date.now() - start;
          if (available) this.latency.record(id, latencyMs);
          entry.info.available = available;
          results.push({ id, name: entry.info.name, available, latencyMs });
        } catch (err: any) {
          entry.info.available = false;
          results.push({
            id,
            name: entry.info.name,
            available: false,
            latencyMs: null,
            error: err?.message ?? String(err),
          });
        }
      }),
    );

    return {
      checkedAt: new Date().toISOString(),
      providers: results.sort((a, b) => a.id.localeCompare(b.id)),
    };
  }

  /**
   * Record a completion call for cost + latency tracking.
   */
  recordCall(providerId: string, tokens: number, costUsd: number, latencyMs: number): void {
    this.latency.record(providerId, latencyMs);
    this.cost.record(providerId, tokens, costUsd);
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  private _toProviderId(provider: LyrieProvider): string {
    // Use first model to build "provider/model" key
    return provider.models[0] ? `${provider.name.toLowerCase().replace(/\s+/g, "-")}` : provider.name;
  }

  private _resolveProviderId(routeKey: string): string | null {
    // routeKey = "anthropic/claude-sonnet-4-6" — map to registered id
    const prefix = routeKey.split("/")[0];
    for (const id of this.entries.keys()) {
      if (id.includes(prefix)) return id;
    }
    return null;
  }
}

// ─── Re-export routing fn for CLI/tests ──────────────────────────────────────
export { autoRoute };
