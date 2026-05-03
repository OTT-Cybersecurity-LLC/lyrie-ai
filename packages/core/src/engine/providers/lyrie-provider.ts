/**
 * LyrieProvider — The Independence Interface.
 *
 * EVERY model provider in Lyrie v1.0.0 must implement this interface.
 * No part of the engine, agents, or tools is allowed to import a specific
 * provider class directly. All provider access goes through the registry.
 *
 * This is the foundation of Lyrie's independence layer:
 *   `lyrie --provider hermes  --model nous-hermes3:70b` (zero external deps)
 *   `lyrie --provider ollama  --model llama3.2:70b`    (local first)
 *   `lyrie --provider openai  --model gpt-5.4`         (external opt-in)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── Interface ───────────────────────────────────────────────────────────────

export interface LyrieMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  /** Tool-call id this message responds to (for role=tool). */
  toolCallId?: string;
  /** Optional name (used by some providers for tool messages). */
  name?: string;
}

export interface LyrieToolDef {
  name: string;
  description: string;
  parameters: {
    type: "object";
    properties: Record<string, any>;
    required: string[];
  };
}

export interface LyrieToolCall {
  id: string;
  name: string;
  /** JSON object with the tool arguments. */
  arguments: Record<string, any>;
}

export interface LyrieCompletionOptions {
  /** Optional system prompt; providers that don't have a system role inline it. */
  system?: string;
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  /** Tool definitions in Lyrie's neutral format; providers translate as needed. */
  tools?: LyrieToolDef[];
  /** Stop sequences. */
  stop?: string[];
}

export interface LyrieUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
}

export interface LyrieCompletion {
  /** Free-form text content (may be empty if tool calls are present). */
  content: string;
  /** Parsed tool calls (provider-specific formats are normalized). */
  toolCalls: LyrieToolCall[];
  /** Provider-reported reason for stopping ("end_turn" | "tool_use" | "max_tokens" | "stop" | …). */
  stopReason: string;
  /** Model id that actually responded. */
  model: string;
  usage: LyrieUsage;
}

export interface LyrieProvider {
  /** Stable id used in config (e.g. "ollama", "hermes", "lmstudio", "anthropic"). */
  readonly id: string;
  /** Human-readable name. */
  readonly name: string;
  /** API endpoint. For local providers this is a localhost URL. */
  readonly endpoint: string;
  /** Env var name for the API key (NEVER the actual key). undefined if local. */
  readonly apiKeyEnv?: string;
  /** Models supported by this provider. May be a curated subset. */
  readonly models: string[];
  /** The default model when no model is specified. */
  readonly defaultModel: string;
  /** True ⇒ this provider does NOT make any external network calls. */
  readonly isLocal: boolean;
  /** Provider supports the agentic tool-use loop. */
  readonly supportsToolUse: boolean;
  /** Provider supports OpenAI-style function calling JSON. */
  readonly supportsFunctionCalling: boolean;
  /** Maximum context window across this provider's models. */
  readonly maxContextTokens: number;

  /** Run a completion. Implementations MUST normalize output into LyrieCompletion. */
  complete(
    model: string,
    messages: LyrieMessage[],
    options?: LyrieCompletionOptions,
  ): Promise<LyrieCompletion>;

  /**
   * Optional health probe. Returns true if the provider is reachable AND
   * returns at least one model. Used by `lyrie doctor` and the daemon
   * pre-flight check.
   */
  health?(): Promise<boolean>;
}

// ─── Registry ────────────────────────────────────────────────────────────────

export class LyrieProviderRegistry {
  private providers: Map<string, LyrieProvider> = new Map();

  // ─── Singleton ─────────────────────────────────────────────────────────────

  private static _instance: LyrieProviderRegistry | undefined;

  /** Return the process-wide singleton registry. */
  static getInstance(): LyrieProviderRegistry {
    if (!LyrieProviderRegistry._instance) {
      LyrieProviderRegistry._instance = new LyrieProviderRegistry();
    }
    return LyrieProviderRegistry._instance;
  }

  /** Replace the singleton (for testing or bootstrap). */
  static setInstance(reg: LyrieProviderRegistry): void {
    LyrieProviderRegistry._instance = reg;
  }

  register(provider: LyrieProvider): void {
    this.providers.set(provider.id, provider);
  }

  get(id: string): LyrieProvider | undefined {
    return this.providers.get(id);
  }

  has(id: string): boolean {
    return this.providers.has(id);
  }

  list(): LyrieProvider[] {
    return [...this.providers.values()];
  }

  /** All providers that make zero external API calls. */
  listLocal(): LyrieProvider[] {
    return this.list().filter((p) => p.isLocal);
  }

  /** First reachable local provider (for `requireLocalProvider` mode). */
  async firstReachableLocal(): Promise<LyrieProvider | undefined> {
    for (const p of this.listLocal()) {
      if (!p.health) return p;
      try {
        if (await p.health()) return p;
      } catch {
        // try next
      }
    }
    return undefined;
  }
}

// ─── External-call guard ─────────────────────────────────────────────────────

export class ExternalCallBlocked extends Error {
  constructor(providerId: string) {
    super(
      `Provider "${providerId}" requires external API calls but ` +
        `requireLocalProvider=true. Refusing to leak data outside the host.`,
    );
    this.name = "ExternalCallBlocked";
  }
}

/**
 * Wraps a provider to refuse calls when `requireLocalProvider` is true and the
 * provider is non-local. Used at config-resolution time, NOT inside the
 * provider itself, so we can swap in a local fallback transparently.
 */
export function assertProviderAllowed(
  provider: LyrieProvider,
  requireLocalProvider: boolean,
): void {
  if (requireLocalProvider && !provider.isLocal) {
    throw new ExternalCallBlocked(provider.id);
  }
}
