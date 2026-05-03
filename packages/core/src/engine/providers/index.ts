/**
 * Provider Registry — All model providers for Lyrie Agent.
 *
 * Lyrie v1.0.0 is **provider-independent**. The engine, agents, and tools
 * never import a specific provider class. All access flows through the
 * `LyrieProvider` interface and the `LyrieProviderRegistry`.
 *
 * Local-first providers (no external API calls):
 *   - Ollama        (default endpoint http://localhost:11434)
 *   - LM Studio     (default endpoint http://localhost:1234/v1)
 *   - Hermes        (NousResearch Hermes-3, the canonical agentic model)
 *
 * Optional remote providers (each one is opt-in, never required):
 *   - Anthropic, OpenAI, Google, xAI, MiniMax, DeepSeek, Cerebras, OpenRouter
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

// ─── New Independence Layer ─────────────────────────────────────────────────

export {
  LyrieProviderRegistry,
  ExternalCallBlocked,
  assertProviderAllowed,
} from "./lyrie-provider";
export type {
  LyrieProvider,
  LyrieMessage,
  LyrieToolDef,
  LyrieToolCall,
  LyrieCompletion,
  LyrieCompletionOptions,
  LyrieUsage,
} from "./lyrie-provider";

export { OllamaLyrieProvider } from "./ollama-lyrie";
export type { OllamaLyrieConfig } from "./ollama-lyrie";

export { LMStudioProvider } from "./lmstudio";
export type { LMStudioConfig } from "./lmstudio";

export { HermesProvider } from "./hermes";
export type { HermesConfig } from "./hermes";

// ─── Legacy provider classes (kept for compatibility) ───────────────────────

export { AnthropicProvider } from "./anthropic";
export { OpenAIProvider } from "./openai";
export { GoogleProvider } from "./google";
export { XAIProvider } from "./xai";
export { MiniMaxProvider } from "./minimax";
export { OllamaProvider } from "./ollama";
export { CerebrasProvider, CEREBRAS_MODELS } from "./cerebras";
export { OpenRouterProvider } from "./openrouter";
export { DeepSeekProvider, DEEPSEEK_MODELS } from "./deepseek";
export type { CerebrasConfig, CerebrasResponse, CerebrasModel } from "./cerebras";
export type { OpenRouterConfig, OpenRouterResponse, OpenRouterModel } from "./openrouter";
export type { DeepSeekConfig, DeepSeekResponse, DeepSeekModel } from "./deepseek";

// ─── Legacy untyped registry (do not extend; use LyrieProviderRegistry) ─────

export interface Provider {
  name: string;
  complete(model: string, messages: any[], options?: any): Promise<any>;
}

export interface ProviderRegistry {
  providers: Map<string, Provider>;
  register(name: string, provider: Provider): void;
  get(name: string): Provider | undefined;
}

export function createProviderRegistry(): ProviderRegistry {
  const providers = new Map<string, Provider>();
  return {
    providers,
    register(name: string, provider: Provider) {
      providers.set(name, provider);
    },
    get(name: string) {
      return providers.get(name);
    },
  };
}

// ─── Bootstrap helpers ──────────────────────────────────────────────────────

import { LyrieProviderRegistry, LyrieProvider } from "./lyrie-provider";
import { OllamaLyrieProvider } from "./ollama-lyrie";
import { LMStudioProvider } from "./lmstudio";
import { HermesProvider } from "./hermes";

export interface BootstrapOptions {
  /** Register Ollama (local). Default: true. */
  ollama?: boolean;
  /** Register LM Studio (local). Default: true. */
  lmstudio?: boolean;
  /** Register Hermes (NousResearch). Default: true. */
  hermes?: boolean;
  /** Optional adapters for remote providers (opt-in). */
  remote?: LyrieProvider[];
  /** Override config per provider. */
  config?: {
    ollama?: ConstructorParameters<typeof OllamaLyrieProvider>[0];
    lmstudio?: ConstructorParameters<typeof LMStudioProvider>[0];
    hermes?: ConstructorParameters<typeof HermesProvider>[0];
  };
}

/**
 * Build a registry seeded with the default local-first providers.
 *
 * After bootstrap, callers can optionally `register()` cloud providers
 * (Anthropic, OpenAI, …) by wrapping them as LyrieProvider adapters.
 */
export function bootstrapLyrieProviders(opts: BootstrapOptions = {}): LyrieProviderRegistry {
  const reg = new LyrieProviderRegistry();
  if (opts.ollama !== false) reg.register(new OllamaLyrieProvider(opts.config?.ollama));
  if (opts.lmstudio !== false) reg.register(new LMStudioProvider(opts.config?.lmstudio));
  if (opts.hermes !== false) reg.register(new HermesProvider(opts.config?.hermes));
  for (const p of opts.remote ?? []) reg.register(p);
  return reg;
}
