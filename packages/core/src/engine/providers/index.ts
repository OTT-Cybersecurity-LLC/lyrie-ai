/**
 * Provider Registry — All model providers for Lyrie Agent.
 * 
 * Lyrie is model-agnostic. Add any provider by implementing the Provider interface.
 * 
 * Built-in providers:
 * - Anthropic (Claude Opus 4.6, Sonnet 4.6, Haiku 4.5)
 * - OpenAI (GPT-5.4, GPT-5.4 Codex, o3, o4-mini)
 * - Google (Gemini 3.1 Pro, Gemini 3.1 Flash)
 * - xAI (Grok 4.20, Grok 4.1 Fast)
 * - MiniMax (M2.7, M2.7 HighSpeed)
 * - Local (Ollama — Qwen, Gemma, Llama, DeepSeek)
 */

export { AnthropicProvider } from "./anthropic";
export { OpenAIProvider } from "./openai";
export { GoogleProvider } from "./google";
export { XAIProvider } from "./xai";
export { MiniMaxProvider } from "./minimax";
export { OllamaProvider } from "./ollama";

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
