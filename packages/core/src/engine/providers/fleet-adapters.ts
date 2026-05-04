/**
 * Fleet Adapters — LyrieProvider wrappers for ModelFleet.
 *
 * Each adapter wraps an existing low-level provider class and exposes the
 * simple `LyrieProvider` interface used by ModelFleet.
 *
 * All 15 models across 7 providers + 2 local:
 *   Anthropic : claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-7
 *   OpenAI    : gpt-5.4-codex, gpt-5, o3, o4-mini
 *   xAI       : grok-3-fast, grok-4-1-fast-reasoning, grok-4-1-fast-non-reasoning
 *   MiniMax   : MiniMax-M2.7, MiniMax-M2.7-highspeed
 *   Google    : gemini-2.5-pro, gemini-2.5-flash
 *   Local     : hermes-3-70b (Hermes), llama3.2:1b (Ollama)
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import type { LyrieProvider, Message, CompletionOptions } from "../model-fleet";
import { AnthropicProvider } from "./anthropic";
import { OpenAIProvider } from "./openai";
import { XAIProvider } from "./xai";
import { MiniMaxProvider } from "./minimax";
import { GoogleProvider } from "./google";
import { HermesProvider } from "./hermes";
import { OllamaLyrieProvider } from "./ollama-lyrie";

// ─── Anthropic ────────────────────────────────────────────────────────────────

export class AnthropicFleetProvider implements LyrieProvider {
  readonly name = "Anthropic";
  readonly models = [
    "claude-haiku-4-5",
    "claude-sonnet-4-6",
    "claude-opus-4-7",
  ];
  readonly isLocal = false;
  private inner: AnthropicProvider;

  constructor(apiKey: string) {
    this.inner = new AnthropicProvider({ apiKey });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.inner.complete("claude-haiku-4-5", [{ role: "user", content: "hi" }], { maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const model = "claude-sonnet-4-6";
    const safeMessages = messages
      .filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role as "user" | "assistant", content: m.content }));
    const result = await this.inner.complete(model, safeMessages, {
      system: options.system,
      maxTokens: options.maxTokens ?? 8192,
      temperature: options.temperature,
      tools: options.tools,
    });
    return result.content;
  }

  estimateCost(tokens: number): number {
    // claude-haiku-4-5: $0.25/MTok in
    return (tokens / 1_000_000) * 0.25;
  }
}

// ─── OpenAI ───────────────────────────────────────────────────────────────────

export class OpenAIFleetProvider implements LyrieProvider {
  readonly name = "OpenAI";
  readonly models = [
    "gpt-5.4-codex",
    "gpt-5",
    "o3",
    "o4-mini",
  ];
  readonly isLocal = false;
  private inner: OpenAIProvider;

  constructor(apiKey: string) {
    this.inner = new OpenAIProvider({ apiKey });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.inner.complete("gpt-4o-mini", [{ role: "user", content: "hi" }], { maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const model = "gpt-5.4-codex";
    const msgs = [
      ...(options.system ? [{ role: "system" as const, content: options.system }] : []),
      ...messages,
    ];
    const result = await this.inner.complete(model, msgs, {
      maxTokens: options.maxTokens ?? 8192,
      temperature: options.temperature,
      tools: options.tools,
    });
    return result.content;
  }

  estimateCost(tokens: number): number {
    // gpt-5.4-codex: ~$2/MTok in
    return (tokens / 1_000_000) * 2;
  }
}

// ─── xAI ─────────────────────────────────────────────────────────────────────

export class XAIFleetProvider implements LyrieProvider {
  readonly name = "xAI";
  readonly models = [
    "grok-3-fast",
    "grok-4-1-fast-reasoning",
    "grok-4-1-fast-non-reasoning",
  ];
  readonly isLocal = false;
  private inner: XAIProvider;

  constructor(apiKey: string) {
    this.inner = new XAIProvider({ apiKey });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.inner.complete("grok-3-fast", [{ role: "user", content: "hi" }], { maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const msgs = [
      ...(options.system ? [{ role: "system" as const, content: options.system }] : []),
      ...messages,
    ];
    const result = await this.inner.complete("grok-4-1-fast-reasoning", msgs, {
      maxTokens: options.maxTokens ?? 8192,
      temperature: options.temperature,
      tools: options.tools,
    });
    return result.content;
  }

  estimateCost(tokens: number): number {
    return (tokens / 1_000_000) * 2;
  }
}

// ─── MiniMax ──────────────────────────────────────────────────────────────────

export class MiniMaxFleetProvider implements LyrieProvider {
  readonly name = "MiniMax";
  readonly models = [
    "MiniMax-M2.7",
    "MiniMax-M2.7-highspeed",
  ];
  readonly isLocal = false;
  private inner: MiniMaxProvider;

  constructor(apiKey: string, groupId?: string) {
    this.inner = new MiniMaxProvider({ apiKey, groupId });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.inner.complete("MiniMax-M2.7-highspeed", [{ role: "user", content: "hi" }], { maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const msgs = [
      ...(options.system ? [{ role: "system" as const, content: options.system }] : []),
      ...messages,
    ];
    const result = await this.inner.complete("MiniMax-M2.7-highspeed", msgs, {
      maxTokens: options.maxTokens ?? 8192,
      temperature: options.temperature,
      tools: options.tools,
    });
    return result.content;
  }

  estimateCost(tokens: number): number {
    return (tokens / 1_000_000) * 0.08;
  }
}

// ─── Google ───────────────────────────────────────────────────────────────────

export class GoogleFleetProvider implements LyrieProvider {
  readonly name = "Google";
  readonly models = [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
  ];
  readonly isLocal = false;
  private inner: GoogleProvider;

  constructor(apiKey: string) {
    this.inner = new GoogleProvider({ apiKey });
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.inner.complete("gemini-2.5-flash", [{ role: "user", content: "hi" }], { maxTokens: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const msgs = messages.filter((m) => m.role !== "system");
    const result = await this.inner.complete("gemini-2.5-flash", msgs, {
      systemInstruction: options.system,
      maxTokens: options.maxTokens ?? 8192,
      temperature: options.temperature,
    });
    return result.content;
  }

  estimateCost(tokens: number): number {
    return (tokens / 1_000_000) * 0.075;
  }
}

// ─── Hermes (local) ───────────────────────────────────────────────────────────

export class HermesFleetProvider implements LyrieProvider {
  readonly name = "Hermes";
  readonly models = ["hermes-3-70b"];
  readonly isLocal = true;
  private inner: HermesProvider;

  constructor(endpoint?: string) {
    this.inner = new HermesProvider({ endpoint });
  }

  async isAvailable(): Promise<boolean> {
    try {
      return (await this.inner.health?.()) ?? false;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const lyrieMessages = messages.map((m) => ({ role: m.role, content: m.content }));
    const result = await this.inner.complete(lyrieMessages as any, {
      system: options.system,
      maxTokens: options.maxTokens ?? 8192,
    });
    return result.content;
  }

  estimateCost(_tokens: number): number {
    return 0;
  }
}

// ─── Ollama (local) ───────────────────────────────────────────────────────────

export class OllamaFleetProvider implements LyrieProvider {
  readonly name = "Ollama";
  readonly models = ["llama3.2:1b"];
  readonly isLocal = true;
  private inner: OllamaLyrieProvider;

  constructor(endpoint?: string) {
    this.inner = new OllamaLyrieProvider({ endpoint, defaultModel: "llama3.2:1b", models: ["llama3.2:1b"] });
  }

  async isAvailable(): Promise<boolean> {
    try {
      return (await this.inner.health?.()) ?? false;
    } catch {
      return false;
    }
  }

  async complete(messages: Message[], options: CompletionOptions): Promise<string> {
    const result = await this.inner.complete(messages as any, {
      system: options.system,
      maxTokens: options.maxTokens ?? 4096,
    });
    return result.content;
  }

  estimateCost(_tokens: number): number {
    return 0;
  }
}

// ─── Factory ──────────────────────────────────────────────────────────────────

export interface FleetConfig {
  anthropicApiKey?: string;
  openaiApiKey?: string;
  xaiApiKey?: string;
  minimaxApiKey?: string;
  minimaxGroupId?: string;
  googleApiKey?: string;
  hermesEndpoint?: string;
  ollamaEndpoint?: string;
  skipLocal?: boolean;
}

export function buildFleetProviders(cfg: FleetConfig = {}): LyrieProvider[] {
  const providers: LyrieProvider[] = [];

  if (cfg.anthropicApiKey) providers.push(new AnthropicFleetProvider(cfg.anthropicApiKey));
  if (cfg.openaiApiKey) providers.push(new OpenAIFleetProvider(cfg.openaiApiKey));
  if (cfg.xaiApiKey) providers.push(new XAIFleetProvider(cfg.xaiApiKey));
  if (cfg.minimaxApiKey) providers.push(new MiniMaxFleetProvider(cfg.minimaxApiKey, cfg.minimaxGroupId));
  if (cfg.googleApiKey) providers.push(new GoogleFleetProvider(cfg.googleApiKey));

  if (!cfg.skipLocal) {
    providers.push(new HermesFleetProvider(cfg.hermesEndpoint));
    providers.push(new OllamaFleetProvider(cfg.ollamaEndpoint));
  }

  return providers;
}
