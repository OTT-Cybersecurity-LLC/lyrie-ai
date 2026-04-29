/**
 * OpenRouter Provider — 100+ models via a single OpenAI-compatible endpoint.
 *
 * OpenRouter exposes a /models endpoint to fetch available models dynamically.
 * Falls back to a hard-coded list if the API is unreachable.
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

export interface OpenRouterConfig {
  apiKey: string;
  baseUrl?: string;
  /** Your site URL (shown in OpenRouter analytics). */
  siteUrl?: string;
  /** Your app name (shown in OpenRouter analytics). */
  appName?: string;
}

export interface OpenRouterResponse {
  content: string;
  model: string;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  toolCalls?: any[];
  finishReason: string;
}

export interface OpenRouterModel {
  id: string;
  name: string;
  description?: string;
  contextLength?: number;
  pricing?: {
    prompt: string;
    completion: string;
  };
}

/** Fallback model list used when /models is unreachable. */
const FALLBACK_MODELS: OpenRouterModel[] = [
  { id: "anthropic/claude-sonnet-4-6", name: "Claude Sonnet 4.6" },
  { id: "anthropic/claude-opus-4-6", name: "Claude Opus 4.6" },
  { id: "openai/gpt-4o", name: "GPT-4o" },
  { id: "google/gemini-pro-1.5", name: "Gemini Pro 1.5" },
  { id: "meta-llama/llama-3.3-70b-instruct", name: "Llama 3.3 70B" },
  { id: "mistralai/mistral-large", name: "Mistral Large" },
  { id: "qwen/qwen-2.5-72b-instruct", name: "Qwen 2.5 72B" },
  { id: "deepseek/deepseek-r1", name: "DeepSeek R1" },
];

export class OpenRouterProvider {
  readonly name = "openrouter";
  readonly dynamicModels = true;

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly siteUrl: string;
  private readonly appName: string;

  /** Cached model list (refreshed on demand). */
  private _modelCache: OpenRouterModel[] | null = null;
  private _cacheTime = 0;
  private static readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

  constructor(config: OpenRouterConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? "https://openrouter.ai/api/v1";
    this.siteUrl = config.siteUrl ?? "https://lyrie.ai";
    this.appName = config.appName ?? "Lyrie Agent";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
    }
  ): Promise<OpenRouterResponse> {
    const body: any = {
      model,
      max_tokens: options?.maxTokens ?? 8192,
      messages,
    };

    if (options?.tools?.length) body.tools = options.tools;
    if (options?.temperature !== undefined) body.temperature = options.temperature;

    const res = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        "HTTP-Referer": this.siteUrl,
        "X-Title": this.appName,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw Object.assign(new Error(`OpenRouter API error: ${res.status} ${text}`), {
        status: res.status,
      });
    }

    const data = await res.json() as any;
    const choice = data.choices?.[0];

    return {
      content: choice?.message?.content ?? "",
      model: data.model ?? model,
      usage: {
        promptTokens: data.usage?.prompt_tokens ?? 0,
        completionTokens: data.usage?.completion_tokens ?? 0,
        totalTokens: data.usage?.total_tokens ?? 0,
      },
      toolCalls: choice?.message?.tool_calls,
      finishReason: choice?.finish_reason ?? "stop",
    };
  }

  /**
   * Fetch the model list from OpenRouter's /models endpoint.
   * Results are cached for 5 minutes.
   */
  async listModels(): Promise<OpenRouterModel[]> {
    const now = Date.now();

    if (this._modelCache && now - this._cacheTime < OpenRouterProvider.CACHE_TTL_MS) {
      return this._modelCache;
    }

    try {
      const res = await fetch(`${this.baseUrl}/models`, {
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "HTTP-Referer": this.siteUrl,
          "X-Title": this.appName,
        },
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = await res.json() as { data?: any[] };
      const models: OpenRouterModel[] = (data.data ?? []).map((m: any) => ({
        id: m.id,
        name: m.name ?? m.id,
        description: m.description,
        contextLength: m.context_length,
        pricing: m.pricing
          ? { prompt: String(m.pricing.prompt), completion: String(m.pricing.completion) }
          : undefined,
      }));

      this._modelCache = models;
      this._cacheTime = now;
      return models;
    } catch {
      // Fallback on network error
      return FALLBACK_MODELS;
    }
  }

  /** Invalidate the model cache (useful in tests). */
  clearModelCache(): void {
    this._modelCache = null;
    this._cacheTime = 0;
  }
}
