/**
 * Cerebras Provider — Ultra-fast inference for Lyrie Agent.
 *
 * Cerebras uses an OpenAI-compatible API endpoint.
 * Supports: llama-4-scout-17b-16e-instruct, llama-3.3-70b
 *
 * © OTT Cybersecurity LLC / Lyrie.ai
 */

export interface CerebrasConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface CerebrasResponse {
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

export const CEREBRAS_MODELS = [
  "llama-4-scout-17b-16e-instruct",
  "llama-3.3-70b",
] as const;

export type CerebrasModel = (typeof CEREBRAS_MODELS)[number];

export class CerebrasProvider {
  readonly name = "cerebras";
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: CerebrasConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? "https://api.cerebras.ai/v1";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
    }
  ): Promise<CerebrasResponse> {
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
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw Object.assign(new Error(`Cerebras API error: ${res.status} ${text}`), {
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
   * List available Cerebras models (static — Cerebras does not have a
   * dynamic model-list endpoint as of v0.7.0).
   */
  listModels(): CerebrasModel[] {
    return [...CEREBRAS_MODELS];
  }
}
