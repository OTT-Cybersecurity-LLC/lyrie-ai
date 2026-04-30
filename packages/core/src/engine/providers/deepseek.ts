/**
 * DeepSeek Provider — DeepSeek V4 Pro + Flash for Lyrie Agent.
 *
 * DeepSeek V4 is an OpenAI-compatible API with two flagship models:
 *   - deepseek-v4-pro   : 1.6T-parameter MoE, 1M context, Thinking + Non-Thinking modes
 *   - deepseek-v4-flash : Fast/lightweight variant, 1M context, same modes
 *
 * API base: https://api.deepseek.com
 * Auth: DEEPSEEK_API_KEY environment variable
 *
 * Thinking mode: set `thinking: true` in options to activate chain-of-thought
 * (maps to `enable_thinking: true` in the DeepSeek request body).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export interface DeepSeekConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface DeepSeekResponse {
  content: string;
  model: string;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  toolCalls?: any[];
  finishReason: string;
  /** Present when thinking mode is active */
  thinking?: string;
}

export const DEEPSEEK_MODELS = [
  "deepseek-v4-pro",
  "deepseek-v4-flash",
] as const;

export type DeepSeekModel = (typeof DEEPSEEK_MODELS)[number];

export class DeepSeekProvider {
  readonly name = "deepseek";
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: DeepSeekConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl ?? "https://api.deepseek.com";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
      /** Enable DeepSeek Thinking mode (chain-of-thought) */
      thinking?: boolean;
    }
  ): Promise<DeepSeekResponse> {
    const body: Record<string, any> = {
      model,
      max_tokens: options?.maxTokens ?? 8192,
      messages,
    };

    if (options?.tools?.length) body.tools = options.tools;
    if (options?.temperature !== undefined) body.temperature = options.temperature;
    if (options?.thinking) body.enable_thinking = true;

    const res = await fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw Object.assign(
        new Error(`DeepSeek API error: ${res.status} ${text}`),
        { status: res.status }
      );
    }

    const data = await res.json() as any;
    const choice = data.choices?.[0];
    const message = choice?.message ?? {};

    return {
      content: message.content ?? "",
      model: data.model ?? model,
      usage: {
        promptTokens: data.usage?.prompt_tokens ?? 0,
        completionTokens: data.usage?.completion_tokens ?? 0,
        totalTokens: data.usage?.total_tokens ?? 0,
      },
      toolCalls: message.tool_calls,
      finishReason: choice?.finish_reason ?? "stop",
      thinking: message.reasoning_content ?? undefined,
    };
  }

  /**
   * List available DeepSeek models.
   */
  listModels(): DeepSeekModel[] {
    return [...DEEPSEEK_MODELS];
  }
}
