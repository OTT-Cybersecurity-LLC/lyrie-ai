/**
 * MiniMax Provider — Ultra-cheap bulk model provider for Lyrie Agent.
 *
 * Supports: MiniMax M2.7, MiniMax M2.7 HighSpeed
 * Used for: Bulk operations, content generation, batch tasks
 * Cost: $0.08/MTok in — cheapest quality model available
 *
 * API: OpenAI-compatible format
 * Base URL: https://api.minimax.io
 *
 * OTT Cybersecurity LLC
 */

export interface MiniMaxConfig {
  apiKey: string;
  groupId?: string;
  baseUrl?: string;
}

export interface MiniMaxMessage {
  role: "system" | "user" | "assistant";
  content: string;
  name?: string;
}

export interface MiniMaxUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface MiniMaxResponse {
  content: string;
  model: string;
  usage: MiniMaxUsage;
  toolCalls?: MiniMaxToolCall[];
  finishReason: string;
  requestId?: string;
}

export interface MiniMaxToolCall {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
}

export interface MiniMaxCompletionOptions {
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  tools?: any[];
  toolChoice?: "auto" | "none" | { type: "function"; function: { name: string } };
  stream?: false; // Lyrie uses non-streaming by default
  frequencyPenalty?: number;
  presencePenalty?: number;
}

// Available MiniMax models
export const MINIMAX_MODELS = {
  M2_7: "MiniMax-M2-ultra",
  M2_7_HIGH_SPEED: "MiniMax-M2-flash",
  M2_7_REASONING: "MiniMax-M2-pro",
} as const;

export type MiniMaxModel = typeof MINIMAX_MODELS[keyof typeof MINIMAX_MODELS];

export class MiniMaxProvider {
  private apiKey: string;
  private groupId: string | undefined;
  private baseUrl: string;

  constructor(config: MiniMaxConfig) {
    if (!config.apiKey) {
      throw new Error("MiniMax API key is required. Set MINIMAX_API_KEY in .env");
    }
    this.apiKey = config.apiKey;
    this.groupId = config.groupId;
    this.baseUrl = config.baseUrl || "https://api.minimax.io";
  }

  async complete(
    model: string,
    messages: MiniMaxMessage[],
    options: MiniMaxCompletionOptions = {}
  ): Promise<MiniMaxResponse> {
    const body: Record<string, any> = {
      model,
      messages,
      max_tokens: options.maxTokens ?? 8192,
      temperature: options.temperature ?? 0.7,
      top_p: options.topP ?? 1.0,
      stream: false,
    };

    if (options.tools?.length) {
      body.tools = options.tools;
      body.tool_choice = options.toolChoice ?? "auto";
    }

    if (options.frequencyPenalty !== undefined) {
      body.frequency_penalty = options.frequencyPenalty;
    }

    if (options.presencePenalty !== undefined) {
      body.presence_penalty = options.presencePenalty;
    }

    // MiniMax requires group_id for some endpoints
    const url = this.groupId
      ? `${this.baseUrl}/v1/text/chatcompletion_v2?GroupId=${this.groupId}`
      : `${this.baseUrl}/v1/chat/completions`;

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`MiniMax API error (${response.status}): ${errorText}`);
    }

    const data = await response.json() as any;

    // Handle MiniMax error codes in 200 responses
    if (data.base_resp?.status_code && data.base_resp.status_code !== 0) {
      throw new Error(
        `MiniMax API error (${data.base_resp.status_code}): ${data.base_resp.status_msg}`
      );
    }

    const choice = data.choices?.[0];
    const message = choice?.message;

    // Extract tool calls if present
    const toolCalls: MiniMaxToolCall[] | undefined =
      message?.tool_calls?.length ? message.tool_calls : undefined;

    return {
      content: message?.content ?? "",
      model: data.model ?? model,
      usage: {
        promptTokens: data.usage?.prompt_tokens ?? 0,
        completionTokens: data.usage?.completion_tokens ?? 0,
        totalTokens: data.usage?.total_tokens ?? 0,
      },
      toolCalls,
      finishReason: choice?.finish_reason ?? "stop",
      requestId: data.id,
    };
  }

  /**
   * Bulk-complete: run multiple prompts in parallel with concurrency control.
   * Use for batch content generation — the primary use case for MiniMax.
   */
  async bulkComplete(
    model: string,
    prompts: MiniMaxMessage[][],
    options: MiniMaxCompletionOptions & { concurrency?: number } = {}
  ): Promise<MiniMaxResponse[]> {
    const concurrency = options.concurrency ?? 5;
    const results: MiniMaxResponse[] = [];

    // Process in batches to respect rate limits
    for (let i = 0; i < prompts.length; i += concurrency) {
      const batch = prompts.slice(i, i + concurrency);
      const batchResults = await Promise.allSettled(
        batch.map((messages) => this.complete(model, messages, options))
      );

      for (const result of batchResults) {
        if (result.status === "fulfilled") {
          results.push(result.value);
        } else {
          // On failure, push an error response rather than throwing
          results.push({
            content: "",
            model,
            usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
            finishReason: "error",
            requestId: undefined,
          });
        }
      }

      // Brief rate-limit pause between batches
      if (i + concurrency < prompts.length) {
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }

    return results;
  }

  /**
   * Estimate cost for a given token count.
   * MiniMax M2.7 pricing: $0.08/MTok in, $0.80/MTok out
   */
  estimateCost(inputTokens: number, outputTokens: number): number {
    const inputCost = (inputTokens / 1_000_000) * 0.08;
    const outputCost = (outputTokens / 1_000_000) * 0.80;
    return inputCost + outputCost;
  }

  get name(): string {
    return "minimax";
  }
}
