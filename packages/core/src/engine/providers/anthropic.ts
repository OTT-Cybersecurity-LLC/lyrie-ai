/**
 * Anthropic Provider — Claude models for Lyrie Agent.
 * 
 * Supports: Claude Opus 4.6, Sonnet 4.6, Haiku 4.5
 * Used for: Brain (strategy), general reasoning, natural prose
 */

export interface AnthropicConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface AnthropicMessage {
  role: "user" | "assistant";
  content: string;
}

export interface AnthropicResponse {
  content: string;
  model: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens?: number;
    cacheWriteTokens?: number;
  };
  toolCalls?: any[];
  stopReason: string;
}

export class AnthropicProvider {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: AnthropicConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || "https://api.anthropic.com";
  }

  async complete(
    model: string,
    messages: AnthropicMessage[],
    options?: {
      system?: string;
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
    }
  ): Promise<AnthropicResponse> {
    const body: any = {
      model,
      max_tokens: options?.maxTokens || 8192,
      messages,
    };

    if (options?.system) body.system = options.system;
    if (options?.tools?.length) body.tools = options.tools;
    if (options?.temperature !== undefined) body.temperature = options.temperature;

    const response = await fetch(`${this.baseUrl}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Anthropic API error (${response.status}): ${error}`);
    }

    const data = await response.json() as any;

    // Extract text content and tool calls
    let content = "";
    const toolCalls: any[] = [];

    for (const block of data.content || []) {
      if (block.type === "text") content += block.text;
      if (block.type === "tool_use") toolCalls.push(block);
    }

    return {
      content,
      model: data.model,
      usage: {
        inputTokens: data.usage?.input_tokens || 0,
        outputTokens: data.usage?.output_tokens || 0,
        cacheReadTokens: data.usage?.cache_read_input_tokens || 0,
        cacheWriteTokens: data.usage?.cache_creation_input_tokens || 0,
      },
      toolCalls: toolCalls.length ? toolCalls : undefined,
      stopReason: data.stop_reason || "end_turn",
    };
  }
}
