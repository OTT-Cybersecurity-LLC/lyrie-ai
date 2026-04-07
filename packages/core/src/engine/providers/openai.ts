/**
 * OpenAI Provider — GPT models for Lyrie Agent.
 * 
 * Supports: GPT-5.4, GPT-5.4 Codex, o3, o4-mini
 * Used for: General tasks, coding, reasoning
 */

export interface OpenAIConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface OpenAIResponse {
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

export class OpenAIProvider {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: OpenAIConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || "https://api.openai.com";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
    }
  ): Promise<OpenAIResponse> {
    const body: any = {
      model,
      max_tokens: options?.maxTokens || 8192,
      messages,
    };

    if (options?.tools?.length) body.tools = options.tools;
    if (options?.temperature !== undefined) body.temperature = options.temperature;

    const response = await fetch(`${this.baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`OpenAI API error (${response.status}): ${error}`);
    }

    const data = await response.json() as any;
    const choice = data.choices?.[0];

    return {
      content: choice?.message?.content || "",
      model: data.model,
      usage: {
        promptTokens: data.usage?.prompt_tokens || 0,
        completionTokens: data.usage?.completion_tokens || 0,
        totalTokens: data.usage?.total_tokens || 0,
      },
      toolCalls: choice?.message?.tool_calls,
      finishReason: choice?.finish_reason || "stop",
    };
  }
}
