/**
 * xAI Provider — Grok models for Lyrie Agent.
 * 
 * Supports: Grok 4.20 (flagship), Grok 4.1 Fast, Grok 4.20 Multi-Agent
 * Used for: Coding (leads SWE-bench 75%), fast tasks, multi-agent coordination
 * 
 * Uses OpenAI-compatible API format.
 */

export interface XAIConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface XAIResponse {
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

export class XAIProvider {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: XAIConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || "https://api.x.ai";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
    }
  ): Promise<XAIResponse> {
    const body: any = {
      model,
      max_tokens: options?.maxTokens || 16384,
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
      throw new Error(`xAI API error (${response.status}): ${error}`);
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
