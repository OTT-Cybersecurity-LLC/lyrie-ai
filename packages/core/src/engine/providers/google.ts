/**
 * Google Provider — Gemini models for Lyrie Agent.
 * 
 * Supports: Gemini 3.1 Pro, Gemini 3.1 Flash, Gemini 2.5 Pro
 * Used for: Reasoning (leads MMLU 94.1%), fast tasks, multimodal
 */

export interface GoogleConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface GoogleResponse {
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

export class GoogleProvider {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: GoogleConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || "https://generativelanguage.googleapis.com";
  }

  async complete(
    model: string,
    messages: any[],
    options?: {
      maxTokens?: number;
      tools?: any[];
      temperature?: number;
      systemInstruction?: string;
    }
  ): Promise<GoogleResponse> {
    const contents = messages.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

    const body: any = {
      contents,
      generationConfig: {
        maxOutputTokens: options?.maxTokens || 8192,
        temperature: options?.temperature ?? 0.7,
      },
    };

    if (options?.systemInstruction) {
      body.systemInstruction = { parts: [{ text: options.systemInstruction }] };
    }

    if (options?.tools?.length) {
      body.tools = options.tools;
    }

    const url = `${this.baseUrl}/v1beta/models/${model}:generateContent?key=${this.apiKey}`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Google API error (${response.status}): ${error}`);
    }

    const data = await response.json() as any;
    const candidate = data.candidates?.[0];
    const content = candidate?.content?.parts?.map((p: any) => p.text).join("") || "";

    return {
      content,
      model,
      usage: {
        promptTokens: data.usageMetadata?.promptTokenCount || 0,
        completionTokens: data.usageMetadata?.candidatesTokenCount || 0,
        totalTokens: data.usageMetadata?.totalTokenCount || 0,
      },
      toolCalls: candidate?.content?.parts?.filter((p: any) => p.functionCall),
      finishReason: candidate?.finishReason || "STOP",
    };
  }
}
