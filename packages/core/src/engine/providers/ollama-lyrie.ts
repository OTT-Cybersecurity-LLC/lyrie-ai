/**
 * OllamaLyrieProvider — LyrieProvider adapter over the existing OllamaProvider.
 *
 * Local, zero external API calls. Default endpoint: http://localhost:11434
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  LyrieCompletion,
  LyrieCompletionOptions,
  LyrieMessage,
  LyrieProvider,
} from "./lyrie-provider";

export interface OllamaLyrieConfig {
  endpoint?: string;
  defaultModel?: string;
  models?: string[];
}

export class OllamaLyrieProvider implements LyrieProvider {
  readonly id = "ollama";
  readonly name = "Ollama";
  readonly endpoint: string;
  readonly apiKeyEnv = undefined;
  readonly models: string[];
  readonly defaultModel: string;
  readonly isLocal = true;
  readonly supportsToolUse = true;
  readonly supportsFunctionCalling = true;
  readonly maxContextTokens = 131072;

  constructor(cfg: OllamaLyrieConfig = {}) {
    this.endpoint = cfg.endpoint || process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    this.defaultModel = cfg.defaultModel || "llama3.2:latest";
    this.models = cfg.models || [
      "llama3.2:latest",
      "llama3.2:70b",
      "qwen2.5:latest",
      "qwen2.5-coder:latest",
      "gemma2:latest",
      "mistral:latest",
      "deepseek-r1:latest",
    ];
  }

  async health(): Promise<boolean> {
    try {
      const r = await fetch(`${this.endpoint}/api/tags`, { signal: AbortSignal.timeout(3000) });
      if (!r.ok) return false;
      const data = (await r.json()) as { models?: any[] };
      return Array.isArray(data.models) && data.models.length > 0;
    } catch {
      return false;
    }
  }

  async complete(
    model: string,
    messages: LyrieMessage[],
    options: LyrieCompletionOptions = {},
  ): Promise<LyrieCompletion> {
    // Ollama supports a "system" role inline.
    const flat = options.system
      ? [{ role: "system" as const, content: options.system }, ...messages]
      : messages;

    const ollamaMessages = flat.map((m) => ({
      role: m.role === "tool" ? "user" : (m.role as "system" | "user" | "assistant"),
      content: m.role === "tool" ? `[tool_result:${m.toolCallId ?? ""}]\n${m.content}` : m.content,
    }));

    const body: Record<string, any> = {
      model: model || this.defaultModel,
      messages: ollamaMessages,
      stream: false,
      options: {
        num_predict: options.maxTokens ?? 4096,
        temperature: options.temperature ?? 0.7,
        top_p: options.topP ?? 0.9,
        ...(options.stop?.length ? { stop: options.stop } : {}),
      },
    };

    if (options.tools?.length) {
      // Ollama exposes OpenAI-style tools via /api/chat (since v0.4).
      body.tools = options.tools.map((t) => ({
        type: "function",
        function: {
          name: t.name,
          description: t.description,
          parameters: t.parameters,
        },
      }));
    }

    const resp = await fetch(`${this.endpoint}/api/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
    if (!resp.ok) {
      throw new Error(`Ollama error (${resp.status}): ${await resp.text()}`);
    }
    const data = (await resp.json()) as any;

    const content: string = data?.message?.content ?? "";
    const toolCalls = Array.isArray(data?.message?.tool_calls)
      ? data.message.tool_calls.map((tc: any, i: number) => ({
          id: tc.id || `ollama-tc-${i}`,
          name: tc.function?.name || tc.name || "",
          arguments:
            typeof tc.function?.arguments === "string"
              ? safeJson(tc.function.arguments)
              : (tc.function?.arguments ?? tc.arguments ?? {}),
        }))
      : [];

    return {
      content,
      toolCalls,
      stopReason: toolCalls.length ? "tool_use" : data?.done_reason || "stop",
      model: data?.model || model,
      usage: {
        promptTokens: data?.prompt_eval_count ?? 0,
        completionTokens: data?.eval_count ?? 0,
        totalTokens: (data?.prompt_eval_count ?? 0) + (data?.eval_count ?? 0),
      },
    };
  }
}

function safeJson(s: string): Record<string, any> {
  try {
    return JSON.parse(s);
  } catch {
    return { _raw: s };
  }
}
