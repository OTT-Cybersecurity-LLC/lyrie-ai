/**
 * LMStudioProvider — LyrieProvider over LM Studio's OpenAI-compatible server.
 *
 * Local, zero external API calls. Default endpoint: http://localhost:1234/v1
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  LyrieCompletion,
  LyrieCompletionOptions,
  LyrieMessage,
  LyrieProvider,
  LyrieToolCall,
} from "./lyrie-provider";

export interface LMStudioConfig {
  endpoint?: string;
  defaultModel?: string;
  models?: string[];
}

export class LMStudioProvider implements LyrieProvider {
  readonly id = "lmstudio";
  readonly name = "LM Studio";
  readonly endpoint: string;
  readonly apiKeyEnv = undefined;
  readonly models: string[];
  readonly defaultModel: string;
  readonly isLocal = true;
  readonly supportsToolUse = true;
  readonly supportsFunctionCalling = true;
  readonly maxContextTokens = 131072;

  constructor(cfg: LMStudioConfig = {}) {
    this.endpoint = cfg.endpoint || process.env.LMSTUDIO_BASE_URL || "http://localhost:1234/v1";
    this.defaultModel = cfg.defaultModel || "hermes-3-70b";
    this.models = cfg.models || [
      "hermes-3-70b",
      "hermes-3-8b",
      "qwen2.5-coder-32b",
      "llama-3.3-70b",
      "deepseek-r1-distill-32b",
    ];
  }

  async health(): Promise<boolean> {
    try {
      const r = await fetch(`${this.endpoint}/models`, { signal: AbortSignal.timeout(3000) });
      if (!r.ok) return false;
      const data = (await r.json()) as { data?: any[] };
      return Array.isArray(data.data);
    } catch {
      return false;
    }
  }

  async complete(
    model: string,
    messages: LyrieMessage[],
    options: LyrieCompletionOptions = {},
  ): Promise<LyrieCompletion> {
    const flat = options.system
      ? [{ role: "system" as const, content: options.system }, ...messages]
      : messages;

    const oaiMessages = flat.map((m) => {
      if (m.role === "tool") {
        return {
          role: "tool" as const,
          content: m.content,
          tool_call_id: m.toolCallId ?? "",
        };
      }
      return { role: m.role as "system" | "user" | "assistant", content: m.content };
    });

    const body: Record<string, any> = {
      model: model || this.defaultModel,
      messages: oaiMessages,
      stream: false,
      max_tokens: options.maxTokens ?? 4096,
      temperature: options.temperature ?? 0.7,
      top_p: options.topP ?? 0.9,
      ...(options.stop?.length ? { stop: options.stop } : {}),
    };

    if (options.tools?.length) {
      body.tools = options.tools.map((t) => ({
        type: "function",
        function: { name: t.name, description: t.description, parameters: t.parameters },
      }));
    }

    const resp = await fetch(`${this.endpoint}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(120_000),
    });
    if (!resp.ok) {
      throw new Error(`LM Studio error (${resp.status}): ${await resp.text()}`);
    }
    const data = (await resp.json()) as any;
    const choice = data?.choices?.[0];
    const message = choice?.message ?? {};
    const content: string = message.content ?? "";

    const toolCalls: LyrieToolCall[] = Array.isArray(message.tool_calls)
      ? message.tool_calls.map((tc: any, i: number) => ({
          id: tc.id || `lmstudio-tc-${i}`,
          name: tc.function?.name || "",
          arguments:
            typeof tc.function?.arguments === "string"
              ? safeJson(tc.function.arguments)
              : (tc.function?.arguments ?? {}),
        }))
      : [];

    return {
      content,
      toolCalls,
      stopReason: choice?.finish_reason || (toolCalls.length ? "tool_use" : "stop"),
      model: data?.model || model,
      usage: {
        promptTokens: data?.usage?.prompt_tokens ?? 0,
        completionTokens: data?.usage?.completion_tokens ?? 0,
        totalTokens: data?.usage?.total_tokens ?? 0,
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
