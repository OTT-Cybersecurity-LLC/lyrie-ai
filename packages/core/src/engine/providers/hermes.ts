/**
 * HermesProvider — Native function-calling adapter for NousResearch Hermes 3.
 *
 * Why this provider exists:
 *   Hermes-3-70B is the Apache-2.0 model purpose-built for agentic
 *   function calling. Lyrie v1.0.0 names it the canonical local model.
 *
 *   Hermes uses ChatML tokens (<|im_start|>role / <|im_end|>) and emits
 *   tool calls as raw text:
 *
 *     <tool_call>
 *     {"name": "tool_name", "arguments": {"arg": "value"}}
 *     </tool_call>
 *
 *   This adapter normalizes Hermes-style output into Lyrie's neutral
 *   `LyrieToolCall[]` format and adds a Hermes-aware system-prompt builder.
 *
 * Endpoint: defaults to local Ollama (`http://localhost:11434`) using
 *   `nous-hermes3:70b`. Can also point at any OpenAI-compatible Hermes
 *   server (Nous Portal, OpenRouter, vLLM-Hermes).
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import {
  LyrieCompletion,
  LyrieCompletionOptions,
  LyrieMessage,
  LyrieProvider,
  LyrieToolCall,
  LyrieToolDef,
} from "./lyrie-provider";

export interface HermesConfig {
  /** Endpoint base URL. Auto-detects Ollama vs OpenAI-compatible. */
  endpoint?: string;
  /** API key env var name (only required for hosted Hermes). */
  apiKeyEnv?: string;
  /** API key value override (otherwise pulled from process.env[apiKeyEnv]). */
  apiKey?: string;
  defaultModel?: string;
  models?: string[];
  /** "ollama" or "openai" — controls which path is hit. */
  protocol?: "ollama" | "openai";
}

export class HermesProvider implements LyrieProvider {
  readonly id = "hermes";
  readonly name = "Hermes (NousResearch)";
  readonly endpoint: string;
  readonly apiKeyEnv?: string;
  readonly models: string[];
  readonly defaultModel: string;
  readonly isLocal: boolean;
  readonly supportsToolUse = true;
  readonly supportsFunctionCalling = true;
  readonly maxContextTokens = 131072;

  private readonly protocol: "ollama" | "openai";
  private readonly apiKey: string | undefined;

  constructor(cfg: HermesConfig = {}) {
    this.endpoint = cfg.endpoint || process.env.HERMES_ENDPOINT || "http://localhost:11434";
    this.apiKeyEnv = cfg.apiKeyEnv;
    this.apiKey = cfg.apiKey || (cfg.apiKeyEnv ? process.env[cfg.apiKeyEnv] : undefined);
    this.protocol = cfg.protocol || (this.endpoint.includes("/v1") ? "openai" : "ollama");
    this.defaultModel = cfg.defaultModel || "nous-hermes3:70b";
    this.models = cfg.models || [
      "nous-hermes3:70b",
      "nous-hermes3:8b",
      "hermes-3-llama-3.1-70b",
      "hermes-3-llama-3.1-8b",
    ];
    // local if pointed at localhost AND no API key
    this.isLocal = /(?:localhost|127\.0\.0\.1)/i.test(this.endpoint) && !this.apiKey;
  }

  async health(): Promise<boolean> {
    try {
      const probe =
        this.protocol === "ollama"
          ? `${this.endpoint}/api/tags`
          : `${this.endpoint.replace(/\/$/, "")}/models`;
      const r = await fetch(probe, {
        signal: AbortSignal.timeout(3000),
        headers: this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {},
      });
      return r.ok;
    } catch {
      return false;
    }
  }

  /**
   * Hermes responds better with explicit XML-tagged tool descriptions.
   * Inject them at the top of the system prompt so the model "wakes up"
   * already aware of the tool catalog and the <tool_call> format.
   */
  buildSystemPrompt(base: string, tools: LyrieToolDef[] = []): string {
    if (!tools.length) return base;
    const toolList = tools
      .map(
        (t) =>
          `<tool>\n  <name>${t.name}</name>\n  <description>${t.description}</description>\n  <parameters>${JSON.stringify(t.parameters)}</parameters>\n</tool>`,
      )
      .join("\n");
    return [
      base,
      "",
      "<tools>",
      toolList,
      "</tools>",
      "",
      "When you call a tool, respond with EXACTLY:",
      "<tool_call>",
      '{"name": "tool_name", "arguments": {"arg": "value"}}',
      "</tool_call>",
      "After the tool returns, you will see the result and may produce more tool calls or a final answer.",
    ].join("\n");
  }

  /** Convert Lyrie messages → ChatML string (used only for raw /generate path). */
  formatMessages(messages: LyrieMessage[]): string {
    return messages
      .map((m) => {
        const role = m.role === "tool" ? "tool" : m.role;
        return `<|im_start|>${role}\n${m.content}<|im_end|>`;
      })
      .concat("<|im_start|>assistant\n")
      .join("\n");
  }

  /**
   * Parse a raw Hermes assistant message and pull out any <tool_call> blocks.
   * Hermes also occasionally emits multiple tool calls in one turn.
   */
  parseToolCalls(text: string): { content: string; toolCalls: LyrieToolCall[] } {
    const toolCalls: LyrieToolCall[] = [];
    const pattern = /<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/g;
    let cleaned = text;
    let m: RegExpExecArray | null;
    let i = 0;
    while ((m = pattern.exec(text)) !== null) {
      const raw = m[1].trim();
      try {
        const parsed = JSON.parse(raw) as { name: string; arguments?: Record<string, any> };
        if (parsed && typeof parsed.name === "string") {
          toolCalls.push({
            id: `hermes-tc-${i++}`,
            name: parsed.name,
            arguments: parsed.arguments ?? {},
          });
        }
      } catch {
        // Hermes sometimes emits unquoted keys; fall back to a permissive pass
        const nameMatch = raw.match(/"name"\s*:\s*"([^"]+)"/);
        const argsMatch = raw.match(/"arguments"\s*:\s*({[\s\S]*})/);
        if (nameMatch) {
          toolCalls.push({
            id: `hermes-tc-${i++}`,
            name: nameMatch[1],
            arguments: argsMatch ? safeJson(argsMatch[1]) : {},
          });
        }
      }
      cleaned = cleaned.replace(m[0], "");
    }
    return { content: cleaned.trim(), toolCalls };
  }

  async complete(
    model: string,
    messages: LyrieMessage[],
    options: LyrieCompletionOptions = {},
  ): Promise<LyrieCompletion> {
    const sys = options.system
      ? this.buildSystemPrompt(options.system, options.tools ?? [])
      : undefined;

    const flat = sys ? [{ role: "system" as const, content: sys }, ...messages] : messages;

    if (this.protocol === "ollama") {
      const body: Record<string, any> = {
        model: model || this.defaultModel,
        messages: flat.map((m) => ({
          role: m.role === "tool" ? "user" : m.role,
          content:
            m.role === "tool"
              ? `<tool_response>\n${m.content}\n</tool_response>`
              : m.content,
        })),
        stream: false,
        options: {
          num_predict: options.maxTokens ?? 4096,
          temperature: options.temperature ?? 0.7,
          top_p: options.topP ?? 0.9,
          ...(options.stop?.length ? { stop: options.stop } : {}),
        },
      };
      const r = await fetch(`${this.endpoint}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(180_000),
      });
      if (!r.ok) throw new Error(`Hermes/Ollama error (${r.status}): ${await r.text()}`);
      const data = (await r.json()) as any;
      const raw: string = data?.message?.content ?? "";
      const { content, toolCalls } = this.parseToolCalls(raw);
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

    // OpenAI-compatible Hermes endpoint
    const body: Record<string, any> = {
      model: model || this.defaultModel,
      messages: flat.map((m) =>
        m.role === "tool"
          ? { role: "tool", content: m.content, tool_call_id: m.toolCallId ?? "" }
          : { role: m.role, content: m.content },
      ),
      stream: false,
      max_tokens: options.maxTokens ?? 4096,
      temperature: options.temperature ?? 0.7,
      ...(options.stop?.length ? { stop: options.stop } : {}),
    };
    const r = await fetch(`${this.endpoint.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {}),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(180_000),
    });
    if (!r.ok) throw new Error(`Hermes error (${r.status}): ${await r.text()}`);
    const data = (await r.json()) as any;
    const raw: string = data?.choices?.[0]?.message?.content ?? "";
    const { content, toolCalls } = this.parseToolCalls(raw);
    return {
      content,
      toolCalls,
      stopReason: data?.choices?.[0]?.finish_reason || (toolCalls.length ? "tool_use" : "stop"),
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
