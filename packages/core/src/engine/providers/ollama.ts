/**
 * Ollama Provider — Local model runner for Lyrie Agent.
 *
 * Supports any model available in the local Ollama instance:
 * - Qwen3.5 Max, Qwen3 Coder
 * - Gemma 4 31B, Gemma 3
 * - Llama 3.3, DeepSeek R2, Mistral
 * - Any custom GGUF model
 *
 * Used for: Privacy-first local inference, offline mode, zero-cost execution
 * Base URL: http://localhost:11434
 *
 * OTT Cybersecurity LLC
 */

export interface OllamaConfig {
  baseUrl?: string;
  timeoutMs?: number;
}

export interface OllamaMessage {
  role: "system" | "user" | "assistant";
  content: string;
  images?: string[]; // base64-encoded images for multimodal models
}

export interface OllamaUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  evalDurationMs: number;
  tokensPerSecond: number;
}

export interface OllamaResponse {
  content: string;
  model: string;
  usage: OllamaUsage;
  finishReason: string;
  done: boolean;
}

export interface OllamaModel {
  name: string;
  modifiedAt: string;
  size: number;
  digest: string;
  details: {
    format: string;
    family: string;
    parameterSize: string;
    quantizationLevel: string;
  };
}

export interface OllamaCompletionOptions {
  maxTokens?: number;
  temperature?: number;
  topP?: number;
  topK?: number;
  repeatPenalty?: number;
  seed?: number;
  numCtx?: number; // context window size
  numGpu?: number; // GPU layers (0 = CPU only)
  numThread?: number; // CPU threads
  stream?: false;
}

export class OllamaProvider {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(config: OllamaConfig = {}) {
    this.baseUrl = config.baseUrl || process.env.OLLAMA_BASE_URL || "http://localhost:11434";
    this.timeoutMs = config.timeoutMs || 120_000; // 2 minute default for local models
  }

  /**
   * Chat completion using the Ollama /api/chat endpoint.
   * Supports all modern models including multimodal.
   */
  async complete(
    model: string,
    messages: OllamaMessage[],
    options: OllamaCompletionOptions = {}
  ): Promise<OllamaResponse> {
    const body: Record<string, any> = {
      model,
      messages,
      stream: false,
      options: {
        num_predict: options.maxTokens ?? 8192,
        temperature: options.temperature ?? 0.7,
        top_p: options.topP ?? 0.9,
        top_k: options.topK ?? 40,
        repeat_penalty: options.repeatPenalty ?? 1.1,
        num_ctx: options.numCtx ?? 32768,
        ...(options.numGpu !== undefined && { num_gpu: options.numGpu }),
        ...(options.numThread !== undefined && { num_thread: options.numThread }),
        ...(options.seed !== undefined && { seed: options.seed }),
      },
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err: any) {
      if (err.name === "AbortError") {
        throw new Error(`Ollama request timed out after ${this.timeoutMs}ms for model: ${model}`);
      }
      throw new Error(
        `Ollama connection failed at ${this.baseUrl} — is Ollama running?\n` +
          `  Start with: ollama serve\n  Error: ${err.message}`
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Ollama API error (${response.status}): ${errorText}`);
    }

    const data = await response.json() as any;

    if (data.error) {
      // Common error: model not installed
      if (data.error.includes("model") && data.error.includes("not found")) {
        throw new Error(
          `Ollama model "${model}" is not installed.\n` +
            `  Install with: ollama pull ${model}`
        );
      }
      throw new Error(`Ollama error: ${data.error}`);
    }

    const content: string = data.message?.content ?? "";
    const promptTokens: number = data.prompt_eval_count ?? 0;
    const completionTokens: number = data.eval_count ?? 0;
    const evalDurationNs: number = data.eval_duration ?? 0;
    const evalDurationMs = evalDurationNs / 1_000_000;
    const tokensPerSecond =
      evalDurationMs > 0 ? (completionTokens / evalDurationMs) * 1000 : 0;

    return {
      content,
      model: data.model ?? model,
      usage: {
        promptTokens,
        completionTokens,
        totalTokens: promptTokens + completionTokens,
        evalDurationMs,
        tokensPerSecond: Math.round(tokensPerSecond * 10) / 10,
      },
      finishReason: data.done_reason ?? (data.done ? "stop" : "length"),
      done: data.done ?? true,
    };
  }

  /**
   * Simple text generation using /api/generate (no chat format).
   * Faster for simple completions.
   */
  async generate(
    model: string,
    prompt: string,
    options: OllamaCompletionOptions = {}
  ): Promise<OllamaResponse> {
    const body: Record<string, any> = {
      model,
      prompt,
      stream: false,
      options: {
        num_predict: options.maxTokens ?? 4096,
        temperature: options.temperature ?? 0.7,
        top_p: options.topP ?? 0.9,
        num_ctx: options.numCtx ?? 32768,
      },
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/api/generate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Ollama generate error (${response.status}): ${errorText}`);
    }

    const data = await response.json() as any;
    const promptTokens = data.prompt_eval_count ?? 0;
    const completionTokens = data.eval_count ?? 0;
    const evalDurationMs = (data.eval_duration ?? 0) / 1_000_000;

    return {
      content: data.response ?? "",
      model: data.model ?? model,
      usage: {
        promptTokens,
        completionTokens,
        totalTokens: promptTokens + completionTokens,
        evalDurationMs,
        tokensPerSecond:
          evalDurationMs > 0
            ? Math.round((completionTokens / evalDurationMs) * 1000 * 10) / 10
            : 0,
      },
      finishReason: data.done ? "stop" : "length",
      done: data.done ?? true,
    };
  }

  /**
   * List all locally installed models.
   */
  async listModels(): Promise<OllamaModel[]> {
    const response = await fetch(`${this.baseUrl}/api/tags`);

    if (!response.ok) {
      throw new Error(`Failed to list Ollama models: ${response.statusText}`);
    }

    const data = await response.json() as any;
    return (data.models ?? []).map((m: any) => ({
      name: m.name,
      modifiedAt: m.modified_at,
      size: m.size,
      digest: m.digest,
      details: {
        format: m.details?.format ?? "unknown",
        family: m.details?.family ?? "unknown",
        parameterSize: m.details?.parameter_size ?? "unknown",
        quantizationLevel: m.details?.quantization_level ?? "unknown",
      },
    }));
  }

  /**
   * Check if Ollama is running and a specific model is available.
   */
  async isAvailable(model?: string): Promise<boolean> {
    try {
      const models = await this.listModels();
      if (!model) return true; // Ollama is running

      return models.some((m) => m.name === model || m.name.startsWith(model));
    } catch {
      return false;
    }
  }

  /**
   * Pull a model from the Ollama registry.
   * This is a long-running operation — streams progress.
   */
  async pullModel(model: string, onProgress?: (status: string) => void): Promise<void> {
    const response = await fetch(`${this.baseUrl}/api/pull`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: model, stream: true }),
    });

    if (!response.ok) {
      throw new Error(`Failed to pull model ${model}: ${response.statusText}`);
    }

    const reader = response.body?.getReader();
    if (!reader) throw new Error("No response body from pull");

    const decoder = new TextDecoder();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      const lines = decoder.decode(value).split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const event = JSON.parse(line);
          if (onProgress) onProgress(event.status ?? "");
          if (event.status === "success") return;
          if (event.error) throw new Error(`Pull error: ${event.error}`);
        } catch (e) {
          // Skip malformed JSON lines
        }
      }
    }
  }

  /**
   * Estimate local inference speed for planning.
   * Returns tokens/second for the given model.
   */
  async benchmarkSpeed(model: string): Promise<number> {
    const testPrompt = "Count from 1 to 10.";
    try {
      const result = await this.generate(model, testPrompt, { maxTokens: 50 });
      return result.usage.tokensPerSecond;
    } catch {
      return 0;
    }
  }

  get name(): string {
    return "ollama";
  }
}
