/**
 * ModelRouter — Intelligent model routing for Lyrie Agent.
 * 
 * Routes each task to the optimal model based on:
 * - Task complexity (simple → fast model, complex → brain model)
 * - Task type (coding → coder model, reasoning → reasoning model)
 * - Cost optimization (cheapest model that can handle the task)
 * - User preference (local vs cloud)
 */

export type TaskType = "brain" | "coder" | "fast" | "reasoning" | "bulk" | "general";

export interface ModelConfig {
  id: string;
  name: string;
  provider: string;
  taskType: TaskType;
  costPerMTokIn: number;
  costPerMTokOut: number;
  contextWindow: number;
  maxTokens: number;
  isLocal: boolean;
}

export interface ModelInstance {
  config: ModelConfig;
  complete(prompt: any, options?: any): Promise<any>;
}

// Default model configurations — best models as of April 2026
const DEFAULT_MODELS: ModelConfig[] = [
  // Cloud models
  {
    id: "claude-opus-4-6",
    name: "Claude Opus 4.6",
    provider: "anthropic",
    taskType: "brain",
    costPerMTokIn: 15,
    costPerMTokOut: 75,
    contextWindow: 1000000,
    maxTokens: 16384,
    isLocal: false,
  },
  {
    id: "grok-4.20-0309-non-reasoning",
    name: "Grok 4.20",
    provider: "xai",
    taskType: "coder",
    costPerMTokIn: 2,
    costPerMTokOut: 6,
    contextWindow: 2000000,
    maxTokens: 16384,
    isLocal: false,
  },
  {
    id: "gemini-2.5-flash",
    name: "Gemini 3.1 Flash",
    provider: "google",
    taskType: "fast",
    costPerMTokIn: 0.075,
    costPerMTokOut: 0.3,
    contextWindow: 1000000,
    maxTokens: 8192,
    isLocal: false,
  },
  {
    id: "gemini-2.5-pro",
    name: "Gemini 3.1 Pro",
    provider: "google",
    taskType: "reasoning",
    costPerMTokIn: 1.25,
    costPerMTokOut: 5,
    contextWindow: 1000000,
    maxTokens: 16384,
    isLocal: false,
  },
  {
    id: "minimax-m2.7-highspeed",
    name: "MiniMax M2.7 HighSpeed",
    provider: "minimax",
    taskType: "bulk",
    costPerMTokIn: 0.08,
    costPerMTokOut: 0.8,
    contextWindow: 204800,
    maxTokens: 8192,
    isLocal: false,
  },
  {
    id: "gpt-5.4",
    name: "GPT-5.4",
    provider: "openai",
    taskType: "general",
    costPerMTokIn: 2.5,
    costPerMTokOut: 10,
    contextWindow: 200000,
    maxTokens: 16384,
    isLocal: false,
  },
  // Local models
  {
    id: "qwen3.5-max",
    name: "Qwen 3.5 Max",
    provider: "local",
    taskType: "brain",
    costPerMTokIn: 0,
    costPerMTokOut: 0,
    contextWindow: 131072,
    maxTokens: 8192,
    isLocal: true,
  },
  {
    id: "qwen3-coder-next",
    name: "Qwen3 Coder Next",
    provider: "local",
    taskType: "coder",
    costPerMTokIn: 0,
    costPerMTokOut: 0,
    contextWindow: 131072,
    maxTokens: 8192,
    isLocal: true,
  },
  {
    id: "gemma-4-31b",
    name: "Gemma 4 31B",
    provider: "local",
    taskType: "fast",
    costPerMTokIn: 0,
    costPerMTokOut: 0,
    contextWindow: 32768,
    maxTokens: 4096,
    isLocal: true,
  },
];

import { AnthropicProvider } from "./providers/anthropic";
import { OpenAIProvider } from "./providers/openai";
import { GoogleProvider } from "./providers/google";
import { XAIProvider } from "./providers/xai";

export interface RouterConfig {
  anthropicApiKey?: string;
  openaiApiKey?: string;
  googleApiKey?: string;
  xaiApiKey?: string;
  minimaxApiKey?: string;
  preferLocal?: boolean;
}

export class ModelRouter {
  private models: ModelConfig[] = [];
  private preferLocal = false;
  private providers: Map<string, any> = new Map();
  private config: RouterConfig = {};

  async initialize(config?: RouterConfig): Promise<void> {
    this.models = [...DEFAULT_MODELS];
    if (config) {
      this.config = config;
      this.preferLocal = config.preferLocal || false;
    }

    // Instantiate real providers with API keys
    if (this.config.anthropicApiKey) {
      this.providers.set("anthropic", new AnthropicProvider({ apiKey: this.config.anthropicApiKey }));
      console.log("   ✓ Anthropic provider connected");
    }
    if (this.config.openaiApiKey) {
      this.providers.set("openai", new OpenAIProvider({ apiKey: this.config.openaiApiKey }));
      console.log("   ✓ OpenAI provider connected");
    }
    if (this.config.googleApiKey) {
      this.providers.set("google", new GoogleProvider({ apiKey: this.config.googleApiKey }));
      console.log("   ✓ Google provider connected");
    }
    if (this.config.xaiApiKey) {
      this.providers.set("xai", new XAIProvider({ apiKey: this.config.xaiApiKey }));
      console.log("   ✓ xAI provider connected");
    }

    console.log(`   → ${this.models.length} models configured`);
    console.log(`   → Cloud: ${this.models.filter((m) => !m.isLocal).length} | Local: ${this.models.filter((m) => m.isLocal).length}`);
    console.log(`   → Active providers: ${Array.from(this.providers.keys()).join(", ") || "none"}`);
  }

  /**
   * Analyze the input and route to the best model.
   */
  async route(input: string): Promise<ModelInstance> {
    const taskType = this.classifyTask(input);
    const candidates = this.models.filter((m) => m.taskType === taskType);
    
    // Prefer local if configured, otherwise use cloud
    const selected = this.preferLocal
      ? candidates.find((m) => m.isLocal) || candidates[0]
      : candidates.find((m) => !m.isLocal) || candidates[0];

    // Find a real provider for the selected model
    const provider = this.providers.get(selected.provider);

    // If no provider for the selected model, fall back to first available provider
    const fallbackProvider = provider || this.providers.values().next().value;
    const fallbackModel = provider ? selected : this.models.find((m) => m.provider === this.providers.keys().next().value) || selected;

    if (!fallbackProvider) {
      // No providers at all — return empty stub
      console.warn("[ModelRouter] No providers available! Returning empty response.");
      return {
        config: selected,
        complete: async () => ({ content: "⚠️ No AI providers configured. Please set API keys in .env", toolCalls: [] }),
      };
    }

    const actualModel = provider ? selected : fallbackModel;
    const actualProvider = fallbackProvider;

    return {
      config: actualModel,
      complete: async (prompt: any, options?: any) => {
        try {
          // Route to the correct provider API
          if (actualModel.provider === "anthropic" || actualProvider instanceof AnthropicProvider) {
            const anthropic = actualProvider as AnthropicProvider;
            const messages = (prompt.messages || []).filter((m: any) => m.role !== "system").map((m: any) => ({
              role: m.role as "user" | "assistant",
              content: m.content,
            }));
            const result = await anthropic.complete(actualModel.id, messages, {
              system: prompt.system,
              maxTokens: options?.maxTokens || actualModel.maxTokens,
              temperature: 0.7,
            });
            console.log(`[ModelRouter] Anthropic response: content=${result.content?.substring(0, 100)}, toolCalls=${result.toolCalls?.length || 0}, stopReason=${result.stopReason}`);
            return { content: result.content, toolCalls: result.toolCalls };
          }

          if (actualModel.provider === "openai" || actualProvider instanceof OpenAIProvider) {
            const openai = actualProvider as OpenAIProvider;
            const messages = [
              ...(prompt.system ? [{ role: "system", content: prompt.system }] : []),
              ...(prompt.messages || []),
            ];
            const result = await openai.complete(actualModel.id, messages, {
              maxTokens: options?.maxTokens || actualModel.maxTokens,
              temperature: 0.7,
            });
            return { content: result.content, toolCalls: result.toolCalls };
          }

          if (actualModel.provider === "google" || actualProvider instanceof GoogleProvider) {
            const google = actualProvider as GoogleProvider;
            const messages = (prompt.messages || []).filter((m: any) => m.role !== "system");
            const result = await google.complete(actualModel.id, messages, {
              systemInstruction: prompt.system,
              maxTokens: options?.maxTokens || actualModel.maxTokens,
              temperature: 0.7,
            });
            return { content: result.content, toolCalls: result.toolCalls };
          }

          if (actualModel.provider === "xai" || actualProvider instanceof XAIProvider) {
            const xai = actualProvider as XAIProvider;
            const messages = [
              ...(prompt.system ? [{ role: "system", content: prompt.system }] : []),
              ...(prompt.messages || []),
            ];
            const result = await xai.complete(actualModel.id, messages, {
              maxTokens: options?.maxTokens || actualModel.maxTokens,
              temperature: 0.7,
            });
            return { content: result.content, toolCalls: result.toolCalls };
          }

          return { content: "⚠️ No matching provider for model: " + actualModel.id, toolCalls: [] };
        } catch (err: any) {
          console.error(`[ModelRouter] Provider error (${actualModel.provider}/${actualModel.id}):`, err.message);
          return { content: `⚠️ AI error: ${err.message}`, toolCalls: [] };
        }
      },
    };
  }

  /**
   * Classify a task into the appropriate type.
   */
  private classifyTask(input: string): TaskType {
    const lower = input.toLowerCase();

    // Coding patterns
    if (/\b(code|build|implement|refactor|debug|fix bug|function|class|api|deploy|git)\b/.test(lower)) {
      return "coder";
    }

    // Fast/simple patterns
    if (/\b(check|status|ping|list|search|find|what is|how many)\b/.test(lower)) {
      return "fast";
    }

    // Reasoning patterns
    if (/\b(analyze|reason|compare|evaluate|calculate|prove|explain why|architecture)\b/.test(lower)) {
      return "reasoning";
    }

    // Bulk patterns
    if (/\b(generate \d+|batch|bulk|mass|all articles|every page)\b/.test(lower)) {
      return "bulk";
    }

    // Strategy / brain patterns — high-level planning, design, system design
    if (/\b(strategy|strategic|plan|design (a|an|the)|launch|roadmap|architect|orchestrate|decide)\b/.test(lower)) {
      return "brain";
    }

    // Default: general
    return "general";
  }

  availableModels(): ModelConfig[] {
    return this.models;
  }

  setPreferLocal(prefer: boolean): void {
    this.preferLocal = prefer;
  }
}
