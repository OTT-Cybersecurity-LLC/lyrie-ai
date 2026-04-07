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
    id: "gemini-3.1-flash",
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
    id: "gemini-3.1-pro",
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

export class ModelRouter {
  private models: ModelConfig[] = [];
  private preferLocal = false;

  async initialize(): Promise<void> {
    this.models = [...DEFAULT_MODELS];
    console.log(`   → ${this.models.length} models configured`);
    console.log(`   → Cloud: ${this.models.filter((m) => !m.isLocal).length} | Local: ${this.models.filter((m) => m.isLocal).length}`);
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

    // Return a model instance (placeholder — real implementation connects to APIs)
    return {
      config: selected,
      complete: async (prompt: any, options?: any) => {
        // TODO: Connect to actual model API based on provider
        return { content: "", toolCalls: [] };
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

    // Complex/strategy patterns
    if (/\b(strategy|plan|design|decide|trade|invest|launch)\b/.test(lower)) {
      return "brain";
    }

    return "general";
  }

  availableModels(): ModelConfig[] {
    return this.models;
  }

  setPreferLocal(prefer: boolean): void {
    this.preferLocal = prefer;
  }
}
