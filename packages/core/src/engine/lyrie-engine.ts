/**
 * LyrieEngine — The main agent runtime.
 * 
 * Responsible for:
 * - Processing user messages
 * - Executing tools with security sandboxing
 * - Spawning sub-agents for parallel work
 * - Self-improving skills after complex tasks
 * - Coordinating multi-step workflows
 */

import { MemoryCore } from "../memory/memory-core";
import { ModelRouter } from "./model-router";
import { ShieldManager } from "./shield-manager";
import { ToolExecutor } from "../tools/tool-executor";
import { SkillManager } from "../skills/skill-manager";

export interface LyrieEngineConfig {
  shield: ShieldManager;
  memory: MemoryCore;
  router: ModelRouter;
}

export interface Message {
  role: "user" | "assistant" | "system";
  content: string;
  source?: string;
  timestamp?: number;
}

export class LyrieEngine {
  private shield: ShieldManager;
  private memory: MemoryCore;
  private router: ModelRouter;
  private tools: ToolExecutor;
  private skills: SkillManager;
  private isRunning = false;

  constructor(config: LyrieEngineConfig) {
    this.shield = config.shield;
    this.memory = config.memory;
    this.router = config.router;
    this.tools = new ToolExecutor(this.shield);
    this.skills = new SkillManager();
  }

  async initialize(): Promise<void> {
    await this.tools.initialize();
    await this.skills.initialize();
    this.isRunning = true;
  }

  /**
   * Process an incoming message and generate a response.
   * This is the main loop of the agent.
   */
  async process(message: Message): Promise<Message> {
    // Step 1: Shield check — scan input for threats
    const threatCheck = await this.shield.scanInput(message.content);
    if (threatCheck.blocked) {
      return {
        role: "assistant",
        content: `⚠️ Security: ${threatCheck.reason}`,
        timestamp: Date.now(),
      };
    }

    // Step 2: Recall relevant context from memory
    const context = await this.memory.recall(message.content, { limit: 10 });

    // Step 3: Route to the optimal model for this task
    const model = await this.router.route(message.content);

    // Step 4: Build the prompt with context + tools + skills
    const prompt = this.buildPrompt(message, context);

    // Step 5: Execute the model call
    const response = await model.complete(prompt, {
      tools: this.tools.available(),
      maxTokens: 8192,
    });

    // Step 6: Execute any tool calls from the response
    if (response.toolCalls?.length) {
      for (const call of response.toolCalls) {
        // Shield validates every tool call before execution
        const allowed = await this.shield.validateToolCall(call);
        if (allowed) {
          const result = await this.tools.execute(call);
          // Feed result back to model for final response
        }
      }
    }

    // Step 7: Store the interaction in memory
    await this.memory.store(
      `conversation:${Date.now()}`,
      { user: message.content, assistant: response.content },
      "medium",
      "system"
    );

    // Step 8: Check if this task created a new skill opportunity
    await this.skills.checkForImprovement(message, response);

    return {
      role: "assistant",
      content: response.content,
      timestamp: Date.now(),
    };
  }

  private buildPrompt(message: Message, context: any[]): any {
    return {
      system: `You are Lyrie, an autonomous AI agent with built-in cybersecurity capabilities. 
You protect while you help. You are sharp, direct, and proactive.
You never ask unnecessary questions — you execute.`,
      messages: [
        ...context.map((c) => ({ role: "system" as const, content: `[Memory] ${JSON.stringify(c)}` })),
        { role: "user" as const, content: message.content },
      ],
    };
  }

  get running(): boolean {
    return this.isRunning;
  }
}
