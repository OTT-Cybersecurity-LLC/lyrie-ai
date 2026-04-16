/**
 * LyrieEngine — The main agent runtime.
 *
 * Responsible for:
 * - Processing user messages with multi-turn tool use
 * - Executing tools with Shield security sandboxing
 * - Spawning sub-agents for parallel work
 * - Self-improving skills after complex tasks
 * - Coordinating multi-step workflows
 * - Formatting tools for Anthropic/OpenAI APIs
 * - Parsing and executing tool calls from model responses
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { MemoryCore } from "../memory/memory-core";
import { ModelRouter, ModelInstance } from "./model-router";
import { ShieldManager } from "./shield-manager";
import { ToolExecutor, ToolResult } from "../tools/tool-executor";
import { SkillManager } from "../skills/skill-manager";
import { CronManager } from "../cron/cron-manager";
import { SubAgentManager } from "../agents/sub-agent";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface LyrieEngineConfig {
  shield: ShieldManager;
  memory: MemoryCore;
  router: ModelRouter;
  /** Maximum tool-use turns before forcing a final response */
  maxToolTurns?: number;
  /** Maximum total tool calls per request */
  maxToolCalls?: number;
  /** Enable cron scheduler */
  enableCron?: boolean;
  /** Sub-agent configuration */
  subAgentConfig?: {
    maxConcurrent?: number;
    defaultTimeout?: number;
  };
}

export interface Message {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  source?: string;
  timestamp?: number;
  toolCallId?: string;
  toolCalls?: ParsedToolCall[];
}

export interface ParsedToolCall {
  id: string;
  name: string;
  input: Record<string, any>;
}

export interface ProcessResult {
  message: Message;
  toolCallsMade: number;
  turns: number;
  model: string;
  durationMs: number;
}

// ─── Engine ──────────────────────────────────────────────────────────────────

export class LyrieEngine {
  private shield: ShieldManager;
  private memory: MemoryCore;
  private router: ModelRouter;
  private tools: ToolExecutor;
  private skills: SkillManager;
  private cron: CronManager | null = null;
  private subAgents: SubAgentManager;
  private isRunning = false;
  private maxToolTurns: number;
  private maxToolCalls: number;
  private requestCount = 0;

  constructor(config: LyrieEngineConfig) {
    this.shield = config.shield;
    this.memory = config.memory;
    this.router = config.router;
    this.tools = new ToolExecutor(this.shield);
    this.skills = new SkillManager();
    this.subAgents = new SubAgentManager(this.tools, config.subAgentConfig);
    this.maxToolTurns = config.maxToolTurns ?? 25;
    this.maxToolCalls = config.maxToolCalls ?? 50;

    if (config.enableCron !== false) {
      this.cron = new CronManager({
        onMemoryBackup: async () => {
          await this.memory.backup?.();
          console.log("[engine] Memory backup completed via cron");
        },
        onSelfHealingCheck: async () => {
          console.log("[engine] Self-healing check completed");
        },
      });
    }
  }

  async initialize(): Promise<void> {
    await this.tools.initialize();
    await this.skills.initialize();
    if (this.cron) await this.cron.initialize();
    this.isRunning = true;
  }

  /**
   * Process an incoming message and generate a response.
   * Supports multi-turn tool use: model calls tool → gets result → calls another → etc.
   */
  async process(message: Message): Promise<ProcessResult> {
    const startTime = Date.now();
    this.requestCount++;

    // ── Step 1: Shield scan input ────────────────────────────────────
    const threatCheck = await this.shield.scanInput(message.content);
    if (threatCheck.blocked) {
      return {
        message: {
          role: "assistant",
          content: `⚠️ Security: ${threatCheck.reason}`,
          timestamp: Date.now(),
        },
        toolCallsMade: 0,
        turns: 0,
        model: "shield",
        durationMs: Date.now() - startTime,
      };
    }

    // ── Step 2: Recall relevant context ──────────────────────────────
    const context = await this.memory.recall(message.content, { limit: 10 });

    // ── Step 3: Route to optimal model ───────────────────────────────
    const model = await this.router.route(message.content);

    // ── Step 4: Build conversation ───────────────────────────────────
    const conversation = this.buildConversation(message, context);

    // ── Step 5: Multi-turn tool-use loop ─────────────────────────────
    let totalToolCalls = 0;
    let turns = 0;
    let finalContent = "";

    // Determine format based on provider
    const provider = model.config.provider;
    const toolDefs =
      provider === "anthropic"
        ? { tools: this.tools.toAnthropicFormat() }
        : provider === "openai"
          ? { tools: this.tools.toOpenAIFormat() }
          : { tools: this.tools.toAnthropicFormat() }; // default to Anthropic format

    console.log(`[Engine] Processing message from ${message.source}: "${message.content.substring(0, 50)}"`);
    console.log(`[Engine] Using model: ${model.config.id} (${model.config.provider})`);

    while (turns < this.maxToolTurns) {
      turns++;

      // Call the model
      console.log(`[Engine] Calling model (turn ${turns})...`);
      const response = await model.complete(
        {
          system: conversation.system,
          messages: conversation.messages,
        },
        {
          ...toolDefs,
          maxTokens: 8192,
        }
      );

      // Parse tool calls from response (handle both Anthropic and OpenAI formats)
      const toolCalls = this.parseToolCalls(response, provider);

      console.log(`[Engine] Response: content="${(response.content || '').substring(0, 80)}", toolCalls=${toolCalls.length}`);

      if (toolCalls.length === 0) {
        // No tool calls — model is done
        finalContent = response.content ?? "";
        console.log(`[Engine] Final content (${finalContent.length} chars): "${finalContent.substring(0, 100)}"`);
        break;
      }

      // Add assistant message with tool calls to conversation
      conversation.messages.push({
        role: "assistant" as const,
        content: response.content ?? "",
        tool_calls: toolCalls.map((tc) => ({
          id: tc.id,
          type: "function" as const,
          function: { name: tc.name, arguments: JSON.stringify(tc.input) },
        })),
      });

      // Execute each tool call
      for (const toolCall of toolCalls) {
        if (totalToolCalls >= this.maxToolCalls) {
          conversation.messages.push({
            role: "tool" as const,
            content: "[Tool call limit reached. Provide your final answer now.]",
            tool_call_id: toolCall.id,
          });
          break;
        }

        totalToolCalls++;

        const result = await this.tools.execute({
          id: toolCall.id,
          tool: toolCall.name,
          args: toolCall.input,
        });

        // Add tool result to conversation
        conversation.messages.push({
          role: "tool" as const,
          content: formatToolResult(result),
          tool_call_id: toolCall.id,
        });
      }

      // If we hit the tool call limit, break
      if (totalToolCalls >= this.maxToolCalls) {
        // One more model call to get final answer
        const finalResponse = await model.complete(
          {
            system: conversation.system,
            messages: conversation.messages,
          },
          { maxTokens: 4096 }
        );
        finalContent = finalResponse.content ?? "[Tool call limit reached]";
        break;
      }
    }

    // If we exhausted turns
    if (turns >= this.maxToolTurns && !finalContent) {
      conversation.messages.push({
        role: "system" as const,
        content: "[Maximum tool-use turns reached. Provide your final response now.]",
      });

      const finalResponse = await model.complete(
        {
          system: conversation.system,
          messages: conversation.messages,
        },
        { maxTokens: 4096 }
      );
      finalContent = finalResponse.content ?? "[Max turns reached]";
    }

    // ── Step 6: Store in memory ──────────────────────────────────────
    await this.memory.store(
      `conversation:${Date.now()}`,
      JSON.stringify({ user: message.content, assistant: finalContent, toolCalls: totalToolCalls }),
      "medium",
      "system"
    );

    // ── Step 7: Check for skill improvement ──────────────────────────
    const responseMsg: Message = {
      role: "assistant",
      content: finalContent,
      timestamp: Date.now(),
    };

    await this.skills.checkForImprovement(message, responseMsg);

    return {
      message: responseMsg,
      toolCallsMade: totalToolCalls,
      turns,
      model: model.config.id,
      durationMs: Date.now() - startTime,
    };
  }

  // ─── Tool Call Parsing ─────────────────────────────────────────────────

  /**
   * Parse tool calls from model response — handles Anthropic, OpenAI, and generic formats.
   */
  private parseToolCalls(response: any, provider: string): ParsedToolCall[] {
    const calls: ParsedToolCall[] = [];

    // Anthropic format: response.content is an array with tool_use blocks
    if (Array.isArray(response.content)) {
      for (const block of response.content) {
        if (block.type === "tool_use") {
          calls.push({
            id: block.id ?? `call_${Date.now()}_${calls.length}`,
            name: block.name,
            input: block.input ?? {},
          });
        }
      }
      return calls;
    }

    // OpenAI format: response.tool_calls array
    if (Array.isArray(response.tool_calls)) {
      for (const tc of response.tool_calls) {
        const fn = tc.function ?? tc;
        calls.push({
          id: tc.id ?? `call_${Date.now()}_${calls.length}`,
          name: fn.name,
          input: typeof fn.arguments === "string"
            ? safeJsonParse(fn.arguments)
            : fn.arguments ?? {},
        });
      }
      return calls;
    }

    // Generic: response.toolCalls array (our internal format)
    if (Array.isArray(response.toolCalls)) {
      for (const tc of response.toolCalls) {
        calls.push({
          id: tc.id ?? `call_${Date.now()}_${calls.length}`,
          name: tc.tool ?? tc.name,
          input: tc.args ?? tc.input ?? {},
        });
      }
      return calls;
    }

    return calls;
  }

  // ─── Conversation Building ─────────────────────────────────────────────

  private buildConversation(
    message: Message,
    context: any[]
  ): { system: string; messages: any[] } {
    const os = require("os");
    const home = os.homedir();
    const platform = os.platform(); // darwin, linux, win32
    const hostname = os.hostname();
    const arch = os.arch();
    const totalMem = Math.round(os.totalmem() / 1024 / 1024 / 1024);
    const cpus = os.cpus().length;

    const platformName = platform === "darwin" ? "macOS" : platform === "win32" ? "Windows" : "Linux";
    const commonPaths = platform === "darwin"
      ? `~/Downloads, ~/Desktop, ~/Documents, ~/Library`
      : platform === "win32"
        ? `C:\\Users\\<user>\\Downloads, Desktop, Documents`
        : `~/Downloads, ~/Desktop, ~/Documents, /etc, /opt`;

    // Per-user sandbox detection
    const OWNER_ID = "1780375318"; // Guy
    const userId = message.source?.split(":")[1] || "";
    const isOwner = userId === OWNER_ID || userId === "7636952147"; // Guy or Lyrie (wife)
    const USER_SANDBOXES: Record<string, string> = {
      "7640328890": `${home}/.lyrie/users/cortez`,  // Cortez @iamcortez
      "337659894": `${home}/.lyrie/users/josh`,      // Josh @yamaSC
    };
    const userSandbox = USER_SANDBOXES[userId];
    const workingDir = isOwner ? home : (userSandbox || `${home}/.lyrie/users/guest`);
    const sandboxNote = isOwner
      ? `You have full access to the system. Working directory: ${home}`
      : `You are in a sandboxed workspace: ${workingDir}. All file operations MUST stay within this directory. You CANNOT access files outside your sandbox.`;

    // Update shield paths for sandboxed users
    if (!isOwner && userSandbox) {
      this.shield.setScopedPaths([userSandbox, "/tmp"]);
    } else {
      this.shield.resetPaths();
    }

    const systemPrompt = `You are Lyrie, an autonomous AI agent with built-in cybersecurity capabilities.
Built by OTT Cybersecurity LLC. You protect while you help.
You are sharp, direct, and proactive. You never ask unnecessary questions — you execute.

${sandboxNote}

System Info (auto-detected):
- OS: ${platformName} (${platform}/${arch})
- Hostname: ${hostname}
- Working Directory: ${workingDir}
- CPU: ${cpus} cores
- RAM: ${totalMem}GB
- Common paths: ${isOwner ? commonPaths : workingDir}

You have access to these tools:
${this.tools
  .listNames()
  .map((n) => `- ${n}`)
  .join("\n")}

When you need to act on the world (read files, execute commands, search the web, scan for threats), use your tools.
Always use real absolute paths based on the detected home directory: ${home}
Never guess paths. Use the detected OS to choose correct commands (e.g. ls on macOS/Linux, dir on Windows).
Always verify your work. Show results, not promises.`;

    const messages: any[] = [];

    // Add memory context
    if (context.length > 0) {
      const contextStr = context
        .map((c) => (typeof c === "string" ? c : JSON.stringify(c)))
        .join("\n");
      messages.push({
        role: "system" as const,
        content: `[Relevant Memory]\n${contextStr}`,
      });
    }

    // Add user message
    messages.push({ role: "user" as const, content: message.content });

    return { system: systemPrompt, messages };
  }

  // ─── Sub-Agent Delegation ──────────────────────────────────────────────

  /**
   * Spawn a sub-agent for a task.
   */
  async spawnSubAgent(
    instruction: string,
    input: string,
    options?: { timeout?: number; model?: ModelInstance; context?: string[] }
  ) {
    return this.subAgents.spawn({
      id: `sub-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      instruction,
      input,
      model: options?.model,
      timeout: options?.timeout,
      context: options?.context,
    });
  }

  /**
   * Spawn multiple sub-agents in parallel.
   */
  async spawnSubAgents(
    tasks: Array<{ instruction: string; input: string; context?: string[] }>
  ) {
    return this.subAgents.spawnAll(
      tasks.map((t, i) => ({
        id: `sub-${Date.now()}-${i}`,
        instruction: t.instruction,
        input: t.input,
        context: t.context,
      }))
    );
  }

  // ─── Cron Access ───────────────────────────────────────────────────────

  /**
   * Get the cron manager for scheduling tasks.
   */
  getCron(): CronManager | null {
    return this.cron;
  }

  // ─── Accessors ─────────────────────────────────────────────────────────

  getTools(): ToolExecutor {
    return this.tools;
  }

  getSubAgents(): SubAgentManager {
    return this.subAgents;
  }

  get running(): boolean {
    return this.isRunning;
  }

  /**
   * Get engine stats.
   */
  stats(): {
    requestsProcessed: number;
    toolStats: ReturnType<ToolExecutor["stats"]>;
    subAgentStats: ReturnType<SubAgentManager["stats"]>;
    cronStats: ReturnType<CronManager["stats"]> | null;
  } {
    return {
      requestsProcessed: this.requestCount,
      toolStats: this.tools.stats(),
      subAgentStats: this.subAgents.stats(),
      cronStats: this.cron?.stats() ?? null,
    };
  }

  /**
   * Shutdown the engine cleanly.
   */
  async shutdown(): Promise<void> {
    this.isRunning = false;
    if (this.cron) await this.cron.shutdown();
    await this.subAgents.shutdown();
    console.log("[engine] LyrieEngine shut down");
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatToolResult(result: ToolResult): string {
  if (result.success) {
    return result.output || "[success, no output]";
  }
  return `Error: ${result.error ?? "Unknown error"}\n${result.output ?? ""}`.trim();
}

function safeJsonParse(str: string): Record<string, any> {
  try {
    return JSON.parse(str);
  } catch {
    return { raw: str };
  }
}
