/**
 * ToolExecutor — Secure tool execution for Lyrie Agent.
 * 
 * Every tool call goes through the Shield before execution.
 * Tools are the agent's hands — this is how Lyrie acts on the world.
 */

import { ShieldManager } from "../engine/shield-manager";

export interface Tool {
  name: string;
  description: string;
  parameters: Record<string, any>;
  execute: (args: any) => Promise<any>;
  risk: "safe" | "moderate" | "dangerous";
}

export interface ToolCall {
  tool: string;
  args: any;
}

export class ToolExecutor {
  private shield: ShieldManager;
  private tools: Map<string, Tool> = new Map();

  constructor(shield: ShieldManager) {
    this.shield = shield;
  }

  async initialize(): Promise<void> {
    // Register built-in tools
    this.register({
      name: "read_file",
      description: "Read the contents of a file",
      parameters: { path: "string" },
      risk: "safe",
      execute: async (args) => {
        const { readFileSync } = await import("fs");
        return readFileSync(args.path, "utf-8");
      },
    });

    this.register({
      name: "write_file",
      description: "Write content to a file",
      parameters: { path: "string", content: "string" },
      risk: "moderate",
      execute: async (args) => {
        const { writeFileSync } = await import("fs");
        writeFileSync(args.path, args.content, "utf-8");
        return `Written ${args.content.length} bytes to ${args.path}`;
      },
    });

    this.register({
      name: "exec",
      description: "Execute a shell command",
      parameters: { command: "string", timeout: "number" },
      risk: "dangerous",
      execute: async (args) => {
        const { execSync } = await import("child_process");
        const timeout = args.timeout || 30000;
        const result = execSync(args.command, { timeout, encoding: "utf-8" });
        return result;
      },
    });

    this.register({
      name: "web_search",
      description: "Search the web",
      parameters: { query: "string" },
      risk: "safe",
      execute: async (args) => {
        // TODO: Integrate with search API
        return `Search results for: ${args.query}`;
      },
    });

    this.register({
      name: "threat_scan",
      description: "Scan a file or URL for security threats",
      parameters: { target: "string", type: "file | url" },
      risk: "safe",
      execute: async (args) => {
        if (args.type === "file") {
          return this.shield.scanFile(args.target);
        } else {
          return this.shield.scanUrl(args.target);
        }
      },
    });

    console.log(`   → ${this.tools.size} tools registered`);
  }

  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  async execute(call: ToolCall): Promise<any> {
    const tool = this.tools.get(call.tool);
    if (!tool) {
      throw new Error(`Unknown tool: ${call.tool}`);
    }

    // Shield validation before execution
    const allowed = await this.shield.validateToolCall({
      tool: call.tool,
      args: call.args,
      risk: tool.risk,
    });

    if (!allowed) {
      throw new Error(`Shield blocked tool call: ${call.tool}`);
    }

    return tool.execute(call.args);
  }

  available(): Tool[] {
    return Array.from(this.tools.values());
  }
}
