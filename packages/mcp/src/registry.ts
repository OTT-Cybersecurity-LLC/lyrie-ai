/**
 * McpRegistry — load mcp.json, manage a fleet of McpClient instances, and
 * expose an aggregated tool catalog to the Lyrie tool executor.
 *
 * The registry is intentionally additive: if no mcp.json is present, the
 * registry is empty and nothing changes about Lyrie's behavior.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { McpClient } from "./client";
import type {
  CallToolResult,
  McpConfigFile,
  McpServerConfig,
  Tool,
  Transport,
} from "./types";

export interface RegisteredTool {
  /** Fully-qualified name surfaced to the agent: mcp:<server>:<tool> */
  qualifiedName: string;
  /** Server name (registry key) */
  server: string;
  tool: Tool;
}

export interface McpRegistryOptions {
  configPath?: string;
  configInline?: McpConfigFile;
}

export class McpRegistry {
  private clients = new Map<string, McpClient>();
  private tools: RegisteredTool[] = [];

  static defaultConfigPath(): string {
    return join(homedir(), ".lyrie", "mcp.json");
  }

  static loadConfig(path: string): McpConfigFile | null {
    if (!existsSync(path)) return null;
    try {
      return JSON.parse(readFileSync(path, "utf8")) as McpConfigFile;
    } catch (err) {
      console.warn(`[mcp] failed to parse ${path}:`, err);
      return null;
    }
  }

  /**
   * Convert a raw McpServerConfig into a Transport. Pure function for testing.
   */
  static toTransport(cfg: McpServerConfig): Transport {
    if (cfg.url) {
      return {
        type: cfg.transportType === "sse" ? "sse" : "http",
        url: cfg.url,
        headers: cfg.headers,
      };
    }
    if (cfg.command) {
      return {
        type: "stdio",
        command: cfg.command,
        args: cfg.args,
        env: cfg.env,
        cwd: cfg.cwd,
      };
    }
    throw new Error("McpServerConfig requires either url or command");
  }

  async loadFrom(opts: McpRegistryOptions = {}): Promise<void> {
    const path = opts.configPath ?? McpRegistry.defaultConfigPath();
    const config = opts.configInline ?? McpRegistry.loadConfig(path);
    if (!config?.mcpServers) return;

    for (const [name, cfg] of Object.entries(config.mcpServers)) {
      if (cfg.disabled) continue;
      try {
        const client = new McpClient({
          name,
          transport: McpRegistry.toTransport(cfg),
        });
        await client.connect();
        const tools = (await client.listTools()).filter((t) => {
          if (cfg.denyTools?.includes(t.name)) return false;
          if (cfg.allowTools && !cfg.allowTools.includes(t.name)) return false;
          return true;
        });
        this.clients.set(name, client);
        for (const tool of tools) {
          this.tools.push({
            qualifiedName: `mcp:${name}:${tool.name}`,
            server: name,
            tool,
          });
        }
      } catch (err) {
        console.warn(`[mcp] failed to connect server "${name}":`, err);
      }
    }
  }

  list(): RegisteredTool[] {
    return [...this.tools];
  }

  servers(): string[] {
    return Array.from(this.clients.keys());
  }

  async call(qualifiedName: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const match = qualifiedName.match(/^mcp:([^:]+):(.+)$/);
    if (!match) throw new Error(`not an MCP-qualified tool name: ${qualifiedName}`);
    const [, server, tool] = match;
    const client = this.clients.get(server);
    if (!client) throw new Error(`unknown MCP server: ${server}`);
    return await client.callTool(tool, args);
  }

  async shutdown(): Promise<void> {
    await Promise.all(Array.from(this.clients.values()).map((c) => c.disconnect()));
    this.clients.clear();
    this.tools = [];
  }
}
