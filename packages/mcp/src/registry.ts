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
import { ShieldGuard, type ShieldGuardLike } from "@lyrie/core";

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
  /** Shield guard used to scan tool results before they reach the agent. */
  shield?: ShieldGuardLike;
}

export class McpRegistry {
  private clients = new Map<string, McpClient>();
  private tools: RegisteredTool[] = [];
  private shield: ShieldGuardLike = ShieldGuard.fallback();

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
    if (opts.shield) this.shield = opts.shield;
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

    const raw = await client.callTool(tool, args);
    return this.shieldFilter(qualifiedName, raw);
  }

  /**
   * Shield-gate tool results. MCP servers are third-party processes — they
   * can absolutely return prompt-injection payloads (intentionally or
   * accidentally). Every text/resource block is scanned before it reaches
   * the agent. Blocked content is replaced with a Shield notice; non-text
   * content (images, binaries) passes through.
   */
  private shieldFilter(qualifiedName: string, result: CallToolResult): CallToolResult {
    if (!result?.content) return result;
    const filtered = result.content.map((block: any) => {
      if (block?.type === "text" && typeof block.text === "string") {
        const verdict = this.shield.scanRecalled(block.text);
        if (verdict.blocked) {
          return {
            type: "text",
            text: `⚠️ Lyrie Shield redacted MCP output from ${qualifiedName}: ${verdict.reason ?? "unsafe content"}`,
          };
        }
      }
      if (block?.type === "resource" && typeof block?.resource?.text === "string") {
        const verdict = this.shield.scanRecalled(block.resource.text);
        if (verdict.blocked) {
          return {
            type: "text",
            text: `⚠️ Lyrie Shield redacted MCP resource from ${qualifiedName}: ${verdict.reason ?? "unsafe content"}`,
          };
        }
      }
      return block;
    });
    return { ...result, content: filtered };
  }

  async shutdown(): Promise<void> {
    await Promise.all(Array.from(this.clients.values()).map((c) => c.disconnect()));
    this.clients.clear();
    this.tools = [];
  }
}
