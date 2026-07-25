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
import { ShieldGuard, type ShieldGuardLike, MCPSecurityScanner, AgenticThreatBridge } from "@lyrie/core";
import type { MCPScannerOptions } from "@lyrie/core";

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
  /** Options for the pre-connection MCP security scanner. */
  scannerOptions?: MCPScannerOptions;
  /**
   * What to do when the scanner returns a critical finding:
   *   "block"  — throw; do not connect (default)
   *   "warn"   — log a warning but continue connecting
   */
  onCritical?: "block" | "warn";
  /**
   * How `shieldFilter` reacts to a critical verdict from the Rust
   * agentic-threat bridge (self-propagation write paths, base64/unicode-
   * confusable prompt injection):
   *   "redact" — replace the offending block with a Shield notice (default,
   *              matches existing ShieldGuard.scanRecalled behavior)
   *   "block"  — throw, rejecting the entire tool call
   */
  mode?: "redact" | "block";
  /** Agentic-threat bridge instance (Rust detector via subprocess). Injectable for tests. */
  agenticBridge?: AgenticThreatBridge;
}

export class McpRegistry {
  private clients = new Map<string, McpClient>();
  private tools: RegisteredTool[] = [];
  private shield: ShieldGuardLike = ShieldGuard.fallback();
  private scanner = new MCPSecurityScanner();
  private agenticBridge: AgenticThreatBridge = new AgenticThreatBridge();
  private mode: "redact" | "block" = "redact";

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
    if (opts.agenticBridge) this.agenticBridge = opts.agenticBridge;
    if (opts.mode) this.mode = opts.mode;
    const path = opts.configPath ?? McpRegistry.defaultConfigPath();
    const config = opts.configInline ?? McpRegistry.loadConfig(path);
    if (!config?.mcpServers) return;

    const onCritical = opts.onCritical ?? "block";
    this.scanner = new MCPSecurityScanner(opts.scannerOptions ?? {});

    for (const [name, cfg] of Object.entries(config.mcpServers)) {
      if (cfg.disabled) continue;
      try {
        // ── Pre-connection security scan ─────────────────────────────────
        const scanResult = await this.scanner.scan({ name, ...cfg });
        if (!scanResult.safe) {
          const findingsSummary = scanResult.findings
            .map((f) => `[${f.severity}] ${f.check}: ${f.description}`)
            .join("\n");
          if (scanResult.riskLevel === "critical") {
            const msg = `[mcp] BLOCKED server "${name}" — MCPSecurityScanner critical finding:\n${findingsSummary}`;
            if (onCritical === "block") {
              console.error(msg);
              continue; // skip this server entirely
            } else {
              console.warn(msg);
            }
          } else {
            console.warn(
              `[mcp] WARNING: server "${name}" has security findings (riskLevel=${scanResult.riskLevel}):\n${findingsSummary}`,
            );
          }
        }
        // ── End security scan ─────────────────────────────────────────────

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
    return this.shieldFilter(qualifiedName, raw, args);
  }

  /**
   * Shield-gate tool results. MCP servers are third-party processes — they
   * can absolutely return prompt-injection payloads (intentionally or
   * accidentally). Every text/resource block is scanned before it reaches
   * the agent, through two layers:
   *
   *   1. `ShieldGuard.scanRecalled()` (JS heuristics) — unchanged behavior,
   *      catches classic prompt-injection/credential patterns.
   *   2. The Rust `AgenticThreatDetector` bridge (broader regex set,
   *      base64/unicode-confusable injection, self-propagation write-path
   *      detection). Runs on tool-result text/resource blocks AND on any
   *      string-valued tool-call argument that looks like a file path
   *      (covers e.g. a filesystem-write MCP tool being pointed at
   *      `.cursorrules`/`AGENTS.md`/a vector-store path).
   *
   * In `"redact"` mode (default) a blocked/critical block is replaced with
   * a Shield notice; non-text content (images, binaries) always passes
   * through untouched. In `"block"` mode, a critical verdict from either
   * layer throws instead, rejecting the whole tool call.
   */
  private async shieldFilter(
    qualifiedName: string,
    result: CallToolResult,
    args?: Record<string, unknown>,
  ): Promise<CallToolResult> {
    // ── Tool-call argument scan: self-propagation / AI-sink write paths ──
    if (args && this.agenticBridge.isAvailable()) {
      for (const [key, value] of Object.entries(args)) {
        if (typeof value !== "string" || value.length === 0) continue;
        const resp = await this.agenticBridge.run({ writePath: value, sensitiveRead: true });
        const finding = resp?.self_propagation ?? resp?.ai_sink_write;
        if (finding && finding.severity === "critical") {
          const msg = `⚠️ Lyrie Shield blocked MCP call ${qualifiedName} — argument "${key}" is a self-propagation write path: ${finding.description}`;
          if (this.mode === "block") {
            throw new Error(msg);
          }
          return { content: [{ type: "text", text: msg }] };
        }
      }
    }

    if (!result?.content) return result;

    const filtered: CallToolResult["content"] = [];
    for (const block of result.content as any[]) {
      const text: string | undefined =
        block?.type === "text" && typeof block.text === "string"
          ? block.text
          : block?.type === "resource" && typeof block?.resource?.text === "string"
            ? block.resource.text
            : undefined;

      if (text === undefined) {
        filtered.push(block);
        continue;
      }

      // Layer 1: JS heuristic ShieldGuard (unchanged existing behavior).
      const verdict = this.shield.scanRecalled(text);
      if (verdict.blocked) {
        const msg = `⚠️ Lyrie Shield redacted MCP ${block.type === "resource" ? "resource" : "output"} from ${qualifiedName}: ${verdict.reason ?? "unsafe content"}`;
        if (this.mode === "block" && verdict.severity === "critical") {
          throw new Error(msg);
        }
        filtered.push({ type: "text", text: msg });
        continue;
      }

      // Layer 2: Rust AgenticThreatDetector bridge — broader pattern set.
      if (this.agenticBridge.isAvailable()) {
        const finding = await this.agenticBridge.scanForPromptInjection(text);
        if (finding) {
          const msg = `⚠️ Lyrie Shield redacted MCP ${block.type === "resource" ? "resource" : "output"} from ${qualifiedName}: ${finding.description}`;
          if (this.mode === "block" && finding.severity === "critical") {
            throw new Error(msg);
          }
          filtered.push({ type: "text", text: msg });
          continue;
        }
      }

      filtered.push(block);
    }

    return { ...result, content: filtered };
  }

  async shutdown(): Promise<void> {
    await Promise.all(Array.from(this.clients.values()).map((c) => c.disconnect()));
    this.clients.clear();
    this.tools = [];
  }
}
