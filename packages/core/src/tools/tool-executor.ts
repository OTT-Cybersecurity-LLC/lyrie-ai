/**
 * ToolExecutor — Secure tool execution for Lyrie Agent.
 *
 * Every tool call goes through the Shield before execution.
 * Tools are the agent's hands — this is how Lyrie acts on the world.
 *
 * Built-in tools:
 *   exec          — Shell command execution (Shield-gated)
 *   read_file     — Read file contents (path-scoped)
 *   write_file    — Write/create files (path-scoped)
 *   list_directory— Directory listing
 *   web_search    — Brave Search API with DuckDuckGo fallback
 *   web_fetch     — Fetch & extract content from URLs
 *   threat_scan   — Shield-powered threat scanning
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { ShieldManager } from "../engine/shield-manager";
import { ShieldGuard, type ShieldGuardLike } from "../engine/shield-guard";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ToolParameter {
  type: "string" | "number" | "boolean" | "object" | "array";
  description: string;
  required?: boolean;
  default?: any;
  enum?: string[];
}

export interface Tool {
  name: string;
  description: string;
  parameters: Record<string, ToolParameter>;
  execute: (args: Record<string, any>) => Promise<ToolResult>;
  risk: "safe" | "moderate" | "dangerous";
  /**
   * Shield Doctrine: if the tool returns text the agent will read but did
   * NOT author (e.g. web fetch, web search, shell stdout, file read), set
   * this to true. The executor runs every successful result through the
   * Shield's `scanRecalled` and redacts unsafe content before it reaches
   * the model.
   */
  untrustedOutput?: boolean;
}

export interface ToolCall {
  id: string;
  tool: string;
  args: Record<string, any>;
}

export interface ToolResult {
  success: boolean;
  output: string;
  error?: string;
  metadata?: Record<string, any>;
}

/** Anthropic tool_use format */
export interface AnthropicToolDef {
  name: string;
  description: string;
  input_schema: {
    type: "object";
    properties: Record<string, any>;
    required: string[];
  };
}

/** OpenAI function calling format */
export interface OpenAIToolDef {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: {
      type: "object";
      properties: Record<string, any>;
      required: string[];
    };
  };
}

// ─── Executor ────────────────────────────────────────────────────────────────

export class ToolExecutor {
  private shield: ShieldManager;
  private tools: Map<string, Tool> = new Map();
  private executionLog: Array<{
    tool: string;
    args: Record<string, any>;
    success: boolean;
    durationMs: number;
    timestamp: number;
  }> = [];
  private maxLogSize = 1000;

  constructor(shield: ShieldManager) {
    this.shield = shield;
  }

  async initialize(): Promise<void> {
    this.registerBuiltinTools();
    console.log(`   → ${this.tools.size} tools registered`);
  }

  // ─── Built-in Tool Registration ──────────────────────────────────────────

  private registerBuiltinTools(): void {
    // ── exec ──────────────────────────────────────────────────────────────
    this.register({
      // Shield Doctrine: shell stdout is untrusted text — redact prompt-injection.
      untrustedOutput: true,
      name: "exec",
      description:
        "Execute a shell command. Returns stdout. Commands are scanned by Shield before execution. Max timeout 120s.",
      parameters: {
        command: {
          type: "string",
          description: "The shell command to execute",
          required: true,
        },
        timeout: {
          type: "number",
          description: "Timeout in milliseconds (default: 30000, max: 120000)",
          default: 30000,
        },
        cwd: {
          type: "string",
          description: "Working directory for the command",
        },
      },
      risk: "dangerous",
      execute: async (args) => {
        const { spawn } = await import("child_process");
        const timeout = Math.min(args.timeout ?? 30000, 120000);
        const cwd = args.cwd ?? process.cwd();

        return new Promise<ToolResult>((resolve) => {
          const chunks: Buffer[] = [];
          const errChunks: Buffer[] = [];
          let killed = false;

          const proc = spawn("sh", ["-c", args.command], {
            cwd,
            timeout,
            env: { ...process.env, TERM: "dumb" },
            stdio: ["ignore", "pipe", "pipe"],
          });

          proc.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
          proc.stderr.on("data", (chunk: Buffer) => errChunks.push(chunk));

          const timer = setTimeout(() => {
            killed = true;
            proc.kill("SIGKILL");
          }, timeout);

          proc.on("close", (code) => {
            clearTimeout(timer);
            const stdout = Buffer.concat(chunks).toString("utf-8");
            const stderr = Buffer.concat(errChunks).toString("utf-8");

            // Truncate large outputs
            const maxLen = 100_000;
            const output = stdout.length > maxLen
              ? stdout.slice(0, maxLen) + `\n[truncated: ${stdout.length - maxLen} bytes omitted]`
              : stdout;

            if (killed) {
              resolve({
                success: false,
                output: output || stderr,
                error: `Command timed out after ${timeout}ms`,
                metadata: { exitCode: code, killed: true },
              });
            } else if (code !== 0) {
              resolve({
                success: false,
                output: output || stderr,
                error: `Exit code ${code}: ${stderr.slice(0, 2000)}`,
                metadata: { exitCode: code },
              });
            } else {
              resolve({
                success: true,
                output,
                metadata: { exitCode: 0, stderrLen: stderr.length },
              });
            }
          });

          proc.on("error", (err) => {
            clearTimeout(timer);
            resolve({
              success: false,
              output: "",
              error: `Spawn error: ${err.message}`,
            });
          });
        });
      },
    });

    // ── read_file ─────────────────────────────────────────────────────────
    this.register({
      // Shield Doctrine: file contents may contain attacker-controlled text.
      untrustedOutput: true,
      name: "read_file",
      description:
        "Read the contents of a file. Supports text files. Path must be within allowed workspace.",
      parameters: {
        path: {
          type: "string",
          description: "Absolute or relative path to the file",
          required: true,
        },
        offset: {
          type: "number",
          description: "Line number to start reading from (1-indexed)",
        },
        limit: {
          type: "number",
          description: "Maximum number of lines to read",
        },
      },
      risk: "safe",
      execute: async (args) => {
        const { readFile, stat } = await import("fs/promises");
        const { resolve: resolvePath } = await import("path");

        const fullPath = resolvePath(args.path);

        try {
          const fileStat = await stat(fullPath);

          // Limit: 10MB max
          if (fileStat.size > 10 * 1024 * 1024) {
            return {
              success: false,
              output: "",
              error: `File too large: ${(fileStat.size / 1024 / 1024).toFixed(1)}MB (max 10MB). Use offset/limit for partial reads.`,
            };
          }

          let content = await readFile(fullPath, "utf-8");

          // Apply offset/limit if specified
          if (args.offset || args.limit) {
            const lines = content.split("\n");
            const start = Math.max(0, (args.offset ?? 1) - 1);
            const end = args.limit ? start + args.limit : lines.length;
            content = lines.slice(start, end).join("\n");
          }

          return {
            success: true,
            output: content,
            metadata: { size: fileStat.size, path: fullPath },
          };
        } catch (err: any) {
          return {
            success: false,
            output: "",
            error: `Failed to read ${fullPath}: ${err.message}`,
          };
        }
      },
    });

    // ── write_file ────────────────────────────────────────────────────────
    this.register({
      name: "write_file",
      description:
        "Write content to a file. Creates the file and parent directories if they don't exist. Overwrites if exists.",
      parameters: {
        path: {
          type: "string",
          description: "Absolute or relative path to the file",
          required: true,
        },
        content: {
          type: "string",
          description: "Content to write to the file",
          required: true,
        },
        append: {
          type: "boolean",
          description: "Append instead of overwrite (default: false)",
          default: false,
        },
      },
      risk: "moderate",
      execute: async (args) => {
        const { writeFile, appendFile, mkdir } = await import("fs/promises");
        const { resolve: resolvePath, dirname } = await import("path");

        const fullPath = resolvePath(args.path);

        try {
          // Ensure parent directory exists
          await mkdir(dirname(fullPath), { recursive: true });

          if (args.append) {
            await appendFile(fullPath, args.content, "utf-8");
          } else {
            await writeFile(fullPath, args.content, "utf-8");
          }

          return {
            success: true,
            output: `Written ${args.content.length} bytes to ${fullPath}${args.append ? " (appended)" : ""}`,
            metadata: { path: fullPath, bytes: args.content.length },
          };
        } catch (err: any) {
          return {
            success: false,
            output: "",
            error: `Failed to write ${fullPath}: ${err.message}`,
          };
        }
      },
    });

    // ── list_directory ────────────────────────────────────────────────────
    this.register({
      name: "list_directory",
      description:
        "List files and directories in a given path. Returns names, types, and sizes.",
      parameters: {
        path: {
          type: "string",
          description: "Directory path to list",
          required: true,
        },
        recursive: {
          type: "boolean",
          description: "List recursively (max 3 levels deep)",
          default: false,
        },
        maxEntries: {
          type: "number",
          description: "Maximum entries to return (default: 500)",
          default: 500,
        },
      },
      risk: "safe",
      execute: async (args) => {
        const { readdir, stat } = await import("fs/promises");
        const { resolve: resolvePath, join } = await import("path");

        const fullPath = resolvePath(args.path);
        const maxEntries = args.maxEntries ?? 500;
        const results: string[] = [];

        const listDir = async (dir: string, depth: number): Promise<void> => {
          if (results.length >= maxEntries) return;
          if (args.recursive && depth > 3) return;

          try {
            const entries = await readdir(dir, { withFileTypes: true });

            for (const entry of entries) {
              if (results.length >= maxEntries) break;

              const entryPath = join(dir, entry.name);
              const relPath = entryPath.replace(fullPath, "").replace(/^\//, "");
              const prefix = entry.isDirectory() ? "📁 " : "📄 ";

              try {
                const s = await stat(entryPath);
                const sizeStr = entry.isDirectory()
                  ? ""
                  : ` (${formatBytes(s.size)})`;
                results.push(`${prefix}${relPath || entry.name}${sizeStr}`);
              } catch {
                results.push(`${prefix}${relPath || entry.name}`);
              }

              if (args.recursive && entry.isDirectory()) {
                await listDir(entryPath, depth + 1);
              }
            }
          } catch (err: any) {
            results.push(`❌ Error reading ${dir}: ${err.message}`);
          }
        };

        await listDir(fullPath, 0);

        const truncated = results.length >= maxEntries
          ? `\n[truncated: showing first ${maxEntries} entries]`
          : "";

        return {
          success: true,
          output: results.join("\n") + truncated,
          metadata: { path: fullPath, count: results.length },
        };
      },
    });

    // ── web_search ────────────────────────────────────────────────────────
    this.register({
      // Shield Doctrine: third-party search snippets are untrusted text.
      untrustedOutput: true,
      name: "web_search",
      description:
        "Search the web using Brave Search API. Falls back to DuckDuckGo HTML scraping if no API key. Returns titles, URLs, and snippets.",
      parameters: {
        query: {
          type: "string",
          description: "Search query",
          required: true,
        },
        count: {
          type: "number",
          description: "Number of results (default: 5, max: 10)",
          default: 5,
        },
      },
      risk: "safe",
      execute: async (args) => {
        const count = Math.min(args.count ?? 5, 10);

        // Try Brave Search API first
        const braveKey = process.env.BRAVE_SEARCH_API_KEY;
        if (braveKey) {
          try {
            return await braveSearch(args.query, count, braveKey);
          } catch (err: any) {
            console.warn(`Brave Search failed, falling back: ${err.message}`);
          }
        }

        // Fallback: DuckDuckGo HTML scraping
        try {
          return await ddgFallback(args.query, count);
        } catch (err: any) {
          return {
            success: false,
            output: "",
            error: `Web search failed: ${err.message}`,
          };
        }
      },
    });

    // ── web_fetch ─────────────────────────────────────────────────────────
    this.register({
      // Shield Doctrine: scraped web content is the #1 prompt-injection vector.
      untrustedOutput: true,
      name: "web_fetch",
      description:
        "Fetch a URL and extract readable content. Strips HTML to plain text/markdown. Max 200KB response.",
      parameters: {
        url: {
          type: "string",
          description: "URL to fetch",
          required: true,
        },
        maxChars: {
          type: "number",
          description: "Maximum characters to return (default: 50000)",
          default: 50000,
        },
        raw: {
          type: "boolean",
          description: "Return raw HTML instead of extracted text",
          default: false,
        },
      },
      risk: "safe",
      execute: async (args) => {
        const maxChars = args.maxChars ?? 50000;

        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 30000);

          const response = await fetch(args.url, {
            signal: controller.signal,
            headers: {
              "User-Agent":
                "Mozilla/5.0 (compatible; LyrieAgent/0.1; +https://lyrie.ai)",
              Accept: "text/html,application/xhtml+xml,text/plain,application/json",
            },
            redirect: "follow",
          });

          clearTimeout(timeout);

          if (!response.ok) {
            return {
              success: false,
              output: "",
              error: `HTTP ${response.status}: ${response.statusText}`,
              metadata: { status: response.status, url: args.url },
            };
          }

          const contentType = response.headers.get("content-type") ?? "";
          let body = await response.text();

          // Enforce size limit on raw body
          if (body.length > 200_000) {
            body = body.slice(0, 200_000);
          }

          let output: string;

          if (args.raw || !contentType.includes("html")) {
            output = body;
          } else {
            output = extractReadableText(body);
          }

          // Truncate to maxChars
          if (output.length > maxChars) {
            output =
              output.slice(0, maxChars) +
              `\n[truncated: ${output.length - maxChars} chars omitted]`;
          }

          return {
            success: true,
            output,
            metadata: {
              url: args.url,
              contentType,
              length: output.length,
              status: response.status,
            },
          };
        } catch (err: any) {
          return {
            success: false,
            output: "",
            error: `Fetch failed: ${err.message}`,
            metadata: { url: args.url },
          };
        }
      },
    });

    // ── threat_scan ───────────────────────────────────────────────────────
    this.register({
      name: "threat_scan",
      description:
        "Scan a file or URL for security threats using the Shield engine.",
      parameters: {
        target: {
          type: "string",
          description: "File path or URL to scan",
          required: true,
        },
        type: {
          type: "string",
          description: 'Type of target: "file" or "url"',
          required: true,
          enum: ["file", "url"],
        },
      },
      risk: "safe",
      execute: async (args) => {
        const result =
          args.type === "file"
            ? await this.shield.scanFile(args.target)
            : await this.shield.scanUrl(args.target);

        return {
          success: true,
          output: JSON.stringify(result, null, 2),
          metadata: { target: args.target, type: args.type },
        };
      },
    });

    // ── apply_diff ────────────────────────────────────────────────────────
    // Cline-style targeted edits with optional approval gate. Lyrie's
    // existing write_file is preserved unchanged for whole-file writes;
    // apply_diff is the recommended path for in-place edits because every
    // patch produces a unified diff and passes the Shield Doctrine before
    // touching disk.
    this.register({
      name: "apply_diff",
      description:
        "Edit a file by applying targeted oldText→newText replacements. Each oldText must be unique. Returns the unified diff. In `require-approval` mode, the plan is queued for `lyrie edits review`/`approve` instead of applied.",
      parameters: {
        path: {
          type: "string",
          description: "Path to the file (relative to the workspace).",
          required: true,
        },
        edits: {
          type: "array",
          description:
            'Array of { oldText, newText }. Each oldText must appear exactly once in the file.',
          required: true,
        },
        description: {
          type: "string",
          description: "Optional human-friendly description of the edit's intent.",
        },
        mode: {
          type: "string",
          description: 'Override approval mode: "auto-approve" | "require-approval" | "dry-run".',
          enum: ["auto-approve", "require-approval", "dry-run"],
        },
      },
      risk: "moderate",
      execute: async (args) => {
        const engine = this.editEngine ?? (this.editEngine = new EditEngine());
        try {
          const plan = engine.plan({
            path: args.path,
            edits: args.edits,
            description: args.description,
            mode: args.mode as EditApprovalMode | undefined,
          });

          if (plan.shielded) {
            return {
              success: false,
              output: `🛡️ Shield blocked diff: ${plan.shieldReason ?? "unsafe content"}`,
              error: "shield_blocked",
              metadata: { planId: plan.id, shielded: true },
            };
          }
          if (!plan.applicable) {
            return {
              success: false,
              output: `Edit not applicable. Detail: ${JSON.stringify(plan.applicableDetail)}`,
              error: "not_applicable",
              metadata: { planId: plan.id, detail: plan.applicableDetail },
            };
          }

          if (plan.mode === "auto-approve") {
            const applied = engine.apply(plan, true);
            return {
              success: !!applied,
              output: plan.unifiedDiff || "(no changes)",
              metadata: {
                planId: plan.id,
                applied: !!applied,
                bytesBefore: applied?.bytesBefore,
                bytesAfter: applied?.bytesAfter,
              },
            };
          }

          if (plan.mode === "dry-run") {
            return {
              success: true,
              output: plan.unifiedDiff,
              metadata: { planId: plan.id, dryRun: true },
            };
          }

          return {
            success: true,
            output:
              plan.unifiedDiff +
              `\n\n— Pending approval. Run: \`lyrie edits approve ${plan.id}\``,
            metadata: { planId: plan.id, pending: true },
          };
        } catch (err: any) {
          return {
            success: false,
            output: "",
            error: `apply_diff failed: ${err.message}`,
          };
        }
      },
    });
  }

  /** Lazy-initialized EditEngine for the apply_diff tool. */
  private editEngine: EditEngine | null = null;

  /** Inject a custom EditEngine (e.g. with a workspace-pinned root). */
  setEditEngine(engine: EditEngine): void {
    this.editEngine = engine;
  }

  // ─── Public API ────────────────────────────────────────────────────────

  register(tool: Tool): void {
    this.tools.set(tool.name, tool);
  }

  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  /**
   * Execute a tool call with full Shield validation.
   */
  async execute(call: ToolCall): Promise<ToolResult> {
    const startTime = Date.now();
    const tool = this.tools.get(call.tool);

    if (!tool) {
      return {
        success: false,
        output: "",
        error: `Unknown tool: ${call.tool}. Available: ${this.listNames().join(", ")}`,
      };
    }

    // Shield validation before execution
    const allowed = await this.shield.validateToolCall({
      tool: call.tool,
      args: call.args,
      risk: tool.risk,
    });

    if (!allowed) {
      const result: ToolResult = {
        success: false,
        output: "",
        error: `🛡️ Shield blocked tool call: ${call.tool} — insufficient permissions or dangerous operation.`,
      };
      this.logExecution(call.tool, call.args, false, Date.now() - startTime);
      return result;
    }

    try {
      const result = await tool.execute(call.args);
      // Shield Doctrine: scan tool output that the agent will treat as recalled
      // text. Tools opt in via `untrustedOutput: true`. Skipping for failed
      // calls (the error path is operator-visible only).
      const filtered = result.success && tool.untrustedOutput
        ? this.shieldFilterOutput(call.tool, result)
        : result;
      this.logExecution(call.tool, call.args, filtered.success, Date.now() - startTime);
      return filtered;
    } catch (err: any) {
      const result: ToolResult = {
        success: false,
        output: "",
        error: `Tool execution error (${call.tool}): ${err.message}`,
      };
      this.logExecution(call.tool, call.args, false, Date.now() - startTime);
      return result;
    }
  }

  /** Lightweight Shield-guard used to scan untrusted tool output. */
  private outputShield: ShieldGuardLike = ShieldGuard.fallback();

  /** Override the output Shield (e.g. inject a real ShieldManager-backed guard). */
  setOutputShield(guard: ShieldGuardLike): void {
    this.outputShield = guard;
  }

  /**
   * Post-execute Shield filter for untrusted tool output. Redacts (does not
   * drop) so the agent still sees the structural recall — it just can't be
   * hijacked by injected text inside scraped pages, search snippets, or
   * shell stdout.
   */
  private shieldFilterOutput(toolName: string, result: ToolResult): ToolResult {
    if (!result?.output || typeof result.output !== "string") return result;
    const verdict = this.outputShield.scanRecalled(result.output);
    if (!verdict.blocked) return result;
    return {
      ...result,
      output: `⚠️ Lyrie Shield redacted ${toolName} output: ${verdict.reason ?? "unsafe content"}`,
      metadata: {
        ...(result.metadata ?? {}),
        shielded: true,
        shieldReason: verdict.reason,
        shieldSeverity: verdict.severity,
      },
    };
  }

  /**
   * Get all available tools.
   */
  available(): Tool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tool names only.
   */
  listNames(): string[] {
    return Array.from(this.tools.keys());
  }

  /**
   * Format tools for Anthropic's tool_use API.
   */
  toAnthropicFormat(): AnthropicToolDef[] {
    return this.available().map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: {
        type: "object" as const,
        properties: Object.fromEntries(
          Object.entries(tool.parameters).map(([key, param]) => [
            key,
            {
              type: param.type,
              description: param.description,
              ...(param.enum ? { enum: param.enum } : {}),
              ...(param.default !== undefined ? { default: param.default } : {}),
            },
          ])
        ),
        required: Object.entries(tool.parameters)
          .filter(([_, p]) => p.required)
          .map(([k]) => k),
      },
    }));
  }

  /**
   * Format tools for OpenAI's function calling API.
   */
  toOpenAIFormat(): OpenAIToolDef[] {
    return this.available().map((tool) => ({
      type: "function" as const,
      function: {
        name: tool.name,
        description: tool.description,
        parameters: {
          type: "object" as const,
          properties: Object.fromEntries(
            Object.entries(tool.parameters).map(([key, param]) => [
              key,
              {
                type: param.type,
                description: param.description,
                ...(param.enum ? { enum: param.enum } : {}),
              },
            ])
          ),
          required: Object.entries(tool.parameters)
            .filter(([_, p]) => p.required)
            .map(([k]) => k),
        },
      },
    }));
  }

  /**
   * Get execution stats.
   */
  stats(): {
    totalCalls: number;
    successRate: number;
    avgDurationMs: number;
    byTool: Record<string, { calls: number; successes: number }>;
  } {
    const total = this.executionLog.length;
    const successes = this.executionLog.filter((l) => l.success).length;
    const avgMs =
      total > 0
        ? this.executionLog.reduce((sum, l) => sum + l.durationMs, 0) / total
        : 0;

    const byTool: Record<string, { calls: number; successes: number }> = {};
    for (const entry of this.executionLog) {
      if (!byTool[entry.tool]) byTool[entry.tool] = { calls: 0, successes: 0 };
      byTool[entry.tool].calls++;
      if (entry.success) byTool[entry.tool].successes++;
    }

    return {
      totalCalls: total,
      successRate: total > 0 ? successes / total : 0,
      avgDurationMs: Math.round(avgMs),
      byTool,
    };
  }

  // ─── Internal ──────────────────────────────────────────────────────────

  private logExecution(
    tool: string,
    args: Record<string, any>,
    success: boolean,
    durationMs: number
  ): void {
    this.executionLog.push({
      tool,
      args: sanitizeArgs(args),
      success,
      durationMs,
      timestamp: Date.now(),
    });

    // Trim log if it exceeds max
    if (this.executionLog.length > this.maxLogSize) {
      this.executionLog = this.executionLog.slice(-this.maxLogSize);
    }
  }
}

// ─── Helper Functions ────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
}

function sanitizeArgs(args: Record<string, any>): Record<string, any> {
  const result: Record<string, any> = {};
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === "string" && value.length > 500) {
      result[key] = value.slice(0, 200) + `...[${value.length} chars]`;
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Extract readable text from HTML — lightweight, no external deps.
 */
function extractReadableText(html: string): string {
  let text = html;

  // Remove script/style blocks
  text = text.replace(/<script[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<noscript[\s\S]*?<\/noscript>/gi, "");

  // Convert common elements to markdown-ish
  text = text.replace(/<h([1-6])[^>]*>([\s\S]*?)<\/h\1>/gi, (_, level, content) => {
    return "\n" + "#".repeat(parseInt(level)) + " " + content.trim() + "\n";
  });
  text = text.replace(/<br\s*\/?>/gi, "\n");
  text = text.replace(/<\/p>/gi, "\n\n");
  text = text.replace(/<li[^>]*>/gi, "\n• ");
  text = text.replace(/<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, "$2 ($1)");

  // Strip remaining tags
  text = text.replace(/<[^>]+>/g, "");

  // Decode common HTML entities
  text = text
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");

  // Clean up whitespace
  text = text.replace(/\n{3,}/g, "\n\n");
  text = text.replace(/[ \t]+/g, " ");
  text = text
    .split("\n")
    .map((l) => l.trim())
    .join("\n");
  text = text.trim();

  return text;
}

/**
 * Brave Search API.
 */
async function braveSearch(
  query: string,
  count: number,
  apiKey: string
): Promise<ToolResult> {
  const url = new URL("https://api.search.brave.com/res/v1/web/search");
  url.searchParams.set("q", query);
  url.searchParams.set("count", String(count));

  const response = await fetch(url.toString(), {
    headers: {
      "X-Subscription-Token": apiKey,
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Brave API ${response.status}: ${response.statusText}`);
  }

  const data = (await response.json()) as any;
  const results = (data.web?.results ?? []).map(
    (r: any, i: number) =>
      `${i + 1}. ${r.title}\n   ${r.url}\n   ${r.description ?? ""}`
  );

  return {
    success: true,
    output: results.length > 0
      ? results.join("\n\n")
      : `No results found for: ${query}`,
    metadata: { query, count: results.length, source: "brave" },
  };
}

/**
 * DuckDuckGo HTML fallback (no API key needed).
 */
async function ddgFallback(
  query: string,
  count: number
): Promise<ToolResult> {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;

  const response = await fetch(url, {
    headers: {
      "User-Agent":
        "Mozilla/5.0 (compatible; LyrieAgent/0.1; +https://lyrie.ai)",
    },
  });

  if (!response.ok) {
    throw new Error(`DDG ${response.status}: ${response.statusText}`);
  }

  const html = await response.text();

  // Parse results from DDG HTML
  const resultPattern =
    /<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/gi;
  const results: string[] = [];
  let match;

  while ((match = resultPattern.exec(html)) !== null && results.length < count) {
    const href = decodeURIComponent(
      (match[1].match(/uddg=([^&]*)/) ?? [])[1] ?? match[1]
    );
    const title = match[2].replace(/<[^>]+>/g, "").trim();
    const snippet = match[3].replace(/<[^>]+>/g, "").trim();
    if (title && href) {
      results.push(`${results.length + 1}. ${title}\n   ${href}\n   ${snippet}`);
    }
  }

  return {
    success: true,
    output: results.length > 0
      ? results.join("\n\n")
      : `No results found for: ${query}`,
    metadata: { query, count: results.length, source: "duckduckgo" },
  };
}
