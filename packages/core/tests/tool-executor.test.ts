/**
 * ToolExecutor Tests
 *
 * Tests secure tool registration, execution, and Shield integration.
 * Modernized for the v0.1.x ToolResult-shaped API.
 *
 * OTT Cybersecurity LLC
 */

import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { ToolExecutor } from "../src/tools/tool-executor";
import { ShieldManager } from "../src/engine/shield-manager";
import { existsSync, writeFileSync, rmSync } from "fs";
import { join } from "path";

const TEST_DIR = process.cwd();
const TEST_FILE = join(TEST_DIR, "_lyrie_test_tool_executor.txt");

function cleanup() {
  if (existsSync(TEST_FILE)) {
    rmSync(TEST_FILE);
  }
}

describe("ToolExecutor", () => {
  let shield: ShieldManager;
  let executor: ToolExecutor;

  beforeEach(async () => {
    cleanup();
    shield = new ShieldManager();
    await shield.initialize();
    executor = new ToolExecutor(shield);
    await executor.initialize();
  });

  afterEach(() => {
    cleanup();
  });

  // ─── Initialization ────────────────────────────────────────────────────────

  it("initializes with built-in tools registered", () => {
    const tools = executor.available();
    expect(tools.length).toBeGreaterThan(0);
  });

  it("registers all required built-in tools", () => {
    const tools = executor.available();
    const toolNames = tools.map((t) => t.name);

    expect(toolNames).toContain("read_file");
    expect(toolNames).toContain("write_file");
    expect(toolNames).toContain("exec");
    expect(toolNames).toContain("web_search");
    expect(toolNames).toContain("threat_scan");
  });

  it("each tool has required fields", () => {
    const tools = executor.available();
    for (const tool of tools) {
      expect(tool.name).toBeTruthy();
      expect(tool.description).toBeTruthy();
      expect(tool.parameters).toBeDefined();
      expect(["safe", "moderate", "dangerous"]).toContain(tool.risk);
      expect(typeof tool.execute).toBe("function");
    }
  });

  // ─── Custom Tool Registration ─────────────────────────────────────────────

  it("registers custom tools", () => {
    const before = executor.available().length;

    executor.register({
      name: "custom_tool",
      description: "A custom test tool",
      parameters: {
        input: { type: "string", description: "input value", required: true },
      },
      risk: "safe",
      execute: async (args) => ({
        success: true,
        output: `processed: ${args.input}`,
      }),
    });

    expect(executor.available().length).toBe(before + 1);
  });

  it("executes a registered custom tool", async () => {
    executor.register({
      name: "reverse_string",
      description: "Reverse a string",
      parameters: {
        text: { type: "string", description: "text to reverse", required: true },
      },
      risk: "safe",
      execute: async (args) => ({
        success: true,
        output: (args.text as string).split("").reverse().join(""),
      }),
    });

    const result = await executor.execute({
      id: "1",
      tool: "reverse_string",
      args: { text: "lyrie" },
    });

    expect(result.success).toBe(true);
    expect(result.output).toBe("eiryl");
  });

  // ─── File Operations ──────────────────────────────────────────────────────

  it("writes a file within workspace", async () => {
    const result = await executor.execute({
      id: "2",
      tool: "write_file",
      args: { path: TEST_FILE, content: "test content from lyrie" },
    });

    expect(result.success).toBe(true);
    expect(existsSync(TEST_FILE)).toBe(true);
    expect(result.output).toContain("Written");
  });

  it("reads a file within workspace", async () => {
    writeFileSync(TEST_FILE, "hello from lyrie test", "utf-8");

    const result = await executor.execute({
      id: "3",
      tool: "read_file",
      args: { path: TEST_FILE },
    });

    expect(result.success).toBe(true);
    expect(result.output).toBe("hello from lyrie test");
  });

  // ─── Security Blocking ────────────────────────────────────────────────────

  it("returns an error result when executing an unknown tool", async () => {
    const result = await executor.execute({
      id: "4",
      tool: "nonexistent_tool",
      args: {},
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("Unknown tool");
  });

  it("blocks dangerous exec tool calls via Shield", async () => {
    const result = await executor.execute({
      id: "5",
      tool: "exec",
      args: { command: "rm -rf /" },
    });
    // Shield should refuse this dangerous command
    expect(result.success).toBe(false);
    expect((result.error ?? result.output ?? "").toLowerCase()).toMatch(
      /shield|blocked|denied/,
    );
  });

  it("returns threat scan results from Shield", async () => {
    const result = await executor.execute({
      id: "6",
      tool: "threat_scan",
      args: { target: "/etc/hosts", type: "file" },
    });

    // ToolResult shape always present
    expect(result).toBeDefined();
    expect(typeof result.success).toBe("boolean");
    // The threat scan tool serializes the underlying ScanResult to JSON
    if (result.success) {
      const parsed = JSON.parse(result.output);
      expect(typeof parsed.blocked).toBe("boolean");
    }
  });

  // ─── Web Search Stub ──────────────────────────────────────────────────────

  it("web_search returns a result-shaped response without crashing", async () => {
    const result = await executor.execute({
      id: "7",
      tool: "web_search",
      args: { query: "Lyrie AI cybersecurity" },
    });

    expect(result).toBeTruthy();
    // Successful or not, the returned shape is a ToolResult
    expect(typeof result.success).toBe("boolean");
    expect(typeof result.output).toBe("string");
  });
});
