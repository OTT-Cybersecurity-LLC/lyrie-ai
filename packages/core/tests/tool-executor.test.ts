/**
 * ToolExecutor Tests
 *
 * Tests secure tool registration, execution, and Shield integration.
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
      parameters: { input: "string" },
      risk: "safe",
      execute: async (args) => `processed: ${args.input}`,
    });

    expect(executor.available().length).toBe(before + 1);
  });

  it("executes a registered custom tool", async () => {
    executor.register({
      name: "reverse_string",
      description: "Reverse a string",
      parameters: { text: "string" },
      risk: "safe",
      execute: async (args) => (args.text as string).split("").reverse().join(""),
    });

    const result = await executor.execute({
      tool: "reverse_string",
      args: { text: "lyrie" },
    });

    expect(result).toBe("eiryL".toLowerCase().split("").reverse().join("").split("").reverse().join(""));
    // Simpler check:
    expect(result).toBe("eiRYL".toLowerCase());
  });

  // ─── File Operations ──────────────────────────────────────────────────────

  it("writes a file within workspace", async () => {
    const result = await executor.execute({
      tool: "write_file",
      args: { path: TEST_FILE, content: "test content from lyrie" },
    });

    expect(existsSync(TEST_FILE)).toBe(true);
    expect(result).toContain("Written");
  });

  it("reads a file within workspace", async () => {
    writeFileSync(TEST_FILE, "hello from lyrie test", "utf-8");

    const result = await executor.execute({
      tool: "read_file",
      args: { path: TEST_FILE },
    });

    expect(result).toBe("hello from lyrie test");
  });

  // ─── Security Blocking ────────────────────────────────────────────────────

  it("throws when trying to execute unknown tool", async () => {
    let threw = false;
    try {
      await executor.execute({ tool: "nonexistent_tool", args: {} });
    } catch (err: any) {
      threw = true;
      expect(err.message).toContain("Unknown tool");
    }
    expect(threw).toBe(true);
  });

  it("blocks dangerous exec tool calls via Shield", async () => {
    let threw = false;
    try {
      await executor.execute({
        tool: "exec",
        args: { command: "echo harmless" }, // exec risk is 'dangerous' — always blocked
      });
    } catch (err: any) {
      threw = true;
      expect(err.message).toContain("Shield blocked");
    }
    expect(threw).toBe(true);
  });

  it("returns threat scan results from Shield", async () => {
    const result = await executor.execute({
      tool: "threat_scan",
      args: { target: "/etc/hosts", type: "file" },
    });

    expect(result).toBeDefined();
    expect(typeof result.blocked).toBe("boolean");
  });

  // ─── Web Search Stub ──────────────────────────────────────────────────────

  it("web_search returns a response without crashing", async () => {
    const result = await executor.execute({
      tool: "web_search",
      args: { query: "Lyrie AI cybersecurity" },
    });

    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });
});
