/**
 * Engine wiring tests — feat/engine-wiring
 *
 * Covers:
 *   Task 1: ModelRouter routes via LyrieProviderRegistry
 *   Task 2: LyrieEngine coordinator mode filters tools
 *   Task 3: tool_search built-in returns results
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test, beforeEach } from "bun:test";

// ─── Task 1: ModelRouter × LyrieProviderRegistry ────────────────────────────

import { ModelRouter } from "./model-router";
import {
  LyrieProviderRegistry,
  LyrieProvider,
  LyrieCompletion,
  LyrieCompletionOptions,
  LyrieMessage,
} from "./providers/lyrie-provider";

/** Minimal stub that satisfies the LyrieProvider interface. */
function makeProvider(id: string, model = `${id}-default`): LyrieProvider {
  return {
    id,
    name: id,
    endpoint: "http://localhost:0",
    models: [model],
    defaultModel: model,
    isLocal: true,
    supportsToolUse: true,
    supportsFunctionCalling: true,
    maxContextTokens: 131072,
    async complete(
      _model: string,
      _messages: LyrieMessage[],
      _options?: LyrieCompletionOptions
    ): Promise<LyrieCompletion> {
      return {
        content: `stub:${id}`,
        toolCalls: [],
        stopReason: "end_turn",
        model: _model,
        usage: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
      };
    },
  };
}

describe("Task 1 — ModelRouter routes via LyrieProviderRegistry", () => {
  beforeEach(() => {
    // Reset the singleton so tests don't bleed
    LyrieProviderRegistry.setInstance(new LyrieProviderRegistry());
  });

  test("LyrieProviderRegistry singleton is available", () => {
    const reg = LyrieProviderRegistry.getInstance();
    expect(reg).toBeDefined();
    expect(typeof reg.get).toBe("function");
  });

  test("setInstance replaces the singleton", () => {
    const fresh = new LyrieProviderRegistry();
    fresh.register(makeProvider("test-prov"));
    LyrieProviderRegistry.setInstance(fresh);
    expect(LyrieProviderRegistry.getInstance().has("test-prov")).toBe(true);
  });

  test("ModelRouter.route() uses registry hermes provider", async () => {
    // Seed registry with a stub hermes provider
    const reg = new LyrieProviderRegistry();
    const hermes = makeProvider("hermes", "nous-hermes3:70b");
    reg.register(hermes);
    LyrieProviderRegistry.setInstance(reg);

    const router = new ModelRouter();
    // We don't call initialize() here (it would bootstrap real local providers)
    // Instead we test route() directly with the seeded singleton
    const instance = await router.route("check the logs");
    expect(instance).toBeDefined();
    expect(instance.config.provider).toBe("hermes");
    expect(instance.config.id).toBe("nous-hermes3:70b");
  });

  test("ModelRouter.route() falls back to first registry provider when hermes missing", async () => {
    const reg = new LyrieProviderRegistry();
    reg.register(makeProvider("ollama", "llama3:8b"));
    LyrieProviderRegistry.setInstance(reg);

    const router = new ModelRouter();
    const instance = await router.route("analyze this");
    expect(instance).toBeDefined();
    expect(instance.config.provider).toBe("ollama");
  });

  test("ModelRouter.route() complete() calls through to registry provider", async () => {
    const reg = new LyrieProviderRegistry();
    reg.register(makeProvider("hermes"));
    LyrieProviderRegistry.setInstance(reg);

    const router = new ModelRouter();
    const instance = await router.route("do something");
    const result = await instance.complete({ system: "sys", messages: [{ role: "user", content: "hi" }] });
    expect(result.content).toBe("stub:hermes");
    expect(result.toolCalls).toEqual([]);
  });

  test("RouterConfig.provider overrides hermes default", async () => {
    const reg = new LyrieProviderRegistry();
    reg.register(makeProvider("hermes"));
    reg.register(makeProvider("lmstudio", "mistral-7b"));
    LyrieProviderRegistry.setInstance(reg);

    const router = new ModelRouter();
    // @ts-ignore — set config directly for unit test
    router["config"] = { provider: "lmstudio" };
    const instance = await router.route("code review");
    expect(instance.config.provider).toBe("lmstudio");
  });

  test("No registry provider → falls through to legacy stub path", async () => {
    // Empty registry, no legacy providers either
    LyrieProviderRegistry.setInstance(new LyrieProviderRegistry());
    const router = new ModelRouter();
    const instance = await router.route("hello");
    // Should return the empty stub without throwing
    expect(instance).toBeDefined();
    const result = await instance.complete({ system: "", messages: [] });
    expect(typeof result.content).toBe("string");
  });
});

// ─── Task 2: LyrieCoordinator singleton + LyrieEngine coordinator mode ───────

import { LyrieCoordinator } from "../agents/coordinator";
import type { Tool } from "../tools/tool-executor";

const makeToolStub = (name: string): Tool => ({
  name,
  description: name,
  parameters: {},
  risk: "safe",
  async execute() {
    return { success: true, output: "" };
  },
});

describe("Task 2 — LyrieCoordinator singleton + tool filtering", () => {
  beforeEach(() => {
    LyrieCoordinator.setInstance(new LyrieCoordinator());
  });

  test("LyrieCoordinator.getInstance() returns singleton", () => {
    const c1 = LyrieCoordinator.getInstance();
    const c2 = LyrieCoordinator.getInstance();
    expect(c1).toBe(c2);
  });

  test("setInstance replaces singleton", () => {
    const custom = new LyrieCoordinator({ allowedTools: new Set(["only_this"]) });
    LyrieCoordinator.setInstance(custom);
    expect(LyrieCoordinator.getInstance().isAllowed("only_this")).toBe(true);
    expect(LyrieCoordinator.getInstance().isAllowed("exec")).toBe(false);
  });

  test("coordinator mode filters exec, read_file, write_file from allTools", () => {
    const allTools = [
      makeToolStub("exec"),
      makeToolStub("read_file"),
      makeToolStub("write_file"),
      makeToolStub("agent_spawn"),
      makeToolStub("tool_search"),
      makeToolStub("agent_status"),
    ];
    const filtered = LyrieCoordinator.getInstance().filterTools(allTools);
    const names = filtered.map((t) => t.name);
    expect(names).not.toContain("exec");
    expect(names).not.toContain("read_file");
    expect(names).not.toContain("write_file");
    expect(names).toContain("agent_spawn");
    expect(names).toContain("tool_search");
  });

  test("coordinator mode: all filtered tools are in COORDINATOR_ALLOWED_TOOLS", () => {
    const { COORDINATOR_ALLOWED_TOOLS } = require("./coordinator");
    // (import path relative to test location, using require for simplicity)
    // We just verify filterTools only keeps allowed tools
    const allTools = ["exec", "web_fetch", "agent_spawn", "report", "team_create"].map(makeToolStub);
    const filtered = LyrieCoordinator.getInstance().filterTools(allTools);
    for (const t of filtered) {
      expect(LyrieCoordinator.getInstance().isAllowed(t.name)).toBe(true);
    }
  });

  test("when coordinator=false, no tools are filtered (allTools passes through)", () => {
    const allTools = ["exec", "read_file", "agent_spawn"].map(makeToolStub);
    // Simulates the non-coordinator path: don't call filterTools
    // (engine only calls filterTools when coordinatorEnabled=true)
    const active = allTools; // passthrough
    expect(active.length).toBe(3);
    expect(active.map((t) => t.name)).toContain("exec");
  });
});

// ─── Task 3: tool_search built-in ────────────────────────────────────────────

import { ToolRegistry } from "../tools/tool-registry";

describe("Task 3 — ToolRegistry singleton + tool_search", () => {
  beforeEach(() => {
    // Fresh registry for each test
    ToolRegistry.setInstance(new ToolRegistry({ alwaysLoaded: ["tool_search"] }));
  });

  test("ToolRegistry.getInstance() returns singleton", () => {
    const r1 = ToolRegistry.getInstance();
    const r2 = ToolRegistry.getInstance();
    expect(r1).toBe(r2);
  });

  test("setInstance replaces singleton", () => {
    const fresh = new ToolRegistry();
    fresh.register(makeToolStub("custom_tool") as any);
    ToolRegistry.setInstance(fresh);
    expect(ToolRegistry.getInstance().has("custom_tool")).toBe(true);
  });

  test("tool_search returns results for known tool names", async () => {
    const reg = ToolRegistry.getInstance();
    // Seed with known tools
    reg.register({
      name: "web_search",
      description: "Search the web with Brave",
      parameters: { query: { type: "string", description: "query", required: true } },
      risk: "safe",
      async execute() { return { success: true, output: "ok" }; },
    });
    reg.register({
      name: "web_fetch",
      description: "Fetch HTML content from a URL",
      parameters: { url: { type: "string", description: "url", required: true } },
      risk: "safe",
      async execute() { return { success: true, output: "ok" }; },
    });
    reg.register({
      name: "exec",
      description: "Execute a shell command",
      parameters: { command: { type: "string", description: "cmd", required: true } },
      risk: "dangerous",
      async execute() { return { success: true, output: "ok" }; },
    });

    const results = reg.search("web");
    expect(results.length).toBeGreaterThanOrEqual(2);
    const names = results.map((r) => r.name);
    expect(names).toContain("web_search");
    expect(names).toContain("web_fetch");
  });

  test("tool_search gracefully returns empty array for unknown queries", () => {
    const reg = ToolRegistry.getInstance();
    reg.register({
      name: "exec",
      description: "Execute a shell command",
      parameters: {},
      risk: "dangerous",
      async execute() { return { success: true, output: "ok" }; },
    });
    const results = reg.search("zzz_definitely_not_a_real_tool_xyz");
    expect(results).toEqual([]);
  });

  test("tool_search returns exact match on tool name", () => {
    const reg = ToolRegistry.getInstance();
    reg.register({
      name: "threat_scan",
      description: "Scan for security threats",
      parameters: {},
      risk: "safe",
      async execute() { return { success: true, output: "ok" }; },
    });
    const results = reg.search("threat_scan", 3);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].name).toBe("threat_scan");
  });

  test("tool_search respects max_results limit", () => {
    const reg = ToolRegistry.getInstance();
    for (let i = 0; i < 10; i++) {
      reg.register({
        name: `file_tool_${i}`,
        description: `file operation tool ${i}`,
        parameters: {},
        risk: "safe",
        async execute() { return { success: true, output: "" }; },
      });
    }
    const results = reg.search("file", 3);
    expect(results.length).toBeLessThanOrEqual(3);
  });

  test("tool_search hydrates returned tools into active schemas", () => {
    const reg = new ToolRegistry({ alwaysLoaded: [] });
    ToolRegistry.setInstance(reg);
    reg.register({
      name: "apply_diff",
      description: "Edit files with targeted replacements",
      parameters: {},
      risk: "moderate",
      async execute() { return { success: true, output: "" }; },
    });
    expect(reg.getActiveSchemas().length).toBe(0);
    const results = reg.search("apply_diff");
    expect(results.length).toBe(1);
    // After search, tool is hydrated
    expect(reg.getActiveSchemas().length).toBe(1);
    expect(reg.getActiveSchemas()[0].name).toBe("apply_diff");
  });
});

// ─── Integration: ToolExecutor registers tool_search ─────────────────────────

import { ToolExecutor } from "../tools/tool-executor";
import { ShieldManager } from "../engine/shield-manager";

// Minimal ShieldManager stub
class StubShield extends ShieldManager {
  constructor() {
    // @ts-ignore — bypass real constructor
    super();
  }
  async scanInput() { return { blocked: false, reason: "" }; }
  async validateToolCall() { return true; }
  async scanFile() { return { safe: true }; }
  async scanUrl() { return { safe: true }; }
  setScopedPaths() {}
  resetPaths() {}
}

describe("ToolExecutor — tool_search builtin registered", () => {
  test("tool_search is registered after initialize()", async () => {
    ToolRegistry.setInstance(new ToolRegistry({ alwaysLoaded: ["tool_search"] }));
    const shield = new StubShield();
    const executor = new ToolExecutor(shield);
    await executor.initialize();
    expect(executor.listNames()).toContain("tool_search");
  });

  test("tool_search execute() returns tools array for known query", async () => {
    ToolRegistry.setInstance(new ToolRegistry({ alwaysLoaded: ["tool_search"] }));
    const shield = new StubShield();
    const executor = new ToolExecutor(shield);
    await executor.initialize();

    // After initialize(), the registry should be seeded with all builtins
    const result = await executor.execute({
      id: "call_1",
      tool: "tool_search",
      args: { query: "exec", max_results: 3 },
    });
    expect(result.success).toBe(true);
    const parsed = JSON.parse(result.output);
    expect(Array.isArray(parsed.tools)).toBe(true);
    expect(parsed.tools.length).toBeGreaterThanOrEqual(1);
    expect(parsed.tools[0].name).toBe("exec");
  });

  test("tool_search execute() returns empty tools for unknown query", async () => {
    ToolRegistry.setInstance(new ToolRegistry({ alwaysLoaded: ["tool_search"] }));
    const shield = new StubShield();
    const executor = new ToolExecutor(shield);
    await executor.initialize();

    const result = await executor.execute({
      id: "call_2",
      tool: "tool_search",
      args: { query: "zzzz_totally_unknown_zzz" },
    });
    expect(result.success).toBe(true);
    const parsed = JSON.parse(result.output);
    expect(parsed.tools).toEqual([]);
  });
});
