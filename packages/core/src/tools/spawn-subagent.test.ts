/**
 * spawn_subagent tool tests
 *
 * Verifies:
 * - Tool is correctly registered in ToolExecutor
 * - Tool definition matches the schema contract
 * - execute() delegates to SubagentRunner
 * - Validation: empty task → error result
 * - Success result propagates correctly
 * - Failure result propagates correctly
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { ToolExecutor } from "./tool-executor";
import { ShieldManager } from "../engine/shield-manager";
import { spawnSubagentTool } from "./spawn-subagent";
import { defaultSubagentRunner } from "../agents/subagent-runner";

// ─── Tool definition contract ─────────────────────────────────────────────────

describe("spawnSubagentTool — definition", () => {
  it("has the correct name", () => {
    expect(spawnSubagentTool.name).toBe("spawn_subagent");
  });

  it("has a non-empty description", () => {
    expect(spawnSubagentTool.description.length).toBeGreaterThan(20);
  });

  it("has a required 'task' parameter", () => {
    expect(spawnSubagentTool.parameters.task).toBeDefined();
    expect(spawnSubagentTool.parameters.task.required).toBe(true);
    expect(spawnSubagentTool.parameters.task.type).toBe("string");
  });

  it("has optional 'model' parameter", () => {
    expect(spawnSubagentTool.parameters.model).toBeDefined();
    expect(spawnSubagentTool.parameters.model.required).toBeFalsy();
  });

  it("has optional 'timeoutSeconds' number parameter", () => {
    expect(spawnSubagentTool.parameters.timeoutSeconds).toBeDefined();
    expect(spawnSubagentTool.parameters.timeoutSeconds.type).toBe("number");
  });

  it("has optional 'context' parameter with correct enum", () => {
    const ctx = spawnSubagentTool.parameters.context;
    expect(ctx).toBeDefined();
    expect(ctx.enum).toEqual(["isolated", "fork"]);
  });

  it("has optional 'parentContext' parameter", () => {
    expect(spawnSubagentTool.parameters.parentContext).toBeDefined();
  });

  it("risk is 'moderate'", () => {
    expect(spawnSubagentTool.risk).toBe("moderate");
  });

  it("execute is a function", () => {
    expect(typeof spawnSubagentTool.execute).toBe("function");
  });
});

// ─── ToolExecutor registration ────────────────────────────────────────────────

describe("ToolExecutor — spawn_subagent registration", () => {
  let executor: ToolExecutor;

  beforeEach(async () => {
    const shield = new ShieldManager();
    await shield.initialize();
    executor = new ToolExecutor(shield);
    await executor.initialize();
  });

  it("spawn_subagent is registered after initialization", () => {
    const names = executor.listNames();
    expect(names).toContain("spawn_subagent");
  });

  it("spawn_subagent is included in available() list", () => {
    const tool = executor.available().find((t) => t.name === "spawn_subagent");
    expect(tool).toBeDefined();
    expect(tool?.description).toBeTruthy();
  });

  it("spawn_subagent appears in Anthropic format", () => {
    const defs = executor.toAnthropicFormat();
    const def = defs.find((d) => d.name === "spawn_subagent");
    expect(def).toBeDefined();
    expect(def?.input_schema.properties.task).toBeDefined();
    expect(def?.input_schema.required).toContain("task");
  });

  it("spawn_subagent appears in OpenAI format", () => {
    const defs = executor.toOpenAIFormat();
    const def = defs.find((d) => d.function.name === "spawn_subagent");
    expect(def).toBeDefined();
    expect(def?.function.parameters.properties.task).toBeDefined();
  });

  it("all other built-in tools still registered", () => {
    const names = executor.listNames();
    for (const name of ["exec", "read_file", "write_file", "web_search", "threat_scan"]) {
      expect(names).toContain(name);
    }
  });
});

// ─── spawn_subagent execute() ─────────────────────────────────────────────────

describe("spawnSubagentTool.execute()", () => {
  it("returns error result when task is missing", async () => {
    const res = await spawnSubagentTool.execute({});
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/task/);
  });

  it("returns error result when task is empty string", async () => {
    const res = await spawnSubagentTool.execute({ task: "  " });
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/task/);
  });

  it("delegates to defaultSubagentRunner", async () => {
    let ranTask = "";
    // Temporarily patch the runner
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async (task: string, _opts: any) => {
      ranTask = task;
      return { success: true, output: "stubbed", durationMs: 1, model: "stub" };
    };

    const res = await spawnSubagentTool.execute({ task: "scan example.com" });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(ranTask).toBe("scan example.com");
    expect(res.success).toBe(true);
    expect(res.output).toBe("stubbed");
  });

  it("propagates sub-agent error correctly", async () => {
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async () => ({
      success: false,
      output: "",
      durationMs: 5,
      model: "stub",
      error: "engine exploded",
    });

    const res = await spawnSubagentTool.execute({ task: "boom" });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(res.success).toBe(false);
    expect(res.error).toMatch(/engine exploded/);
  });

  it("includes durationMs and model in metadata on success", async () => {
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async () => ({
      success: true,
      output: "all good",
      durationMs: 99,
      model: "haiku",
    });

    const res = await spawnSubagentTool.execute({ task: "check CVEs" });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(res.metadata?.durationMs).toBe(99);
    expect(res.metadata?.model).toBe("haiku");
  });

  it("passes model override to runner", async () => {
    let capturedModel: string | undefined;
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async (_task: string, opts: any) => {
      capturedModel = opts.model;
      return { success: true, output: "ok", durationMs: 1, model: opts.model ?? "default" };
    };

    await spawnSubagentTool.execute({ task: "check", model: "claude-opus-4-6" });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(capturedModel).toBe("claude-opus-4-6");
  });

  it("passes timeoutSeconds to runner", async () => {
    let capturedTimeout: number | undefined;
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async (_task: string, opts: any) => {
      capturedTimeout = opts.timeoutSeconds;
      return { success: true, output: "ok", durationMs: 1, model: "stub" };
    };

    await spawnSubagentTool.execute({ task: "quick task", timeoutSeconds: 60 });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(capturedTimeout).toBe(60);
  });

  it("passes context=fork to runner", async () => {
    let capturedCtx: string | undefined;
    const original = defaultSubagentRunner.run.bind(defaultSubagentRunner);
    // @ts-expect-error
    defaultSubagentRunner.run = async (_task: string, opts: any) => {
      capturedCtx = opts.context;
      return { success: true, output: "ok", durationMs: 1, model: "stub" };
    };

    await spawnSubagentTool.execute({ task: "fork task", context: "fork", parentContext: "ctx" });

    // @ts-expect-error
    defaultSubagentRunner.run = original;

    expect(capturedCtx).toBe("fork");
  });
});
