/**
 * ToolRegistry deferred-loading tests.
 *
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import { ToolRegistry } from "./tool-registry";
import type { Tool } from "./tool-executor";

const dummyTool = (name: string, description = `${name} tool`): Tool => ({
  name,
  description,
  parameters: {
    foo: { type: "string", description: "the foo arg", required: true },
  },
  risk: "safe",
  async execute() {
    return { success: true, output: "ok" };
  },
});

describe("ToolRegistry — deferred loading", () => {
  test("getDeferredList returns one entry per registered tool", () => {
    const r = new ToolRegistry();
    r.registerAll([dummyTool("exec"), dummyTool("read_file"), dummyTool("write_file")]);
    const list = r.getDeferredList();
    expect(list.length).toBe(3);
    expect(list.map((e) => e.name).sort()).toEqual(["exec", "read_file", "write_file"]);
  });

  test("alwaysLoaded tools are NOT marked as deferred", () => {
    const r = new ToolRegistry({ alwaysLoaded: ["tool_search", "agent_spawn"] });
    r.registerAll([dummyTool("tool_search"), dummyTool("exec")]);
    const list = r.getDeferredList();
    const ts = list.find((e) => e.name === "tool_search")!;
    const exec = list.find((e) => e.name === "exec")!;
    expect(ts.isDeferred).toBe(false);
    expect(exec.isDeferred).toBe(true);
  });

  test("getActiveSchemas returns only alwaysLoaded + hydrated tools", () => {
    const r = new ToolRegistry({ alwaysLoaded: ["tool_search"] });
    r.registerAll([dummyTool("tool_search"), dummyTool("exec"), dummyTool("read_file")]);

    const initial = r.getActiveSchemas();
    expect(initial.map((s) => s.name)).toEqual(["tool_search"]);

    // hydrate `exec` via fetchSchema
    const schema = r.fetchSchema("exec");
    expect(schema?.name).toBe("exec");
    const after = r.getActiveSchemas();
    expect(after.map((s) => s.name).sort()).toEqual(["exec", "tool_search"]);
  });

  test("search hydrates matching tools", () => {
    const r = new ToolRegistry();
    r.registerAll([
      dummyTool("web_search", "Search the web with Brave"),
      dummyTool("web_fetch", "Fetch HTML content"),
      dummyTool("exec", "Run a shell command"),
    ]);
    const results = r.search("web");
    expect(results.length).toBeGreaterThanOrEqual(2);
    expect(results.map((r) => r.name).sort()).toEqual(["web_fetch", "web_search"]);

    // Now active schemas should include the hydrated tools
    const active = r.getActiveSchemas();
    expect(active.map((s) => s.name).sort()).toContain("web_search");
  });

  test("token estimate: deferred << eager (the whole point of deferred loading)", () => {
    const r = new ToolRegistry();
    for (let i = 0; i < 50; i++) r.register(dummyTool(`tool_${i}`));
    const deferred = r.estimateDeferredTokens();
    const eager = r.estimateEagerTokens();
    expect(deferred).toBeLessThan(eager);
    // 50 tools: ~150 deferred tokens vs ~25,000 eager tokens
    expect(eager / deferred).toBeGreaterThan(50);
  });

  test("resetHydration drops hydrated state", () => {
    const r = new ToolRegistry({ alwaysLoaded: [] });
    r.registerAll([dummyTool("a"), dummyTool("b")]);
    r.fetchSchema("a");
    expect(r.getActiveSchemas().length).toBe(1);
    r.resetHydration();
    expect(r.getActiveSchemas().length).toBe(0);
  });
});
